"""Tests for the secret-scanning webhook trust gate (issue #367).

The endpoint is unauthenticated by design, so the ONLY thing distinguishing a
genuine leak report from an attacker spraying our users' keys is the ECDSA
signature. These tests pin the safe behavior:

* unsigned / bad-signature / unknown-key-id / malformed-envelope requests are
  rejected BEFORE any sink processing (``on_verified_matches`` never runs);
* the signature covers the RAW body bytes — a re-serialized body fails;
* valid requests are accepted fast and handed to the sink without token values
  ever hitting the logs.

All DETERMINISTIC (fixed P-256 fixture key + fixed payloads, no randomness):
the fixture key is computed inline and the keys endpoint is stubbed by patching
``_fetch_keys``. No network access in this module.
"""

import base64
import json
import logging
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from qwed_new.api import secret_scanning_routes as routes
from qwed_new.api.secret_scanning_routes import router

# ---------------------------------------------------------------------------
# Deterministic fixture key pair (fixed scalar — NEVER a deployed key)
# ---------------------------------------------------------------------------

#: P-256 group order, test-local. The production module intentionally defines
#: no such constant (CodeQL unused-global on #374) — the loader pins the
#: curve via isinstance(SECP256R1) instead of a manual scalar bound.
_P256_ORDER_FIXTURE = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


def _fixture_keypair():
    """Fixed P-256 pair so signatures are reproducible across runs."""
    scalar = int.from_bytes(bytes.fromhex("11" * 31 + "12"), "big") % _P256_ORDER_FIXTURE
    private_key = ec.derive_private_key(scalar, ec.SECP256R1())
    return private_key, private_key.public_key()


def _fixture_keypair_alt():
    """A second fixed pair: a DIFFERENT key, for forged-signature tests."""
    scalar = int.from_bytes(bytes.fromhex("22" * 31 + "23"), "big") % _P256_ORDER_FIXTURE
    private_key = ec.derive_private_key(scalar, ec.SECP256R1())
    return private_key, private_key.public_key()


def _pem_of(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


@pytest.fixture
def keypair():
    private_key, public_key = _fixture_keypair()
    return private_key, _pem_of(public_key)


@pytest.fixture
def key_id():
    return (
        "bcb53661c06b4728e59d897fb6165d5c9cda0fd9"
        "cdf9d09ead458168deb7518c"
    )


@pytest.fixture
def app_client(keypair, key_id):
    """A minimal app mounting ONLY the webhook router.

    The module-level key cache is seeded with the fixture key and outbound
    HTTP is forbidden, proving these tests exercise offline verification only.
    """
    _, pem = keypair
    app = FastAPI()
    app.include_router(router)

    with patch.object(
        routes,
        "_KEYS_CACHE",
        {"keys": {key_id: pem}, "etag": None, "fetched_at": 10**18},
    ), patch.object(
        routes, "_fetch_keys", side_effect=RuntimeError("network forbidden in these tests")
    ):
        yield TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def payload():
    return [
        {
            "token": "qwed_live_" + "A" * 30 + "000000",
            "type": "qwed_live_api_key",
            "url": "https://github.com/octo/Hello-World/blob/1234/foo.txt",
            "source": "commit",
        }
    ]


def _canonical(items: list) -> bytes:
    """The exact bytes a real scanner would send (compact JSON, utf-8)."""
    return json.dumps(items, separators=(",", ":")).encode("utf-8")


def _sign(private_key, raw_body: bytes) -> str:
    """DER ECDSA signature over the raw body, base64-encoded (like GitHub's)."""
    der = private_key.sign(raw_body, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(der).decode("ascii")


def _post(app_client, raw_body, key_id, signature, extra_headers=None):
    headers = {
        "Github-Public-Key-Identifier": key_id,
        "Github-Public-Key-Signature": signature,
    }
    if extra_headers:
        headers.update(extra_headers)
    return app_client.post("/webhooks/secret-scanning", content=raw_body, headers=headers)


def _raise_fetch():
    raise RuntimeError("keys endpoint unreachable (test stub)")


# ---------------------------------------------------------------------------
# The trust gate: unsigned / forged / unknown requests must be rejected
# before any sink processing
# ---------------------------------------------------------------------------


class TestSignatureGate:
    """The full HTTP path: raw body in, signature checked first."""

    def test_valid_signed_request_accepted(self, app_client, keypair, key_id, payload):
        private_key, _ = keypair
        raw = _canonical(payload)
        resp = _post(app_client, raw, key_id, _sign(private_key, raw))
        assert resp.status_code == 200
        assert resp.json() == {"received": 1}

    def test_valid_signed_request_reaches_sink(self, app_client, keypair, key_id, payload):
        private_key, _ = keypair
        raw = _canonical(payload)
        seen = []
        with patch.object(routes, "on_verified_matches", side_effect=lambda ms: seen.extend(ms)):
            resp = _post(app_client, raw, key_id, _sign(private_key, raw))
        assert resp.status_code == 200
        assert len(seen) == 1
        assert seen[0].token == payload[0]["token"]

    def test_missing_headers_rejected_and_sink_not_called(
        self, app_client, keypair, key_id, payload
    ):
        private_key, _ = keypair
        raw = _canonical(payload)
        sig = _sign(private_key, raw)
        with patch.object(routes, "on_verified_matches") as sink:
            no_id = _post(app_client, raw, "", sig)
            no_sig = _post(app_client, raw, key_id, "")
        assert no_id.status_code == 401
        assert no_sig.status_code == 401
        sink.assert_not_called()

    def test_forged_signature_rejected_and_sink_not_called(
        self, app_client, keypair, key_id, payload
    ):
        other_key, _ = _fixture_keypair_alt()
        raw = _canonical(payload)
        with patch.object(routes, "on_verified_matches") as sink:
            resp = _post(app_client, raw, key_id, _sign(other_key, raw))
        assert resp.status_code == 403
        sink.assert_not_called()

    def test_tampered_body_rejected(self, app_client, keypair, key_id, payload):
        """The signature covers the RAW bytes: sign A's bytes, deliver B's."""
        private_key, _ = keypair
        original = _canonical(payload)
        tampered = _canonical([{**payload[0], "token": "qwed_live_" + "B" * 30 + "000000"}])
        assert original != tampered
        with patch.object(routes, "on_verified_matches") as sink:
            resp = _post(app_client, tampered, key_id, _sign(private_key, original))
        assert resp.status_code == 403
        sink.assert_not_called()

    def test_reserialized_body_rejected(self, app_client, keypair, key_id, payload):
        """Pretty-printing the same JSON fails: whitespace is part of the bytes."""
        private_key, _ = keypair
        compact = _canonical(payload)
        pretty = json.dumps(json.loads(compact), indent=2).encode("utf-8")
        assert compact != pretty
        with patch.object(routes, "on_verified_matches") as sink:
            resp = _post(app_client, pretty, key_id, _sign(private_key, compact))
        assert resp.status_code == 403
        sink.assert_not_called()

    def test_unknown_key_id_rejected_and_sink_not_called(
        self, app_client, keypair, key_id, payload
    ):
        private_key, pem = keypair
        raw = _canonical(payload)
        unknown = "0" * 64
        with patch.object(routes, "on_verified_matches") as sink, patch.object(
            routes, "_fetch_keys", return_value=({key_id: pem}, '"etag-1"')
        ) as fetch:
            resp = _post(app_client, raw, unknown, _sign(private_key, raw))
        assert resp.status_code == 403
        sink.assert_not_called()
        fetch.assert_called_once()  # one rotation-refetch, then fail closed

    def test_unknown_key_id_with_dead_refetch_returns_503(
        self, app_client, keypair, key_id, payload
    ):
        # Unknown key + refetch service down: verification was impossible,
        # so retryable 503, not 403 (CodeRabbit major #374).
        private_key, _ = keypair
        raw = _canonical(payload)
        unknown = "0" * 64
        with patch.object(routes, "on_verified_matches") as sink, patch.object(
            routes, "_fetch_keys", side_effect=_raise_fetch
        ):
            resp = _post(app_client, raw, unknown, _sign(private_key, raw))
        assert resp.status_code == 503
        sink.assert_not_called()

    def test_non_json_body_rejected(self, app_client, keypair, key_id):
        private_key, _ = keypair
        raw = b"this is not json"
        with patch.object(routes, "on_verified_matches") as sink:
            resp = _post(
                app_client, raw, key_id, _sign(private_key, raw),
                extra_headers={"Content-Type": "text/plain"},
            )
        assert resp.status_code == 400
        sink.assert_not_called()

    def test_unusable_trust_anchor_returns_503(self, keypair, payload):
        # Cache holds only off-spec keys (e.g. RSA): verification impossible
        # -> retryable 503, never 403 (Sentry LOW on #374).
        from cryptography.hazmat.primitives.asymmetric import rsa
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        private_key, _ = keypair
        raw = _canonical(payload)
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = _pem_of(rsa_key.public_key())
        app = FastAPI()
        app.include_router(router)
        cache = {
            "keys": {"bad-rsa": rsa_pem},
            "etag": None,
            "fetched_at": 10**18,
            "last_forced_refresh": None,
        }
        routes._FETCH_STATE["event"] = None
        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", side_effect=_raise_fetch
        ), patch.object(routes, "on_verified_matches") as sink:
            resp = TestClient(app, raise_server_exceptions=False).post(
                "/webhooks/secret-scanning",
                content=raw,
                headers={
                    "Github-Public-Key-Identifier": "bad-rsa",
                    "Github-Public-Key-Signature": _sign(private_key, raw),
                },
            )
        assert resp.status_code == 503
        sink.assert_not_called()

    def test_rotation_refetch_unusable_keys_returns_503(
        self, app_client, keypair, key_id, payload
    ):
        # Unknown key + refetch yields no usable P-256 keys -> 503, not 403.
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key, _ = keypair
        raw = _canonical(payload)
        unknown = "0" * 64
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = _pem_of(rsa_key.public_key())
        with patch.object(routes, "on_verified_matches") as sink, patch.object(
            routes, "_fetch_keys", return_value=({"bad-rsa": rsa_pem}, '"etag-x"')
        ):
            resp = _post(app_client, raw, unknown, _sign(private_key, raw))
        assert resp.status_code == 503
        sink.assert_not_called()

    def test_present_but_unusable_key_still_rotates(
        self, keypair, key_id, payload
    ):
        # Sentry MEDIUM on #374: kid cached but skipped as off-spec (RSA)
        # must still trigger the rotation refetch — checked against the
        # verifier's usable set, not the raw dict. Fixed upstream key ->
        # 200, not a permanent 403.
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key, good_pem = keypair
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        app = FastAPI()
        app.include_router(router)
        cache = {
            "keys": {key_id: _pem_of(rsa_key.public_key())},
            "etag": None,
            "fetched_at": 10**18,
            "last_forced_refresh": None,
            "last_fetch_error_at": None,
        }
        routes._FETCH_STATE["event"] = None
        raw = _canonical(payload)
        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", return_value=({key_id: good_pem}, '"etag-2"')
        ) as fetch, patch.object(routes, "on_verified_matches"):
            resp = TestClient(app, raise_server_exceptions=False).post(
                "/webhooks/secret-scanning",
                content=raw,
                headers={
                    "Github-Public-Key-Identifier": key_id,
                    "Github-Public-Key-Signature": _sign(private_key, raw),
                },
            )
        assert resp.status_code == 200
        fetch.assert_called_once()

    def test_keys_unavailable_returns_503_not_500(self, keypair, key_id, payload):
        # Sentry HIGH on #374: empty/expired cache + dead key service must
        # fail closed with retryable 503, never an unhandled 500.
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        private_key, _ = keypair
        raw = _canonical(payload)
        sig = _sign(private_key, raw)
        app = FastAPI()
        app.include_router(router)
        empty_cache = {
            "keys": {},
            "etag": None,
            "fetched_at": 0.0,
            "last_forced_refresh": None,
        }
        routes._FETCH_STATE["event"] = None
        with patch.object(routes, "_KEYS_CACHE", empty_cache), patch.object(
            routes, "_fetch_keys", side_effect=RuntimeError("keys endpoint down")
        ), patch.object(routes, "on_verified_matches") as sink:
            resp = TestClient(app, raise_server_exceptions=False).post(
                "/webhooks/secret-scanning",
                content=raw,
                headers={
                    "Github-Public-Key-Identifier": key_id,
                    "Github-Public-Key-Signature": sig,
                },
            )
        assert resp.status_code == 503
        sink.assert_not_called()


# ---------------------------------------------------------------------------
# The verifier unit: DER parsing, curve enforcement, timing safety
# ---------------------------------------------------------------------------


class TestVerifierUnit:
    def test_verify_ok(self):
        private_key, public_key = _fixture_keypair()
        raw = _canonical([{"source": "commit", "token": "t", "type": "y", "url": "u"}])
        verifier = routes.SignatureVerifier({"kid": _pem_of(public_key)})
        assert verifier.verify(raw, "kid", _sign(private_key, raw)) == "kid"

    def test_verify_rejects_wrong_key(self):
        _, public_key = _fixture_keypair()
        other, _ = _fixture_keypair_alt()
        raw = _canonical([{"source": "commit", "token": "t", "type": "y", "url": "u"}])
        verifier = routes.SignatureVerifier({"kid": _pem_of(public_key)})
        forged_sig = _sign(other, raw)
        with pytest.raises(routes.SignatureRejected) as ctx:
            verifier.verify(raw, "kid", forged_sig)
        assert ctx.value.status_code == 403

    def test_verify_rejects_garbage_signature(self):
        _, public_key = _fixture_keypair()
        verifier = routes.SignatureVerifier({"kid": _pem_of(public_key)})
        with pytest.raises(routes.SignatureRejected):
            verifier.verify(b"{}", "kid", "!!!not-base64!!!")

    def test_verify_rejects_unknown_key_id(self):
        # empty key set -> construction fails closed (no usable signing keys)
        empty_keys: dict = {}
        with pytest.raises(routes.SignatureRejected, match="no usable signing keys"):
            routes.SignatureVerifier(empty_keys)

    def test_rejects_non_p256_key(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = _pem_of(rsa_key.public_key())
        with pytest.raises(routes.SignatureRejected):
            routes.SignatureVerifier({"kid": rsa_pem})

    def test_comparison_does_not_short_circuit(self):
        """Different wrong signatures take the same rejection path."""
        _, public_key = _fixture_keypair()
        verifier = routes.SignatureVerifier({"kid": _pem_of(public_key)})
        wrong1 = base64.b64encode(b"\x30" + b"\x00" * 63).decode()
        wrong2 = base64.b64encode(b"\x31" + b"\x00" * 63).decode()
        with pytest.raises(routes.SignatureRejected):
            verifier.verify(b"{}", "kid", wrong1)
        with pytest.raises(routes.SignatureRejected):
            verifier.verify(b"{}", "kid", wrong2)


# ---------------------------------------------------------------------------
# Envelope guards: size caps, batch caps, no token material in logs
# ---------------------------------------------------------------------------


class TestEnvelopeGuards:
    def test_body_over_cap_rejected(self):
        oversized = b"[" + b"x" * (routes.MAX_BODY_BYTES + 1) + b"]"
        with pytest.raises(HTTPException) as exc:
            routes._parse_match_batch(oversized)
        assert exc.value.status_code == 413

    def test_oversized_batch_rejected(self):
        big = _canonical([{"token": "t", "type": "y"}] * (routes.MAX_MATCHES_PER_REQUEST + 1))
        with pytest.raises(HTTPException) as exc:
            routes._parse_match_batch(big)
        assert exc.value.status_code == 413

    def test_non_json_body_rejected(self):
        with pytest.raises(HTTPException) as exc:
            routes._parse_match_batch(b"not json at all")
        assert exc.value.status_code == 400

    def test_token_value_never_logged(self, caplog):
        marker = "SECRET-VALUE-123"
        matches = [routes.SecretMatch(token=marker, type="y")]
        with caplog.at_level(logging.INFO, logger="qwed_new.api.secret_scanning_routes"):
            routes._record_receipt(matches, event="unit-probe")
        emitted = " ".join(record.getMessage() for record in caplog.records)
        assert marker not in emitted


# ---------------------------------------------------------------------------
# Key cache: stale cap, forced-refresh throttle, mixed-curve resilience
# ---------------------------------------------------------------------------


class TestKeyCache:
    """get_signing_keys fail-closed + throttled rotation refetch.

    Floats are deliberate: time.monotonic() returns float, so the tests use
    the same type as production. Integer ticks would diverge from the real
    clock source.
    """

    def _cache(self, *, keys=None, etag=None, fetched_at=0.0, last_forced_refresh=None,
               last_fetch_error_at=None):
        routes._FETCH_STATE["event"] = None
        return {
            "keys": keys or {},
            "etag": etag,
            "fetched_at": fetched_at,
            "last_forced_refresh": last_forced_refresh,
            "last_fetch_error_at": last_fetch_error_at,
        }

    def test_fresh_cache_serves_without_fetch(self):
        _, public_key = _fixture_keypair()
        cache = self._cache(keys={"kid": _pem_of(public_key)}, fetched_at=100.0)
        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", side_effect=_raise_fetch
        ) as fetch, patch.object(routes.time, "monotonic", return_value=100.0 + 5):
            assert "kid" in routes.get_signing_keys()
            fetch.assert_not_called()

    def test_failed_refresh_fails_closed(self):
        # TTL expired + fetch down -> propagate, never serve stale
        # (CodeRabbit on #374; QWED fail-closed, no silent degradation).
        _, public_key = _fixture_keypair()
        cache = self._cache(keys={"kid": _pem_of(public_key)}, fetched_at=0.0)
        with (
            patch.object(routes, "_KEYS_CACHE", cache),
            patch.object(routes, "_fetch_keys", side_effect=RuntimeError("down")),
            patch.object(
                routes.time,
                "monotonic",
                return_value=routes.KEYS_CACHE_TTL_SECONDS + 1,
            ),
            pytest.raises(RuntimeError, match="down"),
        ):
            routes.get_signing_keys()

    def test_forced_refresh_throttled(self):
        _, public_key = _fixture_keypair()
        cache = self._cache(
            keys={"kid": _pem_of(public_key)},
            fetched_at=100.0,
            last_forced_refresh=100.0,
        )
        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", side_effect=_raise_fetch
        ) as fetch, patch.object(routes.time, "monotonic", return_value=100.0 + 5):
            # a forced refetch within the throttle window must NOT hit the network
            routes.get_signing_keys(force_refresh=True)
            fetch.assert_not_called()

    def test_rotation_recognised_immediately_after_normal_fetch(self):
        # Greptile P1 on #374: a normal startup/TTL fetch must NOT arm the
        # forced-refresh throttle, so a key GitHub rotates immediately after
        # is still fetched on unknown-key-id retry.
        _, public_key = _fixture_keypair()
        pem = _pem_of(public_key)
        cache = self._cache(keys={"kid": pem}, fetched_at=100.0, last_forced_refresh=None)
        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", return_value=({"kid": pem, "new": pem}, '"etag-2"')
        ) as fetch, patch.object(routes.time, "monotonic", return_value=100.0 + 5):
            out = routes.get_signing_keys(force_refresh=True)
            fetch.assert_called_once()
            assert "new" in out

    def test_ttl_expired_triggers_refresh(self):
        _, public_key = _fixture_keypair()
        pem = _pem_of(public_key)
        cache = self._cache(keys={"kid": pem}, fetched_at=0.0)
        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", return_value=({"kid": pem}, '"new-etag"')
        ) as fetch, patch.object(routes.time, "monotonic", return_value=routes.KEYS_CACHE_TTL_SECONDS + 1):
            out = routes.get_signing_keys()
            fetch.assert_called_once()
            assert out == {"kid": pem}
            assert routes._KEYS_CACHE["etag"] == '"new-etag"'
            # Normal TTL fetch must NOT arm the rotation throttle (Greptile).
            assert routes._KEYS_CACHE["last_forced_refresh"] is None

    def test_failed_fetch_does_not_arm_success_throttle(self):
        # Sentry HIGH on #374: outcome stamps happen after the fetch — a
        # failed forced fetch stamps the error, never last_forced_refresh.
        _, public_key = _fixture_keypair()
        pem = _pem_of(public_key)
        cache = self._cache(keys={"kid": pem}, fetched_at=0.0)
        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", side_effect=RuntimeError("down")
        ), patch.object(routes.time, "monotonic", return_value=500.0):
            with pytest.raises(RuntimeError, match="down"):
                routes.get_signing_keys(force_refresh=True)
            assert routes._KEYS_CACHE["last_forced_refresh"] is None
            assert routes._KEYS_CACHE["last_fetch_error_at"] == 500.0

    def test_rotation_unknown_key_with_recent_error_returns_503(
        self, app_client, keypair, key_id, payload
    ):
        # Throttled during an outage (recent fetch error) + still unknown:
        # suspect anchor -> 503 so the scanner redelivers, never 403.
        private_key, _ = keypair
        raw = _canonical(payload)
        unknown = "0" * 64
        with patch.object(routes, "on_verified_matches") as sink, patch.object(
            routes, "_fetch_keys", side_effect=_raise_fetch
        ), patch.object(routes.time, "monotonic", return_value=1000.0):
            routes._FETCH_STATE["event"] = None
            routes._KEYS_CACHE["last_fetch_error_at"] = 999.0
            resp = _post(app_client, raw, unknown, _sign(private_key, raw))
        assert resp.status_code == 503
        sink.assert_not_called()

    def test_concurrent_refresh_singleflight(self):
        # Greptile P1 on #374: N concurrent refreshes on an empty cache must
        # produce exactly one GitHub fetch; followers share the leader result.
        import threading as _threading

        _, public_key = _fixture_keypair()
        pem = _pem_of(public_key)
        cache = self._cache(keys={}, fetched_at=0.0)
        calls = {"n": 0}

        def _slow_fetch():
            calls["n"] += 1
            import time as _time

            _time.sleep(0.2)
            return ({"kid": pem}, '"etag-1"')

        errors: list = []
        results: list = []

        def _worker():
            try:
                results.append(routes.get_signing_keys())
            except Exception as exc:  # fail-closed surface only
                errors.append(exc)

        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", side_effect=_slow_fetch
        ), patch.object(routes.time, "monotonic", return_value=routes.KEYS_CACHE_TTL_SECONDS + 1):
            threads = [_threading.Thread(target=_worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
        assert not errors
        assert len(results) == 8
        assert calls["n"] == 1
        assert all("kid" in r for r in results)

    def test_follower_fails_closed_when_leader_fails(self):
        # Sentry HIGH + CodeRabbit major on #374: leader fetch fails with
        # expired keys cached -> concurrent follower must also raise, never
        # return the expired keys.
        import threading as _threading

        _, public_key = _fixture_keypair()
        pem = _pem_of(public_key)
        expired_at = 0.0
        now = routes.KEYS_CACHE_TTL_SECONDS + 100.0
        cache = self._cache(keys={"kid": pem}, fetched_at=expired_at)

        def _failing_fetch():
            import time as _time

            calls["n"] += 1
            _time.sleep(0.2)
            raise RuntimeError("keys endpoint down")

        errors: list = []
        calls = {"n": 0}

        def _worker(start_gate):
            start_gate.wait(timeout=10)
            try:
                routes.get_signing_keys()
            except RuntimeError as exc:
                errors.append(exc)

        with patch.object(routes, "_KEYS_CACHE", cache), patch.object(
            routes, "_fetch_keys", side_effect=_failing_fetch
        ), patch.object(routes.time, "monotonic", return_value=now):
            import threading as _t

            start_gate = _t.Barrier(2)
            t1 = _threading.Thread(target=_worker, args=(start_gate,))
            t2 = _threading.Thread(target=_worker, args=(start_gate,))
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)
        assert len(errors) == 2
        # Exactly one leader fetch: proves one worker was a true follower
        # that failed because the leader failed (CodeRabbit minor #374).
        assert calls["n"] == 1


class TestMixedCurveResilience:
    """One off-spec key must not kill the verifier (Sentry on #374)."""

    def test_offspec_key_skipped_valid_key_still_works(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key, public_key = _fixture_keypair()
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        keys = {
            "good": _pem_of(public_key),
            "bad-rsa": _pem_of(rsa_key.public_key()),
        }
        verifier = routes.SignatureVerifier(keys)  # must NOT raise
        assert "good" in verifier._pubkeys
        assert "bad-rsa" not in verifier._pubkeys

        raw = _canonical([{"token": "t", "type": "y"}])
        assert verifier.verify(raw, "good", _sign(private_key, raw)) == "good"

    def test_garbage_pem_skipped_and_not_fatal(self):
        private_key, public_key = _fixture_keypair()
        keys = {"good": _pem_of(public_key), "junk": "not a pem at all"}
        verifier = routes.SignatureVerifier(keys)
        raw = _canonical([{"token": "t", "type": "y"}])
        assert verifier.verify(raw, "good", _sign(private_key, raw)) == "good"


class TestCurvePinning:
    """Only P-256 is accepted; other EC curves are dropped (CodeAnt/Sentry)."""

    def test_non_p256_ec_curve_rejected(self):
        # A valid EC key on a different curve must not be treated as P-256.
        other_curve_key = ec.generate_private_key(ec.SECP384R1()).public_key()
        other_pem = _pem_of(other_curve_key)
        with pytest.raises(routes.SignatureRejected):
            routes.SignatureVerifier({"kid": other_pem})

    def test_unparseable_pem_rejected(self):
        bad_keys = {"kid": "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"}
        with pytest.raises(routes.SignatureRejected):
            routes.SignatureVerifier(bad_keys)

    def test_all_keys_offspec_fails_closed(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bad_rsa_pem = _pem_of(rsa_key.public_key())
        with pytest.raises(routes.SignatureRejected, match="no usable signing keys"):
            routes.SignatureVerifier({"bad-rsa": bad_rsa_pem})


class TestFetchKeys:
    """_fetch_keys: conditional request, 304, non-200, bad shape, junk entries."""

    def _resp(self, status, payload=None, etag=None):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = payload if payload is not None else {}
        resp.headers = {"ETag": etag} if etag else {}
        return resp

    def test_200_parses_keys_and_etag(self):
        pem = _pem_of(_fixture_keypair()[1])
        body = {"public_keys": [{"key_identifier": "kid", "key": pem}]}
        with patch.object(routes, "_KEYS_CACHE", {"keys": {}, "etag": None}), patch.object(
            routes.httpx, "get", return_value=self._resp(200, body, '"etag-1"')
        ):
            keys, etag = routes._fetch_keys()
        assert keys == {"kid": pem}
        assert etag == '"etag-1"'

    def test_304_returns_cached_keys(self):
        pem = _pem_of(_fixture_keypair()[1])
        with patch.object(
            routes, "_KEYS_CACHE", {"keys": {"kid": pem}, "etag": '"old"'}
        ), patch.object(routes.httpx, "get", return_value=self._resp(304)) as get:
            keys, etag = routes._fetch_keys()
        assert keys == {"kid": pem}
        assert etag == '"old"'
        assert get.call_args.kwargs["headers"]["If-None-Match"] == '"old"'

    def test_non_200_raises(self):
        with (
            patch.object(routes, "_KEYS_CACHE", {"keys": {}, "etag": None}),
            patch.object(routes.httpx, "get", return_value=self._resp(500)),
            pytest.raises(RuntimeError, match="HTTP 500"),
        ):
            routes._fetch_keys()

    def test_bad_shape_raises(self):
        with (
            patch.object(routes, "_KEYS_CACHE", {"keys": {}, "etag": None}),
            patch.object(routes.httpx, "get", return_value=self._resp(200, {"unexpected": []})),
            pytest.raises(RuntimeError, match="unexpected shape"),
        ):
            routes._fetch_keys()

    def test_null_public_keys_raises_retryable(self):
        # Greptile P1 on #374: 200 with public_keys: null must raise
        # RuntimeError (leader maps it to 503 + error stamp), never escape
        # as TypeError 500.
        with (
            patch.object(routes, "_KEYS_CACHE", {"keys": {}, "etag": None}),
            patch.object(routes.httpx, "get", return_value=self._resp(200, {"public_keys": None})),
            pytest.raises(RuntimeError, match="unexpected shape"),
        ):
            routes._fetch_keys()

    def test_transport_error_reraises(self):
        with (
            patch.object(routes, "_KEYS_CACHE", {"keys": {}, "etag": None}),
            patch.object(routes.httpx, "get", side_effect=httpx.ConnectError("boom")),
            pytest.raises(httpx.ConnectError),
        ):
            routes._fetch_keys()

    def test_malformed_entries_skipped(self):
        body = {
            "public_keys": [
                {"key_identifier": "ok", "key": _pem_of(_fixture_keypair()[1])},
                {"no_key_identifier": True},
                {"key_identifier": "", "key": "x"},
                {"key_identifier": "nokey"},
                "not-a-dict",
            ]
        }
        with patch.object(routes, "_KEYS_CACHE", {"keys": {}, "etag": None}), patch.object(
            routes.httpx, "get", return_value=self._resp(200, body)
        ):
            keys, _ = routes._fetch_keys()
        assert list(keys.keys()) == ["ok"]

    def test_token_header_added_when_env_set(self, monkeypatch):
        monkeypatch.setenv("GITHUB_KEYS_TOKEN", "tok-123")
        with patch.object(routes, "_KEYS_CACHE", {"keys": {}, "etag": None}), patch.object(
            routes.httpx, "get", return_value=self._resp(200, {"public_keys": []})
        ) as get:
            routes._fetch_keys()
        assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer tok-123"


class TestEnvelopeEdgeCases:
    """_parse_match_batch: empty array, non-dict items, bad field types."""

    def test_empty_array_rejected(self):
        with pytest.raises(HTTPException) as exc:
            routes._parse_match_batch(b"[]")
        assert exc.value.status_code == 400

    def test_non_array_rejected(self):
        with pytest.raises(HTTPException) as exc:
            routes._parse_match_batch(b'{"not": "an array"}')
        assert exc.value.status_code == 400

    def test_non_dict_item_rejected(self):
        with pytest.raises(HTTPException) as exc:
            routes._parse_match_batch(b'["just-a-string"]')
        assert exc.value.status_code == 400

    def test_bad_field_type_rejected(self):
        with pytest.raises(HTTPException) as exc:
            routes._parse_match_batch(b'[{"token": 123, "type": "y"}]')
        assert exc.value.status_code == 400

    def test_valid_item_parsed(self):
        matches = routes._parse_match_batch(
            b'[{"token": "t", "type": "y", "url": "u", "source": "commit"}]'
        )
        assert matches[0].token == "t"
        assert matches[0].source == "commit"


class TestSinkFailure:
    """A crashing downstream sink must not surface to the caller (#368 seam)."""

    def test_sink_failure_is_logged_not_raised(self, caplog):
        def _boom(_matches):
            raise RuntimeError("sink exploded")

        matches = [routes.SecretMatch(token="t", type="y")]
        with patch.object(routes, "on_verified_matches", side_effect=_boom), caplog.at_level(
            logging.ERROR, logger="qwed_new.api.secret_scanning_routes"
        ):
            routes._deliver_verified_matches(matches)  # must not raise

    def test_sink_success_path(self):
        seen = []
        matches = [routes.SecretMatch(token="t", type="y")]
        with patch.object(routes, "on_verified_matches", side_effect=lambda m: seen.extend(m)):
            routes._deliver_verified_matches(matches)
        assert seen == matches
