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
from unittest.mock import patch

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


def _fixture_keypair():
    """Fixed P-256 pair so signatures are reproducible across runs."""
    scalar = int.from_bytes(bytes.fromhex("11" * 31 + "12"), "big") % routes._P256_ORDER
    private_key = ec.derive_private_key(scalar, ec.SECP256R1())
    return private_key, private_key.public_key()


def _fixture_keypair_alt():
    """A second fixed pair: a DIFFERENT key, for forged-signature tests."""
    scalar = int.from_bytes(bytes.fromhex("22" * 31 + "23"), "big") % routes._P256_ORDER
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
        private_key, _ = keypair
        raw = _canonical(payload)
        unknown = "0" * 64
        with patch.object(routes, "on_verified_matches") as sink, patch.object(
            routes, "_fetch_keys", side_effect=_raise_fetch
        ) as fetch:
            resp = _post(app_client, raw, unknown, _sign(private_key, raw))
        assert resp.status_code == 403
        sink.assert_not_called()
        fetch.assert_called_once()  # one rotation-refetch, then fail closed

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
        with pytest.raises(routes.SignatureRejected) as ctx:
            verifier.verify(raw, "kid", _sign(other, raw))
        assert ctx.value.status_code == 403

    def test_verify_rejects_garbage_signature(self):
        _, public_key = _fixture_keypair()
        verifier = routes.SignatureVerifier({"kid": _pem_of(public_key)})
        with pytest.raises(routes.SignatureRejected):
            verifier.verify(b"{}", "kid", "!!!not-base64!!!")

    def test_verify_rejects_unknown_key_id(self):
        verifier = routes.SignatureVerifier({})
        with pytest.raises(routes.SignatureRejected) as ctx:
            verifier.verify(b"{}", "nope", base64.b64encode(b"x" * 64).decode())
        assert ctx.value.status_code == 403

    def test_rejects_non_p256_key(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(routes.SignatureRejected):
            routes.SignatureVerifier({"kid": _pem_of(rsa_key.public_key())})

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
