"""Server-identity handshake before API-key bootstrap (issue #376).

A healthy /health proves only that SOMETHING answers on the port. These
tests pin the proof that matters: the server must answer a fresh
caller nonce with domain-separated HMACs under the exact secret set init
holds, otherwise init refuses to bootstrap.

Hermetic: the server endpoint is called directly (no socket), the CLI
helper runs against a stubbed httpx.get (no network). The stub plays an
honest server — it computes real proofs for the requested nonce — so the
round trip, mismatches, and replay rejection are all exercised for real.
"""

import asyncio
import hashlib
import hmac

import pytest
from fastapi import HTTPException

from qwed_new.api.main import server_identity
from qwed_sdk import cli as cli_module


def _proof(secret, domain, nonce):
    return hmac.new(
        secret.encode(),
        f"qwed-server-identity-v1:{domain}:{nonce}".encode(),
        hashlib.sha256,
    ).hexdigest()


def test_proof_is_domain_separated_hmac():
    assert cli_module._identity_proof("s", "jwt", "n") == _proof("s", "jwt", "n")
    assert cli_module._identity_proof("s", "lookup", "n") == _proof("s", "lookup", "n")
    assert cli_module._identity_proof("s", "jwt", "n") != cli_module._identity_proof(
        "s", "lookup", "n"
    )


def test_endpoint_proves_requested_nonce(monkeypatch):
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "local-jwt-secret")
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "local-lookup-secret")

    body = asyncio.run(server_identity(nonce="caller-nonce-123"))

    assert body == {
        "identity": {
            "jwt_hmac": _proof("local-jwt-secret", "jwt", "caller-nonce-123"),
            "lookup_hmac": _proof("local-lookup-secret", "lookup", "caller-nonce-123"),
        }
    }
    rendered = repr(body)
    assert "local-jwt-secret" not in rendered
    assert "local-lookup-secret" not in rendered


def test_endpoint_rejects_missing_or_wild_nonce():
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(server_identity(nonce=""))
    assert excinfo.value.status_code == 400
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(server_identity(nonce="x" * 129))
    assert excinfo.value.status_code == 400


def test_endpoint_fails_closed_without_server_secrets(monkeypatch):
    """Missing env must 503, never prove the empty string (Sentry HIGH)."""
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(server_identity(nonce="caller-nonce-123"))

    assert excinfo.value.status_code == 503


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, broken=False):
        self.status_code = status_code
        self._payload = payload
        self._broken = broken

    def json(self):
        if self._broken:
            raise ValueError("not json")
        return self._payload


def _honest_server(monkeypatch, jwt_secret="s3cr3t-jwt", lookup_secret="s3cr3t-lookup"):
    """Stub httpx.get with a server that honestly proves whatever nonce the
    CLI sends — mismatches then come only from genuinely different secrets."""

    def _fake(url, params=None, timeout=None):
        assert url.endswith("/health/identity")
        nonce = (params or {}).get("nonce", "")
        return _FakeResponse(
            payload={
                "identity": {
                    "jwt_hmac": cli_module._identity_proof(jwt_secret, "jwt", nonce),
                    "lookup_hmac": cli_module._identity_proof(lookup_secret, "lookup", nonce),
                }
            }
        )

    monkeypatch.setattr("httpx.get", _fake)


def _fixed_response(monkeypatch, payload=None, status_code=200, broken=False, error=None):
    def _fake(url, params=None, timeout=None):
        if error is not None:
            raise error
        return _FakeResponse(status_code=status_code, payload=payload, broken=broken)

    monkeypatch.setattr("httpx.get", _fake)


def test_matching_identity_passes(monkeypatch):
    _honest_server(monkeypatch)

    assert (
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")
        is None
    )


def test_empty_local_secrets_fail_closed_without_network(monkeypatch):
    """Empty local secrets must never reach the wire: both sides proving
    the empty string would match (Sentry HIGH on #388)."""
    calls = []
    monkeypatch.setattr("httpx.get", lambda *args, **kwargs: calls.append(1))

    with pytest.raises(RuntimeError, match="local secrets are missing"):
        cli_module._verify_server_identity("http://localhost:8000", "", "s3cr3t-lookup")

    assert calls == []


def test_jwt_mismatch_fails_closed_with_remediation(monkeypatch):
    _honest_server(monkeypatch, jwt_secret="foreign-jwt")

    with pytest.raises(RuntimeError) as excinfo:
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")

    message = str(excinfo.value)
    assert "jwt" in message
    assert "Restart the server" in message


def test_lookup_mismatch_fails_closed(monkeypatch):
    _honest_server(monkeypatch, lookup_secret="foreign-lookup")

    with pytest.raises(RuntimeError, match="lookup"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_captured_response_rejected_for_other_nonce(monkeypatch):
    """Replay regression (CodeRabbit CWE-294 on #388): a response captured
    for one nonce must fail verification under a fresh nonce."""
    stale_nonce = "stale-nonce-from-earlier-handshake"
    stale = {
        "identity": {
            "jwt_hmac": cli_module._identity_proof("s3cr3t-jwt", "jwt", stale_nonce),
            "lookup_hmac": cli_module._identity_proof("s3cr3t-lookup", "lookup", stale_nonce),
        }
    }
    _fixed_response(monkeypatch, payload=stale)

    with pytest.raises(RuntimeError, match="different"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_missing_endpoint_fails_closed(monkeypatch):
    """A server predating the identity endpoint cannot prove itself: an old
    server and a foreign process are indistinguishable here, so both stop."""
    _fixed_response(monkeypatch, payload={}, status_code=404)

    with pytest.raises(RuntimeError, match="did not prove"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_unreachable_server_fails_closed(monkeypatch):
    import httpx

    _fixed_response(monkeypatch, error=httpx.ConnectError("refused"))

    with pytest.raises(RuntimeError, match="could not reach"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_malformed_identity_fails_closed(monkeypatch):
    _fixed_response(monkeypatch, payload={}, broken=True)

    with pytest.raises(RuntimeError, match="unreadable"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_bootstrap_runs_after_successful_handshake(monkeypatch):
    monkeypatch.setattr(
        cli_module, "_ensure_local_server_running", lambda *args: (True, False)
    )
    monkeypatch.setattr(
        cli_module, "_bootstrap_api_key", lambda *args: ("qwed_live_new_key", "demo-org")
    )
    _honest_server(monkeypatch)

    key, org = cli_module._start_server_and_bootstrap(
        normalized_server_url="http://localhost:8000",
        jwt_secret="s3cr3t-jwt",
        lookup_secret="s3cr3t-lookup",
        organization_name="demo-org",
        secrets_fresh=False,
    )

    assert (key, org) == ("qwed_live_new_key", "demo-org")


def test_bootstrap_blocked_on_identity_mismatch(monkeypatch):
    bootstrapped = []
    monkeypatch.setattr(
        cli_module, "_ensure_local_server_running", lambda *args: (True, False)
    )
    monkeypatch.setattr(
        cli_module, "_bootstrap_api_key", lambda *args: bootstrapped.append(1)
    )
    _honest_server(monkeypatch, jwt_secret="foreign-jwt")

    with pytest.raises(SystemExit):
        cli_module._start_server_and_bootstrap(
            normalized_server_url="http://localhost:8000",
            jwt_secret="s3cr3t-jwt",
            lookup_secret="s3cr3t-lookup",
            organization_name="demo-org",
            secrets_fresh=False,
        )

    assert bootstrapped == []
