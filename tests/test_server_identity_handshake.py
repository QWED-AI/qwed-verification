"""Server-identity handshake before API-key bootstrap (issue #376).

A healthy /health proves only that SOMETHING answers on the port. These
tests pin the proof that matters: the server must present fingerprints of
the exact secret set init holds, otherwise init refuses to bootstrap.

Hermetic: the server endpoint is called directly (no socket), the CLI
helper runs against a stubbed httpx.get (no network).
"""

import asyncio
import hashlib
import os

import pytest

from qwed_new.api.main import server_identity
from qwed_sdk import cli as cli_module


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_identity_endpoint_returns_fingerprints_not_secrets(monkeypatch):
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "local-jwt-secret")
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "local-lookup-secret")

    body = asyncio.run(server_identity())

    assert body == {
        "identity": {
            "jwt_sha256": _digest("local-jwt-secret"),
            "lookup_sha256": _digest("local-lookup-secret"),
        }
    }
    rendered = repr(body)
    assert "local-jwt-secret" not in rendered
    assert "local-lookup-secret" not in rendered


def test_identity_endpoint_missing_env_fingerprints_empty(monkeypatch):
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    body = asyncio.run(server_identity())

    assert body["identity"] == {"jwt_sha256": _digest(""), "lookup_sha256": _digest("")}


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, broken=False):
        self.status_code = status_code
        self._payload = payload
        self._broken = broken

    def json(self):
        if self._broken:
            raise ValueError("not json")
        return self._payload


def _identity_payload(jwt_secret="s3cr3t-jwt", lookup_secret="s3cr3t-lookup"):
    return {
        "identity": {
            "jwt_sha256": _digest(jwt_secret),
            "lookup_sha256": _digest(lookup_secret),
        }
    }


def _stub_get(monkeypatch, response=None, error=None):
    def _fake(url, timeout=None):
        assert url.endswith("/health/identity")
        if error is not None:
            raise error
        return response

    monkeypatch.setattr("httpx.get", _fake)


def test_matching_identity_passes(monkeypatch):
    _stub_get(monkeypatch, response=_FakeResponse(payload=_identity_payload()))

    assert (
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")
        is None
    )


def test_jwt_mismatch_fails_closed_with_remediation(monkeypatch):
    _stub_get(
        monkeypatch,
        response=_FakeResponse(payload=_identity_payload(jwt_secret="foreign-jwt")),
    )

    with pytest.raises(RuntimeError) as excinfo:
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")

    message = str(excinfo.value)
    assert "jwt" in message
    assert "Restart the server" in message


def test_lookup_mismatch_fails_closed(monkeypatch):
    _stub_get(
        monkeypatch,
        response=_FakeResponse(payload=_identity_payload(lookup_secret="foreign-lookup")),
    )

    with pytest.raises(RuntimeError, match="lookup"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_missing_endpoint_fails_closed(monkeypatch):
    """A server predating the identity endpoint cannot prove itself: an old
    server and a foreign process are indistinguishable here, so both stop."""
    _stub_get(monkeypatch, response=_FakeResponse(status_code=404, payload={}))

    with pytest.raises(RuntimeError, match="does not expose"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_unreachable_server_fails_closed(monkeypatch):
    import httpx

    _stub_get(monkeypatch, error=httpx.ConnectError("refused"))

    with pytest.raises(RuntimeError, match="could not reach"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_malformed_identity_fails_closed(monkeypatch):
    _stub_get(monkeypatch, response=_FakeResponse(payload={}, broken=True))

    with pytest.raises(RuntimeError, match="unreadable"):
        cli_module._verify_server_identity("http://localhost:8000", "s3cr3t-jwt", "s3cr3t-lookup")


def test_bootstrap_runs_after_successful_handshake(monkeypatch):
    monkeypatch.setattr(
        cli_module, "_ensure_local_server_running", lambda *args: (True, False)
    )
    monkeypatch.setattr(
        cli_module, "_bootstrap_api_key", lambda *args: ("qwed_live_new_key", "demo-org")
    )
    _stub_get(monkeypatch, response=_FakeResponse(payload=_identity_payload()))

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
    _stub_get(
        monkeypatch,
        response=_FakeResponse(payload=_identity_payload(jwt_secret="foreign-jwt")),
    )

    with pytest.raises(SystemExit):
        cli_module._start_server_and_bootstrap(
            normalized_server_url="http://localhost:8000",
            jwt_secret="s3cr3t-jwt",
            lookup_secret="s3cr3t-lookup",
            organization_name="demo-org",
            secrets_fresh=False,
        )

    assert bootstrapped == []


def test_fingerprint_helper_is_sha256():
    assert cli_module._server_identity_fingerprint("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert "abc" not in cli_module._server_identity_fingerprint("abc")


def test_endpoint_never_echoes_raw_values(monkeypatch):
    """Belt and suspenders alongside the direct test: unique markers must
    not appear anywhere in the rendered response."""
    jwt_marker = "jwt-marker-not-a-secret"
    lookup_marker = "lookup-marker-not-a-secret"
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", jwt_marker)
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", lookup_marker)
    os.environ.pop("UNRELATED", None)

    body = asyncio.run(server_identity())

    assert jwt_marker not in repr(body)
    assert lookup_marker not in repr(body)
    assert body["identity"]["jwt_sha256"] == _digest(jwt_marker)
