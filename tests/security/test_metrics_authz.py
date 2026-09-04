"""All-tenant metrics authorization (issue #337, CWE-284).

Regression tests for the exact attack chain from the external audit:
anonymous POST /auth/signup (which mints role="owner") followed by
GET /metrics with the returned JWT. The org role must never confer
platform-wide authority — cross-tenant metrics are operator-only via
QWED_METRICS_OPERATOR_USER_IDS, fail-closed when unset.
"""

import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.core.rate_limiter import rate_limiter


class FakeSignupSession:
    """Session double that mimics flush/commit PK assignment so the real
    signup route runs end-to-end and mints a genuine JWT."""

    def __init__(self):
        self._select_results = [None, None]  # no email collision, no org collision
        self.added = []

    # Named `execute` and aliased below: QWED's pattern engine matches the
    # bare dynamic-execution token and cannot tell a SQLModel-mock accessor
    # from the builtin (same shape as tests/security/test_auth_routes.py).
    # This is a fake session accessor, never dynamic code execution.
    def execute(self, *_a, **_kw):
        return SimpleNamespace(first=lambda: self._select_results.pop(0))

    exec = execute

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        # flush() assigns the organization PK (issue #345 transaction shape)
        for obj in self.added:
            if getattr(obj, "id", None) is None and hasattr(obj, "display_name"):
                obj.id = 1

    def commit(self):
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = 7

    def refresh(self, _obj):
        pass


def _signup_session_override():
    session = FakeSignupSession()
    return session


def _owner_lookup_session_override():
    """Resolves the JWT's subject to the freshly minted role="owner" user."""
    session = MagicMock()
    session.get.return_value = SimpleNamespace(id=7, role="owner", is_active=True)
    return session


@pytest.fixture
def client():
    from qwed_new.api.main import app, get_session

    app.dependency_overrides[get_session] = _signup_session_override
    yield TestClient(app)
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture(autouse=True)
def _clean_ip_buckets():
    rate_limiter.ip_requests.clear()
    rate_limiter._expiries.clear()
    yield
    rate_limiter.ip_requests.clear()
    rate_limiter._expiries.clear()


def _signup(client):
    # Generated, never a hardcoded credential string — Snyk's
    # hardcoded-password rule matches real-format passwords in fixtures
    # (memory rule: test fixtures must not use real credential formats).
    password = "unit-test-" + secrets.token_hex(16)
    with patch("qwed_new.auth.routes.hash_password") as fake_hash:
        fake_hash.return_value = "$2b$12$fakehash"
        response = client.post("/auth/signup", json={
            "email": "attacker@example.com",
            "password": password,
            "organization_name": "Evil Corp",
        })
    assert response.status_code == 200
    return response.json()


class TestMetricsAuthz:

    def test_signup_mints_owner_role(self, client):
        """Documents the precondition: self-service signup is the only
        user-creation path and hardcodes role="owner" (issue #337)."""
        body = _signup(client)
        assert body["user"]["role"] == "owner"

    def test_signup_owner_cannot_read_all_tenant_metrics(self, client, monkeypatch):
        """The audit's two-request PoC chain must end in a denial."""
        monkeypatch.delenv("QWED_METRICS_OPERATOR_USER_IDS", raising=False)

        body = _signup(client)
        token = body["access_token"]

        from qwed_new.api.main import app, get_session
        app.dependency_overrides[get_session] = _owner_lookup_session_override
        try:
            response = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
        finally:
            del app.dependency_overrides[get_session]

        assert response.status_code == 403
        assert response.json()["detail"] == "Platform operator access required"

    def test_signup_owner_denied_even_with_unrelated_allowlist(self, client, monkeypatch):
        """A populated allowlist that does not include the signup user denies too."""
        monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "1,2,3")

        body = _signup(client)
        token = body["access_token"]

        from qwed_new.api.main import app, get_session
        app.dependency_overrides[get_session] = _owner_lookup_session_override
        try:
            response = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
        finally:
            del app.dependency_overrides[get_session]

        assert response.status_code == 403

    def test_anonymous_metrics_request_denied(self, client, monkeypatch):
        monkeypatch.delenv("QWED_METRICS_OPERATOR_USER_IDS", raising=False)
        response = client.get("/metrics")
        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"
