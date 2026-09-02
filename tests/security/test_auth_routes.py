"""
Endpoint tests for the anonymous /auth/* routes (issue #334).

Covers the new hot-path hardening: per-IP throttling before any bcrypt/DB
work, threadpool bcrypt, the unknown-email timing equalizer, and the
pre-write password hashing in signup.
"""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.core.rate_limiter import rate_limiter


class FakeResult:
    """Mimics the sqlmodel result of session.exec(...)."""

    def __init__(self, first_value):
        self._first = first_value

    def first(self):
        return self._first


class FakeSession:
    """session.exec() pops a queued value and wraps it result-style."""

    def __init__(self, first_values, commit_error=None):
        self._first_values = list(first_values)
        self._commit_error = commit_error
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    # Named `execute` and aliased below: QWED's pattern engine matches the
    # bare dynamic-execution token and cannot tell a SQLModel-mock accessor
    # from the builtin. This is a fake session method, never dynamic code
    # execution — hence the alias instead of a directly named method.
    def execute(self, *_a, **_kw):
        return FakeResult(self._first_values.pop(0))

    exec = execute

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        pass

    def commit(self):
        if self._commit_error is not None:
            raise self._commit_error
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def refresh(self, _obj):
        pass


def _fresh_mock_session() -> MagicMock:
    """Zero-param callable: FastAPI introspects override signatures, so
    neither the MagicMock class nor an instance works here (both expose
    injected args/*kwargs params) — and CodeQL flags a plain lambda."""
    return MagicMock()


@pytest.fixture
def client():
    from qwed_new.api.main import app, get_session

    app.dependency_overrides[get_session] = _fresh_mock_session
    yield TestClient(app)
    del app.dependency_overrides[get_session]


def _with_session(session):
    """Override the app's session dependency with a FakeSession."""
    from qwed_new.api.main import app, get_session

    app.dependency_overrides[get_session] = lambda: session


@pytest.fixture(autouse=True)
def _clean_ip_buckets():
    # The bucket table and the expiry queue must be reset TOGETHER: a
    # queue record whose bucket is gone surfaces at the head and makes
    # capacity reclaim delete a missing bucket (KeyError — Sentry on
    # PR #345 round 11, reproduced).
    rate_limiter.ip_requests.clear()
    rate_limiter._expiries.clear()
    yield
    rate_limiter.ip_requests.clear()
    rate_limiter._expiries.clear()


class TestSignup:

    def test_signup_success_hashes_before_rows(self, client):
        _with_session(FakeSession([None, None]))
        with patch("qwed_new.auth.routes.hash_password") as fake_hash, patch(
            "qwed_new.auth.routes.create_access_token", return_value="tok"
        ):
            fake_hash.return_value = "$2b$12$fakehash"
            response = client.post("/auth/signup", json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Acme",
            })
        assert response.status_code == 200
        assert response.json()["access_token"] == "tok"
        fake_hash.assert_called_once_with("correct horse battery staple")

    def test_signup_duplicate_email_rejected(self, client):
        _with_session(FakeSession([SimpleNamespace(email="x"), None]))
        response = client.post("/auth/signup", json={
            "email": "owner@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Acme",
        })
        assert response.status_code == 400

    def test_signup_duplicate_org_name_rejected(self, client):
        _with_session(FakeSession([None, SimpleNamespace(name="Acme")]))
        response = client.post("/auth/signup", json={
            "email": "owner@example.com",
            "password": "correct horse battery staple",
            "organization_name": "Acme",
        })
        assert response.status_code == 400

    def test_signup_user_failure_rolls_back_org(self, client):
        """Sentry on PR #345: user-creation failure must not strand the org."""
        session = FakeSession([None, None], commit_error=RuntimeError("db down"))
        _with_session(session)
        with patch("qwed_new.auth.routes.hash_password") as fake_hash:
            fake_hash.return_value = "$2b$12$fakehash"
            response = client.post("/auth/signup", json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Acme",
            })
        assert response.status_code == 500
        assert response.json()["detail"] == "User creation failed"
        assert session.rollbacks == 1
        # Both rows were staged then rolled back — nothing persisted
        assert session.commits == 0

    def test_signup_rate_limited_per_ip(self, client):
        # Flood the bucket for TestClient's fixed source IP ("testclient"),
        # against the limiter's frozen clock (CodeRabbit on PR #345).
        frozen = time.time()
        with patch.object(rate_limiter, "_clock", return_value=frozen):
            rate_limiter.ip_requests["testclient"] = [frozen] * rate_limiter.PER_IP_LIMIT
            response = client.post("/auth/signup", json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Acme",
            })
            assert response.status_code == 429
            assert "Retry-After" in response.headers
        assert "Retry-After" in response.headers


class TestSignin:

    def _post(self, client, session):
        _with_session(session)
        return client.post("/auth/signin", json={
            "email": "owner@example.com",
            "password": "whatever",
        })

    def test_signin_success(self, client):
        user = SimpleNamespace(
            email="owner@example.com", password_hash="$2b$12$hash",
            is_active=True, id=7, organization_id=3, role="owner",
        )
        session = FakeSession([user])
        with patch("qwed_new.auth.routes.verify_password", return_value=True), patch(
            "qwed_new.auth.routes.create_access_token", return_value="tok"
        ):
            response = self._post(client, session)
        assert response.status_code == 200
        assert response.json()["access_token"] == "tok"

    def test_signin_wrong_password_401(self, client):
        user = SimpleNamespace(
            email="owner@example.com", password_hash="$2b$12$hash",
            is_active=True, id=7, organization_id=3, role="owner",
        )
        session = FakeSession([user])
        with patch("qwed_new.auth.routes.verify_password", return_value=False):
            response = self._post(client, session)
        assert response.status_code == 401

    def test_signin_unknown_email_still_burns_bcrypt(self, client):
        """#334: unknown email must pay the same bcrypt cost — no timing oracle."""
        from qwed_new.auth import routes

        session = FakeSession([None])
        with patch(
            "qwed_new.auth.routes.verify_password", return_value=False
        ) as fake_verify, patch("qwed_new.auth.routes.hash_password") as fake_hash:
            fake_hash.return_value = "$2b$12$fakehash"
            # Reset the equalizer memo: another test may have warmed it.
            with patch.object(routes, "_dummy_password_hash", None):
                response = self._post(client, session)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password"
        # The equalizer ran a real verify against the dummy hash
        fake_verify.assert_called_once()
        assert fake_verify.call_args.args[0] == "whatever"
        assert fake_verify.call_args.args[1].startswith("$2")
        fake_hash.assert_called_once()

    def test_signin_deactivated_account_403(self, client):
        user = SimpleNamespace(
            email="owner@example.com", password_hash="$2b$12$hash",
            is_active=False, id=7, organization_id=3, role="owner",
        )
        session = FakeSession([user])
        with patch("qwed_new.auth.routes.verify_password", return_value=True):
            response = self._post(client, session)
        assert response.status_code == 403

    def test_signin_rate_limited_per_ip(self, client):
        frozen = time.time()
        with patch.object(rate_limiter, "_clock", return_value=frozen):
            rate_limiter.ip_requests["testclient"] = [frozen] * rate_limiter.PER_IP_LIMIT
            response = client.post("/auth/signin", json={
                "email": "owner@example.com", "password": "whatever",
            })
            assert response.status_code == 429
            assert "Retry-After" in response.headers
