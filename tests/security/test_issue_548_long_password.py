"""
Signup and signin with a password longer than bcrypt reads (issue #548).

bcrypt 5 raises ValueError for a password over 72 bytes, which reached the
caller as a 500. Signup now refuses it with a 400 before any lookup, and
signin answers 401. These tests use real bcrypt, not a mock.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.auth.security import (
    MAX_PASSWORD_BYTES,
    hash_password,
    password_too_long,
    verify_password,
)
from tests.security.test_auth_routes import (  # noqa: F401  (autouse fixture)
    FakeSession,
    _clean_ip_buckets,
    _fresh_mock_session,
    _with_session,
)


@pytest.fixture
def client():
    from qwed_new.api.main import app, get_session

    app.dependency_overrides[get_session] = _fresh_mock_session
    yield TestClient(app)
    del app.dependency_overrides[get_session]


def _password(n_bytes: int) -> str:
    """A password of exactly n_bytes in UTF-8, half of it two-byte."""
    two_byte = "é" * (n_bytes // 4)
    return "a" * (n_bytes - 2 * len(two_byte)) + two_byte


AT_LIMIT = _password(MAX_PASSWORD_BYTES)
OVER_LIMIT = _password(MAX_PASSWORD_BYTES + 1)
EMAIL = "owner@example.com"


def test_the_passwords_have_the_intended_sizes():
    assert len(AT_LIMIT.encode("utf-8")) == MAX_PASSWORD_BYTES
    assert len(OVER_LIMIT.encode("utf-8")) == MAX_PASSWORD_BYTES + 1
    assert len(OVER_LIMIT) < MAX_PASSWORD_BYTES  # bytes, not characters, count


def test_password_too_long_counts_utf8_bytes():
    assert not password_too_long(AT_LIMIT)
    assert password_too_long(OVER_LIMIT)


def test_password_too_long_does_not_encode_a_string_over_the_limit():
    class _NoEncode(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("encoded")

    assert password_too_long(_NoEncode("a" * (MAX_PASSWORD_BYTES + 1)))


def test_verify_password_refuses_a_password_over_the_limit():
    stored = hash_password(AT_LIMIT)

    assert verify_password(AT_LIMIT, stored)
    assert not verify_password(OVER_LIMIT, stored)
    # A password that starts with the stored one but runs past 72 bytes
    # does not match either (bcrypt 4 truncated it to the stored one).
    assert not verify_password(AT_LIMIT + "x", stored)


# ------------------------------------------------------------------- signup

def test_signup_refuses_a_password_over_the_limit_with_400(client):
    # No queued results: a lookup or insert would fail the test with a 500.
    session = FakeSession([])
    _with_session(session)

    response = client.post("/auth/signup", json={
        "email": EMAIL, "password": OVER_LIMIT, "organization_name": "Acme",
    })

    assert response.status_code == 400
    assert response.json()["detail"] == "Password must be at most 72 bytes"
    assert session.added == []


def test_signup_refuses_it_even_for_a_registered_email(client):
    # The answer does not tell whether the email is registered.
    _with_session(FakeSession([SimpleNamespace(email=EMAIL), None]))

    response = client.post("/auth/signup", json={
        "email": EMAIL, "password": OVER_LIMIT, "organization_name": "Acme",
    })

    assert response.json()["detail"] == "Password must be at most 72 bytes"


def test_signup_accepts_a_password_of_exactly_the_limit(client):
    session = FakeSession([None, None])
    _with_session(session)

    with patch("qwed_new.auth.routes.create_access_token", return_value="tok"):
        response = client.post("/auth/signup", json={
            "email": EMAIL, "password": AT_LIMIT, "organization_name": "Acme",
        })

    assert response.status_code == 200
    (user,) = [row for row in session.added if hasattr(row, "password_hash")]
    assert verify_password(AT_LIMIT, user.password_hash)


# ------------------------------------------------------------------- signin

def _signin(client, session, password):
    _with_session(session)
    return client.post("/auth/signin", json={"email": EMAIL, "password": password})


def test_signin_with_a_password_over_the_limit_is_401_for_a_registered_email(client):
    user = SimpleNamespace(
        email=EMAIL, password_hash=hash_password(AT_LIMIT),
        is_active=True, id=7, organization_id=3, role="owner",
    )

    response = _signin(client, FakeSession([user]), OVER_LIMIT)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_signin_with_a_password_over_the_limit_is_401_for_an_unknown_email(client):
    response = _signin(client, FakeSession([None]), OVER_LIMIT)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"
