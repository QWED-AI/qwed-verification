import os

from qwed_new.config import ensure_jwt_secret


def test_ensure_jwt_secret_returns_existing(monkeypatch):
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "already-set-secret")

    def _unexpected_call(_size):
        raise AssertionError("token_urlsafe should not be called when secret exists")

    monkeypatch.setattr("qwed_new.config.secrets.token_urlsafe", _unexpected_call)

    value = ensure_jwt_secret()
    assert value == "already-set-secret"


def test_ensure_jwt_secret_generates_when_missing(monkeypatch):
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.setattr("qwed_new.config.secrets.token_urlsafe", lambda size: f"generated-{size}")

    value = ensure_jwt_secret()
    assert value == "generated-48"
    assert os.getenv("QWED_JWT_SECRET_KEY") == "generated-48"
