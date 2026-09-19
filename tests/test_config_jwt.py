import os

import pytest

from qwed_new.config import ensure_jwt_secret, ensure_lookup_secret


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


def test_ensure_lookup_secret_returns_existing_untouched(monkeypatch):
    # Stability guarantee (issue #372): an existing value is never rotated,
    # or every issued key's lookup digest breaks.
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "already-set-lookup")

    def _unexpected_call(_size):
        raise AssertionError("token_urlsafe should not be called when secret exists")

    monkeypatch.setattr("qwed_new.config.secrets.token_urlsafe", _unexpected_call)

    value = ensure_lookup_secret()
    assert value == "already-set-lookup"


def test_ensure_lookup_secret_generates_when_missing(monkeypatch):
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.setattr("qwed_new.config.secrets.token_urlsafe", lambda size: f"generated-{size}")

    value = ensure_lookup_secret()
    assert value == "generated-48"
    assert os.getenv("QWED_API_KEY_LOOKUP_SECRET") == "generated-48"


def test_ensure_lookup_secret_differs_from_jwt_secret(monkeypatch):
    # The server refuses to boot with equal values; fresh generation must
    # retry until distinct.
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "same-value")
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)
    calls = iter(["same-value", "distinct-value"])
    monkeypatch.setattr("qwed_new.config.secrets.token_urlsafe", lambda size: next(calls))

    value = ensure_lookup_secret()
    assert value == "distinct-value"
    assert value != os.getenv("QWED_JWT_SECRET_KEY")


def test_ensure_lookup_secret_rejects_existing_equal_to_jwt(monkeypatch):
    # CodeRabbit/CodeAnt on #375: persisting an equal value only produces a
    # server that refuses to boot — fail loudly instead. Never rotate: the
    # user fixes .env explicitly.
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "same-value")
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "same-value")

    def _unexpected_call(_size):
        raise AssertionError("must not generate when refusing an equal value")

    monkeypatch.setattr("qwed_new.config.secrets.token_urlsafe", _unexpected_call)

    with pytest.raises(RuntimeError, match="must differ"):
        ensure_lookup_secret()
