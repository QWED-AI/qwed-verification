import importlib.util
from pathlib import Path

import pytest


def test_security_raises_runtime_error_if_no_secret(monkeypatch):
    """Missing auth secret must fail fast at module import time."""
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)

    security_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "qwed_new"
        / "auth"
        / "security.py"
    )
    spec = importlib.util.spec_from_file_location("security_missing_secret_test", security_path)
    module = importlib.util.module_from_spec(spec)

    with pytest.raises(RuntimeError, match="QWED_JWT_SECRET_KEY must be set"):
        spec.loader.exec_module(module)
