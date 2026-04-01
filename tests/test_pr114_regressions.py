import builtins
import importlib
import importlib.util
import os
import runpy
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from qwed_sdk import qwed_local as qwed_local_module
from src.qwed_new.core.consensus_verifier import ConsensusVerifier, VerificationMode


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_module(module_name: str, relative_path: str):
    module_path = PROJECT_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_setup_and_verify_wait_for_server_retries_on_timeout(monkeypatch):
    monkeypatch.setenv("QWED_ADMIN_PASSWORD", "unit-test-password")
    module = _load_module("setup_and_verify_test", "scripts/setup_and_verify.py")

    response = MagicMock()
    response.status_code = 200
    get_mock = MagicMock(side_effect=[requests.exceptions.Timeout(), response])

    with patch.object(module.requests, "get", get_mock), patch.object(module.time, "sleep"):
        assert module.wait_for_server() is True

    assert get_mock.call_args_list[0].kwargs["timeout"] == 2
    assert get_mock.call_args_list[1].kwargs["timeout"] == 2


def test_unreadable_code_challenge_requires_allow_unsafe_exec(monkeypatch):
    script_path = PROJECT_ROOT / "benchmarks" / "unreadable_code_challenge.py"
    monkeypatch.setattr(sys, "argv", [str(script_path)])

    with pytest.raises(SystemExit, match="--allow-unsafe-exec"):
        runpy.run_path(str(script_path), run_name="__main__")


def test_cache_print_stats_falls_back_without_colorama(tmp_path, monkeypatch):
    from qwed_sdk.cache import VerificationCache

    cache = VerificationCache(cache_dir=str(tmp_path))
    cache.set("2+2", {"verified": True, "value": 4})

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "colorama":
            raise ImportError("colorama unavailable in test")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with patch("builtins.print") as mock_print:
        cache.print_stats()

    assert any("Cache Statistics" in str(call.args[0]) for call in mock_print.call_args_list)


def test_integrations_exports_none_when_optional_imports_fail(monkeypatch):
    module_names = [
        "qwed_sdk.integrations",
        "qwed_sdk.integrations.langchain",
        "qwed_sdk.integrations.crewai",
        "qwed_sdk.integrations.llamaindex",
    ]
    saved_modules = {name: sys.modules.get(name) for name in module_names}
    for name in module_names:
        sys.modules.pop(name, None)

    original_import = builtins.__import__
    blocked = {
        "langchain",
        "crewai",
        "llamaindex",
        "qwed_sdk.integrations.langchain",
        "qwed_sdk.integrations.crewai",
        "qwed_sdk.integrations.llamaindex",
    }

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        package = globals.get("__package__") if globals else ""
        if name in blocked or (level == 1 and package == "qwed_sdk.integrations" and name in blocked):
            raise ImportError(f"blocked optional import: {name}")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    try:
        module = importlib.import_module("qwed_sdk.integrations")
        assert module.QWEDTool is None
        assert module.QWEDVerifiedAgent is None
        assert module.VerificationConfig is None
        assert module.QWEDQueryEngine is None
        assert module.VerifiedResponse is None
    finally:
        for name in module_names:
            sys.modules.pop(name, None)
        for name, saved in saved_modules.items():
            if saved is not None:
                sys.modules[name] = saved


def test_qwed_local_safe_eval_helpers_run_through_code_guard():
    assert qwed_local_module._safe_eval_sympy_expr("1 + 2", {}) == 3
    assert qwed_local_module._safe_eval_z3_expr("True", {}) is True

    with patch("qwed_new.guards.code_guard.CodeGuard.verify_safety", return_value={
        "verified": False,
        "violations": ["Forbidden function call: eval()"],
    }):
        with pytest.raises(ValueError, match="Code blocked"):
            qwed_local_module._safe_eval_sympy_expr("1 + 2", {})


@pytest.mark.asyncio
async def test_consensus_verifier_records_async_aggregation_failure():
    verifier = ConsensusVerifier(max_workers=1, enable_circuit_breaker=False)
    verifier._select_engines = lambda query, mode: [("Math", lambda q: 42)]
    verifier._is_engine_available = lambda engine_name: True
    verifier._record_engine_result = lambda engine_name, result: (_ for _ in ()).throw(RuntimeError("boom"))
    verifier._calculate_consensus = lambda results: {
        "answer": None,
        "confidence": 0.0,
        "status": "degraded",
    }

    result = await verifier.verify_async("2+2", mode=VerificationMode.SINGLE, timeout_seconds=0.1)

    assert any(
        item.engine_name == "consensus_orchestrator" and item.error == "boom"
        for item in result.verification_chain
    )


def test_database_logging_redacts_credentials(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:supersecret@db.example/qwed")
    logger = MagicMock()

    with patch("logging.getLogger", return_value=logger):
        _load_module("database_redaction_test", "src/qwed_new/core/database.py")

    debug_messages = [call.args[1] for call in logger.debug.call_args_list if len(call.args) > 1]
    assert any("db.example" in message for message in debug_messages)
    assert all("supersecret" not in message for message in debug_messages)


def test_telemetry_init_logs_when_disabled(monkeypatch):
    monkeypatch.setenv("OTEL_ENABLED", "false")
    logger = MagicMock()

    with patch("logging.getLogger", return_value=logger):
        module = _load_module("telemetry_disabled_test", "src/qwed_new/core/telemetry.py")

    module._init_telemetry.cache_clear()
    module._init_telemetry()

    logger.info.assert_any_call("OpenTelemetry disabled via OTEL_ENABLED=false")


def test_telemetry_requests_instrumentation_logs_missing_dependency(monkeypatch):
    monkeypatch.setenv("OTEL_ENABLED", "true")
    logger = MagicMock()

    with patch("logging.getLogger", return_value=logger):
        module = _load_module("telemetry_requests_test", "src/qwed_new/core/telemetry.py")

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "opentelemetry.instrumentation.requests":
            raise ImportError("requests instrumentation unavailable")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module.instrument_requests()

    logger.info.assert_any_call("opentelemetry-instrumentation-requests not installed")
