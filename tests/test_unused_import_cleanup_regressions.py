import builtins
import importlib
import sys

from src.qwed_new.core.money import Money, verify_invoice_total
from src.qwed_new.core.reasoning_verifier import ReasoningVerifier
from src.qwed_new.core.dsl.parser import parse_and_validate
from src.qwed_new.guards.pii_guard import PIIGuard


def _import_with_blocked_prefixes(monkeypatch, module_name, blocked_prefixes):
    real_import = builtins.__import__

    def fake_import(name, globals_=None, locals_=None, fromlist=(), level=0):
        for prefix in blocked_prefixes:
            if name == prefix or name.startswith(prefix + "."):
                raise ImportError(f"blocked optional dependency: {name}")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


def test_optional_sdk_imports_fall_back_cleanly(monkeypatch):
    crewai_module = _import_with_blocked_prefixes(monkeypatch, "qwed_sdk.crewai", ["crewai"])
    langchain_module = _import_with_blocked_prefixes(monkeypatch, "qwed_sdk.langchain", ["langchain"])
    llamaindex_module = _import_with_blocked_prefixes(monkeypatch, "qwed_sdk.llamaindex", ["llama_index"])

    assert crewai_module.CREWAI_AVAILABLE is False
    assert langchain_module.LANGCHAIN_AVAILABLE is False
    assert llamaindex_module.LLAMAINDEX_AVAILABLE is False
    assert hasattr(crewai_module, "Agent")
    assert hasattr(langchain_module, "BaseTool")
    assert hasattr(llamaindex_module, "BaseNodePostprocessor")


def test_money_invoice_verification_still_works():
    subtotal = Money("100.00", "INR")
    tax = Money("18.00", "INR")
    total = Money("118.00", "INR")

    is_valid, message = verify_invoice_total(subtotal, tax, total)

    assert is_valid is True
    assert message == "Invoice total is correct"


def test_pii_guard_detects_secret_like_value():
    guard = PIIGuard()

    result = guard.scan("api=sk-proj-abcdefghijklmnopqrstuvwxyz123456")

    assert result["verified"] is False
    assert "openai_api_key" in result["types"]


def test_reasoning_verifier_reports_cache_stats():
    verifier = ReasoningVerifier(providers=["anthropic"], enable_cache=False)

    stats = verifier.get_cache_stats()

    assert stats["size"] >= 0
    assert stats["max_size"] == verifier._cache_max_size


def test_dsl_parser_parse_and_validate_success():
    result = parse_and_validate("(AND (GT x 5) (LT y 10))")

    assert result["status"] == "SUCCESS"
    assert result["ast"] == ["AND", ["GT", "x", 5], ["LT", "y", 10]]
