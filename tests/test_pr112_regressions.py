import builtins
import asyncio
import sys
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from qwed.guards.attestation_guard import AttestationGuard
from qwed_sdk.cache import VerificationCache
from qwed_new.api import main as api_main
from qwed_new.core.agent_service import AgentService
from qwed_new.core.consensus_verifier import ConsensusVerifier
from qwed_new.core.logic_verifier import LogicVerifier
from qwed_new.core.reasoning_verifier import ReasoningVerifier
from qwed_new.core import symbolic_verifier as symbolic_module
from qwed_new.core.symbolic_verifier import SymbolicVerifier
from qwed_new.core.verifier import VerificationEngine


def _block_import(monkeypatch, blocked_prefixes):
    real_import = builtins.__import__

    def fake_import(name, globals_=None, locals_=None, fromlist=(), level=0):
        for prefix in blocked_prefixes:
            if name == prefix or name.startswith(prefix + "."):
                raise ImportError(f"blocked import: {name}")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_agent_service_initializes_cleanly():
    service = AgentService()

    assert service._agents == {}
    assert service._activity_logs == []


def test_cache_print_stats_uses_plain_fallback_when_qwed_local_import_fails(monkeypatch, tmp_path, capsys):
    _block_import(monkeypatch, ["qwed_sdk.qwed_local"])
    sys.modules.pop("qwed_sdk.qwed_local", None)

    cache = VerificationCache(cache_dir=str(tmp_path))
    cache.print_stats()

    output = capsys.readouterr().out
    assert "Cache Statistics" in output


def test_consensus_helper_fallbacks_and_failures(monkeypatch):
    _block_import(monkeypatch, ["qwed_new.core.translator"])
    sys.modules.pop("qwed_new.core.translator", None)

    verifier = ConsensusVerifier()

    expression, expected = verifier._parse_math_query("What is 12 plus 30?")
    assert expression == "12 + 30"
    assert expected == Decimal("42")

    with pytest.raises(ValueError, match="Verification code generation failed"):
        verifier._generate_verification_code("What is 2 plus 2?")

    with pytest.raises(ValueError, match="Logic translation failed"):
        verifier._model_as_logic("If A then B")


def test_logic_verifier_unsat_explanation_falls_back_when_core_lookup_fails():
    verifier = LogicVerifier()

    class BadSolver:
        def set(self, *_args, **_kwargs):
            return None

        def unsat_core(self):
            raise RuntimeError("unsat core unavailable")

    explanation = verifier._explain_unsat(BadSolver(), ["x > 1", "x < 0"])

    assert explanation == "Constraints are logically inconsistent"


def test_reasoning_verifier_safe_arithmetic_and_fallback():
    verifier = ReasoningVerifier(enable_cache=False)

    assert verifier._safe_arithmetic_eval("1 + 2 * 3") == Decimal("7")
    assert verifier._safe_arithmetic_eval("2 ** 3") == Decimal("8")
    assert verifier._formulas_equivalent("1/0", "1") is False


def test_symbolic_verifier_reports_bounds_transform_error(monkeypatch):
    verifier = SymbolicVerifier()
    code = """
def add(x: int, y: int) -> int:
    return x + y
"""

    def broken_unparse(_tree):
        raise RuntimeError("boom")

    monkeypatch.setattr(symbolic_module.ast, "unparse", broken_unparse)

    result = verifier.verify_bounded(code)

    assert result["status"] == "bounds_transform_error"
    assert result["bounded"] is False


def test_verification_engine_skips_domain_error_samples():
    engine = VerificationEngine()

    result = engine.verify_identity("sqrt(x)", "x")

    assert result["status"] == "NOT_EQUIVALENT"


def test_verify_math_returns_symbolic_result_for_non_numeric_expression(monkeypatch):
    monkeypatch.setattr(api_main, "check_rate_limit", lambda _api_key: None)

    class DummySession:
        def add(self, _item):
            return None

        def commit(self):
            return None

    tenant = SimpleNamespace(api_key="", organization_id=1)
    session = DummySession()

    result = asyncio.run(api_main.verify_math({"expression": "x + 1"}, tenant, session))

    assert result["is_valid"] is True
    assert result["is_symbolic"] is True


def test_attestation_guard_requires_secret(monkeypatch):
    monkeypatch.delenv("QWED_ATTESTATION_SECRET", raising=False)

    with pytest.raises(ValueError, match="Refusing insecure fallback secret"):
        AttestationGuard()


def test_attestation_guard_uses_injected_timestamp(monkeypatch):
    monkeypatch.setenv("QWED_ATTESTATION_SECRET", "x" * 16)
    guard = AttestationGuard()

    token = guard.sign_verification(
        "what is 2+2?",
        {"verified": True},
        timestamp=123.0,
    )
    payload = guard.verify_attestation(token)

    assert payload["timestamp"] == 123.0
