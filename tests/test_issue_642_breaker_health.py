"""#642: the consensus circuit breaker counted a verdict as an engine failure.

``_record_engine_result`` recorded a failure for every result with
``success=False``, and ``success`` is the verdict: SymPy sets it to
``is_correct``, Z3 to ``is_sat``. The breaker belongs to the module-level
``consensus_verifier``, which every tenant shares, so three wrong claims in a
row opened SymPy for 30 seconds and every tenant's next consensus request came
back BLOCKED.

The breaker now measures health: an engine that answered within its time
budget is healthy, whatever it answered. An engine that did not answer still
counts against it (#340).
"""

import asyncio
import time

import pytest

from qwed_new.core.consensus_verifier import (
    ConsensusVerifier,
    EngineResult,
    EngineState,
    VerificationMode,
)
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.translator import TranslationLayer

WRONG = MathVerificationTask(expression="2+2", claimed_answer=5, reasoning="stub", confidence=0.9)
QUESTION = "What is 2+2? I say 5."

CALLS = {
    "parallel": lambda v: v.verify_with_consensus(QUESTION, mode=VerificationMode.SINGLE, parallel=True),
    "sequential": lambda v: v.verify_with_consensus(QUESTION, mode=VerificationMode.SINGLE, parallel=False),
    "async": lambda v: asyncio.run(v.verify_async(QUESTION, mode=VerificationMode.SINGLE)),
}


@pytest.fixture
def wrong_claims(monkeypatch):
    """Every question translates to 2+2 with a claimed answer of 5."""
    monkeypatch.setattr(TranslationLayer, "translate", lambda self, query, provider=None: WRONG)


def _stub(query):
    return EngineResult("Stub", "stub", None, 0.0, 1.0, success=False, status="UNVERIFIABLE")


@pytest.mark.parametrize("path", list(CALLS))
def test_wrong_claims_do_not_open_the_breaker(wrong_claims, path):
    verifier = ConsensusVerifier()
    # Two engines, so the parallel case runs _execute_parallel (CodeRabbit).
    verifier._select_engines = lambda query, mode: [("SymPy", verifier._verify_with_math), ("Stub", _stub)]
    for _ in range(verifier.circuit_breaker.failure_threshold + 1):
        chain = CALLS[path](verifier).verification_chain
        sympy = next(r for r in chain if r.engine_name == "SymPy")
        # SymPy ran and decided the claim is wrong; it was never skipped.
        assert (sympy.success, sympy.status) == (False, "UNVERIFIABLE")

    health = verifier.circuit_breaker.get_health("SymPy")
    assert health.state == EngineState.HEALTHY
    assert health.consecutive_failures == 0


@pytest.mark.parametrize("result", [
    EngineResult("Z3", "constraint_solving", None, 0.0, 5.0, success=False, status="UNVERIFIABLE"),
    EngineResult("Stats", "statistical_analysis", None, 0.0, 5.0, success=False, status="UNVERIFIABLE"),
    EngineResult("SymPy", "symbolic_math", None, 0.0, 5.0, success=False, status="BLOCKED",
                 error="Query translation failed"),
], ids=["unsatisfiable", "nothing-to-compute", "untranslatable"])
def test_an_engine_that_answered_is_healthy_whatever_it_answered(result):
    verifier = ConsensusVerifier()
    for _ in range(verifier.circuit_breaker.failure_threshold + 1):
        verifier._record_engine_result(result.engine_name, result)

    assert verifier.circuit_breaker.get_health(result.engine_name).state == EngineState.HEALTHY


def test_an_engine_that_does_not_answer_still_opens_the_breaker():
    # A hung engine is what the breaker is for (#340).
    verifier = ConsensusVerifier()

    def hung(query):
        time.sleep(0.3)
        return EngineResult("SymPy", "symbolic_math", 4, 1.0, 300.0, success=True, status="VERIFIED")

    verifier._select_engines = lambda query, mode: [("SymPy", hung)]
    for _ in range(verifier.circuit_breaker.failure_threshold):
        result = asyncio.run(verifier.verify_async(QUESTION, timeout_seconds=0.05))
        assert result.verification_chain[0].method == "timeout"

    assert verifier.circuit_breaker.get_health("SymPy").state == EngineState.OPEN
