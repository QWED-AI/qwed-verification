"""#320: /verify/consensus verified an answer that only the model had agreed with.

In single mode, the default, the one engine was SymPy, and it compared the
expression the model translated from the query with the answer the same model
gave. A unanimous vote of that one engine was VERIFIED, with
``meets_requirement`` true, so the model's agreement with itself was reported
as a consensus. The proof did not name the query either.

One engine is not a consensus: an answer that only one engine verified is now
BLOCKED, and a VERIFIED consensus binds the query in its proof.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from qwed_new.core import consensus_verifier as cv
from qwed_new.core.consensus_verifier import ConsensusVerifier, EngineResult, VerificationMode
from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)


class _Translator:
    """Stands in for the model: the expression and the answer it claims."""

    def translate(self, query):
        return SimpleNamespace(expression="2+2", claimed_answer=4)


def _engine(name, answer, status="VERIFIED"):
    return EngineResult(name, "method", answer, 1.0, 1.0, True, status=status)


@pytest.mark.parametrize("min_confidence", [0.95, 1.0])
def test_one_engine_agreeing_with_the_model_is_blocked(client, min_confidence):  # noqa: F811
    # SymPy checked the model's expression against the model's own answer,
    # and that was VERIFIED with meets_requirement true.
    with patch("qwed_new.core.translator.TranslationLayer", _Translator):
        body = client.post(
            "/verify/consensus", json={"query": "What is 2 + 2?", "min_confidence": min_confidence},
        ).json()

    assert body["status"] == "BLOCKED"
    assert body["agreement_status"] == "no_independent_verification"
    assert body["meets_requirement"] is False
    assert body.get("proof_ref") is None
    assert [step["engine"] for step in body["verification_chain"]] == ["SymPy"]


@pytest.mark.parametrize("results", [
    [_engine("SymPy", 4)],
    # The same engine twice is still one engine.
    [_engine("SymPy", 4), _engine("SymPy", 4)],
])
def test_an_answer_one_engine_verified_is_not_a_consensus(results):
    consensus = ConsensusVerifier(enable_circuit_breaker=False)._calculate_consensus(results)

    assert consensus["diagnostic_status"] == "BLOCKED"
    assert consensus["status"] == "no_independent_verification"
    assert consensus.get("proof_ref") is None


def test_two_engines_that_verified_the_same_answer_are_a_consensus():
    consensus = ConsensusVerifier(enable_circuit_breaker=False)._calculate_consensus(
        [_engine("SymPy", 4), _engine("Z3", 4)]
    )

    assert consensus["diagnostic_status"] == "VERIFIED"
    assert consensus["status"] == "unanimous"


def test_a_verified_consensus_binds_the_query(monkeypatch):
    # The proof bound the engines and the answer, not the query, so the same
    # answer to different questions had the same proof.
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    monkeypatch.setattr(verifier, "_select_engines", lambda query, mode: [
        ("SymPy", lambda query: _engine("SymPy", 4)),
        ("Z3", lambda query: _engine("Z3", 4)),
    ])

    first = verifier.verify_with_consensus("What is 2 + 2?", mode=VerificationMode.MAXIMUM, parallel=False)
    second = verifier.verify_with_consensus("What is 3 + 1?", mode=VerificationMode.MAXIMUM, parallel=False)

    assert first.verified_evidence["query"] == "What is 2 + 2?"
    assert first.to_diagnostic_result().proof_ref != second.to_diagnostic_result().proof_ref
    assert first.proof_ref == first.to_diagnostic_result().proof_ref


def test_the_blocked_result_says_why():
    result = cv.ConsensusResult(
        final_answer=4, confidence=0.999, engines_used=1,
        agreement_status=cv.NO_INDEPENDENT_VERIFICATION, verification_chain=[_engine("SymPy", 4)],
        total_latency_ms=1.0, status=cv.DiagnosticStatus.BLOCKED,
    )

    diagnostic = result.to_diagnostic_result()

    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.constraint_id == "consensus.no_independent_verification"
    assert "one engine is not a consensus" in diagnostic.agent_message
