"""#633 and #659: consensus is advisory only, and its Z3 engine proves the claim.

#633: ``/verify/consensus`` was presented as a verification mode. Its VERIFIED
branch built a proof, and the route returned any result that said VERIFIED as
such. Every engine decides a model's translation of the question, so engines
that agree have verified nothing. A consensus result is now UNVERIFIABLE or
BLOCKED, never VERIFIED, in every mode; it carries ``advisory_only``, and the
route holds any verifier to that. The SDK reads a consensus response the same
way, whatever the server answers.

#659: in ``maximum`` mode the Z3 engine unpacked the model's logic translation
into two values, so it raised on every question and was BLOCKED. It now proves
the claim from the constraints through the DSL bridge, as ``/verify/logic``
does, on the one z3 thread. Z3 decides whether a claim holds, not a value, so
it does not vote on the answer.
"""

import asyncio
import copy
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from hypothesis import given, settings as hypothesis_settings, strategies as st

from qwed_new.api import main as api_main
from qwed_new.core import control_plane, z3_thread
from qwed_new.core.consensus_verifier import (
    ADVISORY_MESSAGE,
    NO_INDEPENDENT_VERIFICATION,
    SECURE_EXECUTION_REQUIRED,
    ConsensusResult,
    ConsensusVerifier,
    EngineResult,
    VerificationMode,
    _EngineCall,
    advisory,
)
from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus, claim_verified
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier, DSLVerificationResult
from qwed_new.core.schemas import LogicVerificationTask
from qwed_sdk import AttestationError, QWEDAsyncClient, QWEDClient, VerificationResult
from qwed_sdk.client import _attestation_of
from qwed_sdk.models import CONSENSUS_STATUSES, advisory_result, is_admitted
from tests.test_issue_320_logic_route_admission import _rows, client  # noqa: F401  (fixture)
from tests.test_issue_578_raw_translation import MODEL, model  # noqa: F401  (fixture)

CYRILLIC_I = chr(0x0406)
ZERO_WIDTH_SPACE = chr(0x200B)
NOT_VERIFIED = {"UNVERIFIABLE", "BLOCKED"}


def _logic(model, monkeypatch, constraints, claim=None, goal="VALIDITY"):  # noqa: F811
    """The model translates every logic question into this task."""
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=constraints, claim=claim, goal=goal)
    monkeypatch.setattr(model, "translate_logic", lambda query: task)


def _z3(query="x is over 5. Is x over 3?"):
    return ConsensusVerifier(enable_circuit_breaker=False)._verify_with_logic(query)


def _engine(name, answer, status="VERIFIED", success=True):
    return EngineResult(name, "method", answer, 1.0, 1.0, success, status=status)


# ------------------------------------------------------------------ #659 Z3


def test_the_z3_engine_proves_a_claim_that_follows(model, monkeypatch):  # noqa: F811
    # The issue's case: on main the unpack raised, and the engine was BLOCKED.
    _logic(model, monkeypatch, ["x > 5"], claim="x > 3")

    result = _z3()

    assert result.status == "VERIFIED"
    assert result.success is True
    assert result.result == "VALID"
    assert result.method == "claim_proof"
    assert result.translation.engine == "Z3"
    assert result.translation.translation_model == MODEL
    assert result.translation.output.claim == "x > 3"


@pytest.mark.parametrize("constraints, claim, goal, status, verdict, reason", [
    # A counterexample: x = 6 meets x > 5 and not x > 7.
    (["x > 5"], "x > 7", "VALIDITY", "UNVERIFIABLE", "INVALID", "counterexample"),
    # Constraints that cannot all hold prove every claim, so none.
    (["x > 5", "x < 3"], "x > 100", "VALIDITY", "UNVERIFIABLE", "VACUOUS", "cannot all hold"),
    # No claim: satisfiable constraints prove nothing (#631). The old engine
    # checked only satisfiability.
    (["x > 5"], None, "SATISFIABILITY", "UNVERIFIABLE", None, "no claim"),
    # A claim beside a satisfiability goal is one more condition, not a claim.
    (["x > 5"], "x > 3", "SATISFIABILITY", "UNVERIFIABLE", None, "no claim"),
    # The goal's case and spaces do not matter, as on /verify/logic.
    (["x > 5"], "x > 3", "validity", "VERIFIED", "VALID", None),
    (["x > 5"], "x > 3", " VALIDITY\t", "VERIFIED", "VALID", None),
    # A claim with no constraints is proved for every x.
    ([], "x * x >= 0", "VALIDITY", "VERIFIED", "VALID", None),
    ([], "x > 3", "VALIDITY", "UNVERIFIABLE", "INVALID", "counterexample"),
    # A goal the bridge does not know, look-alike and invisible letters too.
    (["x > 5"], "x > 3", "PROVE", "BLOCKED", None, "Unsupported logic goal"),
    (["x > 5"], "x > 3", f"VALID{CYRILLIC_I}TY", "BLOCKED", None, "Unsupported logic goal"),
    (["x > 5"], "x > 3", f"VALI{ZERO_WIDTH_SPACE}DITY", "BLOCKED", None, "Unsupported logic goal"),
    # A constraint the bridge refuses to translate.
    (["__import__('os').getpid() > 0"], "x > 3", "VALIDITY", "BLOCKED", None, "translation failed"),
], ids=[
    "counterexample", "vacuous", "no-claim", "claim-beside-sat-goal", "goal-lowercase",
    "goal-spaces", "claim-alone", "claim-alone-false", "goal-unknown", "goal-cyrillic",
    "goal-zero-width", "refused-constraint",
])
def test_the_z3_engine_verifies_only_a_claim_that_follows(
    model, monkeypatch, constraints, claim, goal, status, verdict, reason,  # noqa: F811
):
    _logic(model, monkeypatch, constraints, claim=claim, goal=goal)

    result = _z3()

    assert result.status == status
    assert result.success is (status == "VERIFIED")
    assert result.result == verdict
    if reason is not None:
        assert reason in result.error
    # The translation is kept whatever the verdict (#578).
    assert result.translation.engine == "Z3"
    assert result.translation.output.goal == goal


@pytest.mark.parametrize("verdict, status", [
    ("UNKNOWN", "UNVERIFIABLE"),
    ("ERROR", "BLOCKED"),
    ("BLOCKED", "BLOCKED"),
    # prove_from_dsl never gives these; if it did, nothing is VERIFIED.
    ("SAT", "BLOCKED"),
    ("valid", "BLOCKED"),
    ("VALID ", "BLOCKED"),
    ("", "BLOCKED"),
], ids=["unknown", "error", "blocked", "sat", "lowercase-valid", "valid-space", "empty"])
def test_only_valid_is_verified(model, monkeypatch, verdict, status):  # noqa: F811
    _logic(model, monkeypatch, ["x > 5"], claim="x > 3")
    monkeypatch.setattr(
        DSLLogicVerifier, "prove_from_dsl", lambda self, *args: DSLVerificationResult(status=verdict),
    )

    result = _z3()

    assert result.status == status
    assert result.success is False


def test_the_proof_runs_on_the_z3_thread(model, monkeypatch):  # noqa: F811
    # z3py's default context is not thread safe: every solve on a request
    # path runs on the one z3 thread, the logic route's and this engine's.
    _logic(model, monkeypatch, ["x > 5"], claim="x > 3")
    threads = []
    prove = DSLLogicVerifier.prove_from_dsl

    def recording(self, *args):
        threads.append(threading.current_thread().name)
        return prove(self, *args)

    monkeypatch.setattr(DSLLogicVerifier, "prove_from_dsl", recording)

    assert _z3().status == "VERIFIED"
    (name,) = threads
    assert name.startswith("qwed-z3")
    assert control_plane._run_z3_call is z3_thread.run_z3_call


@pytest.mark.parametrize("parallel", [True, False], ids=["parallel", "sequential"])
def test_a_z3_thread_that_does_not_answer_is_an_engine_failure(model, monkeypatch, parallel):  # noqa: F811
    _logic(model, monkeypatch, ["x > 5"], claim="x > 3")
    monkeypatch.setattr(z3_thread, "Z3_CALL_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(DSLLogicVerifier, "prove_from_dsl", lambda self, *args: time.sleep(0.3))
    verifier = ConsensusVerifier()
    call = _EngineCall(verifier._verify_with_logic)
    monkeypatch.setattr(verifier, "_select_engines", lambda query, mode: [("Z3", call)])

    with pytest.raises(TimeoutError):
        verifier._verify_with_logic("q")
    result = verifier.verify_with_consensus("q", mode=VerificationMode.MAXIMUM, parallel=parallel)

    (z3,) = result.verification_chain
    assert z3.status == "BLOCKED"
    # The breaker counts it: the engine did not answer (#642).
    assert verifier.circuit_breaker.get_health("Z3").consecutive_failures == 1
    # The translation it had is kept (#578).
    assert z3.translation.output.claim == "x > 3"
    assert result.status is DiagnosticStatus.BLOCKED


def test_the_z3_latency_is_on_the_monotonic_clock():
    # Not the wall clock, which a clock change can move backwards.
    result = ConsensusVerifier._z3_result("VERIFIED", "VALID", None, [], time.monotonic_ns() - 7_000_000)

    assert 7.0 <= result.latency_ms < 7_000.0


def test_run_z3_call_blocking_runs_on_the_z3_thread_and_times_out(monkeypatch):
    assert z3_thread.run_z3_call_blocking(lambda: threading.current_thread().name).startswith("qwed-z3")

    monkeypatch.setattr(z3_thread, "Z3_CALL_TIMEOUT_SECONDS", 0.05)
    with pytest.raises(TimeoutError):
        z3_thread.run_z3_call_blocking(time.sleep, 0.3)


# ------------------------------------------------------------- agreement


def test_z3_does_not_vote_on_the_answer():
    # SymPy and Python computed 4 and Z3 proved the claim: before, Z3's
    # "VALID" was a third answer, and the consensus a "majority".
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    consensus = verifier._calculate_consensus([
        _engine("SymPy", 4),
        _engine("Python", 4, status="UNVERIFIABLE"),
        _engine("Z3", "VALID"),
    ])

    assert consensus["status"] == "unanimous"
    assert consensus["answer"] == 4
    assert consensus["diagnostic_status"] is DiagnosticStatus.UNVERIFIABLE


def test_z3_alone_is_not_a_consensus_and_gives_no_answer():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    consensus = verifier._calculate_consensus([
        _engine("SymPy", 5, status="UNVERIFIABLE", success=False),
        _engine("Python", 4, status="UNVERIFIABLE"),
        _engine("Z3", "VALID"),
    ])

    assert consensus["status"] == NO_INDEPENDENT_VERIFICATION
    assert consensus["diagnostic_status"] is DiagnosticStatus.BLOCKED
    assert consensus["answer"] is None


def test_a_consensus_with_no_engine_that_computed_an_answer():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    consensus = verifier._calculate_consensus([_engine("Z3", "VALID", status="UNVERIFIABLE")])

    assert consensus["status"] == "no_answer"
    assert consensus["diagnostic_status"] is DiagnosticStatus.UNVERIFIABLE
    assert consensus["answer"] is None


@pytest.mark.parametrize("chain, status", [
    ([_engine("SymPy", 4, status="UNVERIFIABLE"), _engine("Python", 5, status="UNVERIFIABLE")], "split"),
    ([_engine("SymPy", 4), _engine("Python", 5), _engine("Stats", 6, status="UNVERIFIABLE")], "split"),
    ([_engine("SymPy", 4), _engine("Other", 5), _engine("Z3", "VALID")], "split"),
    ([_engine("SymPy", 4), _engine("Python", 4)], "unanimous"),
], ids=["two-advisory", "three", "with-z3", "one-answer"])
def test_answers_with_no_weight_do_not_divide_by_zero(chain, status):
    # Every answer has confidence 0, so there is no weight between them.
    # Answers that differ divided by zero (on main too) instead of a split.
    for result in chain:
        result.confidence = 0.0

    consensus = ConsensusVerifier(enable_circuit_breaker=False)._calculate_consensus(chain)

    assert consensus["status"] == status
    assert consensus["confidence"] == 0.0
    assert consensus["diagnostic_status"] is DiagnosticStatus.UNVERIFIABLE


_CHAIN = st.lists(
    st.builds(
        EngineResult,
        engine_name=st.sampled_from(["SymPy", "Python", "Z3", "Stats", "Other"]),
        method=st.just("method"),
        result=st.one_of(st.none(), st.integers(-3, 3), st.sampled_from(["VALID", "4"])),
        # 0.0 on its own too: answers with no weight between them.
        confidence=st.one_of(st.just(0.0), st.floats(0.0, 1.0)),
        latency_ms=st.just(1.0),
        success=st.booleans(),
        error=st.sampled_from([None, "x", SECURE_EXECUTION_REQUIRED]),
        status=st.sampled_from(["VERIFIED", "UNVERIFIABLE", "BLOCKED", None, "verified", "VERIFIED "]),
    ),
    max_size=6,
)


@hypothesis_settings(max_examples=300, deadline=None)
@given(chain=_CHAIN)
def test_no_chain_gives_a_verified_consensus(chain):
    verifier = ConsensusVerifier(enable_circuit_breaker=False)

    consensus = verifier._calculate_consensus(chain)
    result = ConsensusResult(
        final_answer=consensus["answer"], confidence=consensus["confidence"], engines_used=len(chain),
        agreement_status=consensus["status"], verification_chain=chain, total_latency_ms=1.0,
        status=consensus["diagnostic_status"],
    )
    diagnostic = advisory(result.to_diagnostic_result())

    assert consensus["diagnostic_status"].value in NOT_VERIFIED
    assert "proof_ref" not in consensus
    assert diagnostic.status.value in NOT_VERIFIED
    assert diagnostic.proof_ref is None
    assert diagnostic.developer_fields["advisory_only"] is True
    assert claim_verified(diagnostic) is False


# -------------------------------------------------------------- advisory()


def test_advisory_reads_a_verified_result_as_unverifiable():
    verified = DiagnosticResult.verified(
        "unanimous", {"query_semantics_verified": True, "is_valid": True, "confidence": 0.99}, {"answer": "4"},
    ).with_audit_record('{"translations":[]}')

    result = advisory(verified)

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert result.agent_message == ADVISORY_MESSAGE
    assert result.proof_ref is None
    assert result.attestation is None
    assert "query_semantics_verified" not in result.developer_fields
    assert result.developer_fields["advisory_only"] is True
    assert result.developer_fields["confidence"] == 0.99
    assert result.raw_llm_output == '{"translations":[]}'
    assert claim_verified(result) is False


@pytest.mark.parametrize("make", [
    lambda: DiagnosticResult.blocked("blocked here", {"constraint_id": "c.blocked"}),
    lambda: DiagnosticResult.unverifiable("not settled", {"constraint_id": "c.open"}),
], ids=["blocked", "unverifiable"])
def test_advisory_keeps_a_result_that_is_not_verified(make):
    original = make().with_audit_record("record")

    result = advisory(original)

    assert result.status is original.status
    assert result.agent_message == original.agent_message
    assert result.constraint_id == original.constraint_id
    assert result.raw_llm_output == "record"
    assert result.developer_fields["advisory_only"] is True


@pytest.mark.parametrize("status", ["VERIFIED", "BLOCKED", "verified"])
def test_advisory_reads_a_status_that_is_not_a_diagnostic_status_as_unverifiable(status):
    # A status given as text passes the dataclass's checks without a proof.
    result = advisory(DiagnosticResult(status=status, agent_message="m", developer_fields={}))

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields["advisory_only"] is True


@hypothesis_settings(max_examples=50, deadline=None)
@given(status=st.sampled_from(list(DiagnosticStatus)))
def test_advisory_never_returns_verified(status):
    if status is DiagnosticStatus.VERIFIED:
        result = DiagnosticResult.verified("m", {}, {"e": 1})
    else:
        result = DiagnosticResult(status=status, agent_message="m", developer_fields={})

    assert advisory(result).status in (DiagnosticStatus.UNVERIFIABLE, DiagnosticStatus.BLOCKED)


# ------------------------------------------------------------------- route


def _stand_in(agreement, status, confidence=0.999, chain=()):
    return ConsensusResult(
        final_answer=4, confidence=confidence, engines_used=len(chain), agreement_status=agreement,
        verification_chain=list(chain), total_latency_ms=1.0, status=status,
    )


@pytest.mark.parametrize("stand_in, status", [
    (_stand_in("blocked_secure_execution", DiagnosticStatus.BLOCKED), "BLOCKED"),
    (_stand_in("blocked", DiagnosticStatus.BLOCKED), "BLOCKED"),
    (_stand_in("majority", DiagnosticStatus.UNVERIFIABLE, confidence=0.5), "UNVERIFIABLE"),
    (_stand_in(NO_INDEPENDENT_VERIFICATION, DiagnosticStatus.BLOCKED), "BLOCKED"),
    (_stand_in("unanimous", DiagnosticStatus.UNVERIFIABLE), "UNVERIFIABLE"),
    (_stand_in("unanimous", DiagnosticStatus.VERIFIED), "UNVERIFIABLE"),
    (_stand_in("unanimous", "VERIFIED"), "UNVERIFIABLE"),
    # Below the minimum confidence too, these stay BLOCKED, not UNVERIFIABLE.
    (_stand_in("blocked_secure_execution", DiagnosticStatus.BLOCKED, confidence=0.0), "BLOCKED"),
    (_stand_in("blocked", DiagnosticStatus.BLOCKED, confidence=0.0), "BLOCKED"),
    (_stand_in(NO_INDEPENDENT_VERIFICATION, DiagnosticStatus.BLOCKED, confidence=0.0), "BLOCKED"),
], ids=["secure-execution", "all-blocked", "below-minimum", "one-engine", "unanimous", "says-verified",
        "says-verified-text", "secure-execution-below-minimum", "all-blocked-below-minimum",
        "one-engine-below-minimum"])
def test_every_consensus_response_is_advisory(client, isolated_audit_chain, stand_in, status):  # noqa: F811
    with patch.object(api_main.consensus_verifier, "verify_async", AsyncMock(return_value=stand_in)):
        response = client.post("/verify/consensus", json={"query": "What is 2 + 2?"})
    body = response.json()

    assert response.status_code == 200  # an answer, not an error, below the minimum too
    assert body["status"] == status
    assert body["advisory_only"] is True
    assert body["proof_ref"] is None
    assert body.get("attestation") is None
    assert body["meets_requirement"] is False  # on the early responses too
    assert [row.is_verified for row in _rows(isolated_audit_chain)] == [False]


def test_the_route_documents_only_the_errors_it_returns():
    """Below the minimum confidence, or without a secure execution runtime,
    the route answers 200 (above), so its OpenAPI does not list them as 422
    or 503. 422 is FastAPI's request validation error, and the description
    says the route is advisory."""
    operation = api_main.app.openapi()["paths"]["/verify/consensus"]["post"]

    assert operation["responses"]["422"]["description"] == "Validation Error"
    assert "secure execution" not in operation["responses"]["503"]["description"].lower()
    assert "advisory only" in operation["description"]
    # The errors it does return are named: rate limited, audit record not stored.
    assert "429 when rate limited" in operation["description"]
    assert "500 when the audit" in operation["description"]


@pytest.fixture
def sandbox(monkeypatch):
    """A sandbox that runs the Python engine's code and answers 30."""
    verifier = api_main.consensus_verifier
    monkeypatch.setattr(verifier, "_secure_executor", SimpleNamespace(execute=lambda code, context: (True, None, 30.0)))
    verifier.reset_circuit_breakers()
    yield verifier
    verifier.reset_circuit_breakers()


@pytest.mark.parametrize("mode, status, agreement, engines", [
    ("single", "BLOCKED", NO_INDEPENDENT_VERIFICATION, ["SymPy"]),
    ("high", "BLOCKED", NO_INDEPENDENT_VERIFICATION, ["SymPy", "Python"]),
    # SymPy and Z3 both verified, which was a VERIFIED consensus.
    ("maximum", "UNVERIFIABLE", "unanimous", ["SymPy", "Python", "Z3"]),
])
def test_no_mode_returns_verified(client, isolated_audit_chain, model, sandbox, mode, status, agreement, engines):  # noqa: F811
    body = client.post(
        "/verify/consensus", json={"query": "What is 15% of 200?", "verification_mode": mode, "min_confidence": 0.0},
    ).json()

    assert body["status"] == status
    assert body["agreement_status"] == agreement
    assert body["advisory_only"] is True
    assert body["meets_requirement"] is False
    assert body.get("attestation") is None
    chain = {step["engine"]: step for step in body["verification_chain"]}
    assert sorted(chain) == sorted(engines)
    if "Z3" in chain:
        assert chain["Z3"]["status"] == "VERIFIED"
        assert chain["Z3"]["result"] == "VALID"
        assert chain["Z3"]["translation_model"] == MODEL
    assert [row.is_verified for row in _rows(isolated_audit_chain)] == [False]


@pytest.mark.parametrize("path", ["async", "parallel", "sequential"])
def test_every_execution_path_agrees(model, sandbox, path):  # noqa: F811
    verifier = ConsensusVerifier()
    verifier._secure_executor = sandbox._secure_executor
    query = "What is 15% of 200?"
    if path == "async":
        result = asyncio.run(verifier.verify_async(query, mode=VerificationMode.MAXIMUM))
    else:
        result = verifier.verify_with_consensus(query, mode=VerificationMode.MAXIMUM, parallel=path == "parallel")

    assert result.agreement_status == "unanimous"
    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert result.proof_ref is None
    assert {r.engine_name: r.status for r in result.verification_chain} == {
        "SymPy": "VERIFIED", "Python": "UNVERIFIABLE", "Z3": "VERIFIED",
    }


def test_an_open_z3_breaker_leaves_one_engine_that_verified(model, sandbox):  # noqa: F811
    verifier = ConsensusVerifier()
    verifier._secure_executor = sandbox._secure_executor
    for _ in range(verifier.circuit_breaker.failure_threshold):
        verifier.circuit_breaker.record_failure("Z3")

    result = verifier.verify_with_consensus("What is 15% of 200?", mode=VerificationMode.MAXIMUM, parallel=False)

    assert result.agreement_status == NO_INDEPENDENT_VERIFICATION
    assert result.status is DiagnosticStatus.BLOCKED


# --------------------------------------------------------------------- SDK

# A server from before #633, or any other, can answer VERIFIED with
# meets_requirement true and a signed attestation; the SDK takes none of it.
_SIGNED = {
    "meets_requirement": True, "is_valid": True, "is_verified": True, "admission": "ADMIT",
    "attestation": "t", "proof_ref": "sha256:" + "e" * 64,
}
_SERVER_STATUSES = [
    "VERIFIED", "verified", "Verified", "VERIFIED ", " VERIFIED", "VERIFIED\t", "VERIFIED\n",
    "VERIFIED_", "VERI-FIED", "VERIFIEDS",
    "V" + chr(0x0415) + "RIFIED",  # a Cyrillic look-alike letter
    "VERI" + ZERO_WIDTH_SPACE + "FIED",
    "".join(chr(ord(c) + 0xFEE0) for c in "VERIFIED"),  # full width, VERIFIED under NFKC
    "UNVERIFIED", "VALID", "SAT", "ADMIT", "",
    "blocked", "BLOCKED ", "unverifiable", "UNVERIFIABLE\n",
    None, True, 1, 0, 1.0, [], ["VERIFIED"], {"status": "VERIFIED"},
]


def _sdk_consensus(data, use_async):
    """The SDK's verify_consensus on a server that answers ``data``."""
    if use_async:
        async def run():
            sdk = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")
            sdk._request = AsyncMock(return_value=dict(data))
            return await sdk.verify_consensus("2+2=4")

        return asyncio.run(run())
    sdk = QWEDClient(api_key="k", base_url="http://qwed.test")
    sdk._request = lambda *args, **kwargs: dict(data)
    return sdk.verify_consensus("2+2=4")


def _assert_advisory(result, status):
    """The SDK's result, and the response copy it holds, read as advisory."""
    assert (result.status, result.is_verified) == (status, False)
    assert (result.attestation, result.proof_ref, result.admission) == (None, None, None)
    response = result.result
    assert not set(response) & {"attestation", "proof_ref", "admission"}
    assert (response["status"], response["meets_requirement"], response["advisory_only"]) == (status, False, True)
    # No SDK path takes the response copy as verified either.
    assert is_admitted(response) is False
    assert VerificationResult.from_dict(response).is_verified is False
    sdk = QWEDClient(api_key="k", base_url="http://qwed.test")
    with pytest.raises(AttestationError, match="^no "):
        sdk.verify_attestation(response)


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("status", _SERVER_STATUSES, ids=repr)
def test_the_sdk_reads_any_other_status_as_unverifiable(use_async, status):
    result = _sdk_consensus({"status": status, **_SIGNED}, use_async)

    _assert_advisory(result, "UNVERIFIABLE")
    assert result.result["is_valid"] is True  # the other fields, as sent


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("status", sorted(CONSENSUS_STATUSES))
def test_the_sdk_keeps_an_advisory_status(use_async, status):
    result = _sdk_consensus({"status": status, "advisory_only": True, **_SIGNED}, use_async)

    _assert_advisory(result, status)


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("meets", [True, "true", 1, False, None])
def test_the_sdk_reads_a_response_with_no_status_as_unverifiable(use_async, meets):
    result = _sdk_consensus({"meets_requirement": meets}, use_async)

    _assert_advisory(result, "UNVERIFIABLE")


def test_the_sdk_leaves_the_servers_response_as_it_was():
    data = {"status": "VERIFIED", **_SIGNED}
    sent = dict(data)

    result = advisory_result(data, 1.0)

    assert data == sent
    assert result.result is not data


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
def test_the_sdk_times_a_consensus_on_the_monotonic_clock(monkeypatch, use_async):
    # 5 ms between the two readings around the request, whatever the wall
    # clock does meanwhile.
    readings = iter(range(0, 10**15, 5_000_000))
    monkeypatch.setattr(time, "monotonic_ns", lambda: next(readings))

    result = _sdk_consensus({"status": "UNVERIFIABLE"}, use_async)

    assert result.latency_ms == pytest.approx(5.0)


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=12),
    lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=5), children, max_size=3),
    max_leaves=6,
)
_READ = {"status", "meets_requirement", "advisory_only", "attestation", "proof_ref", "admission"}
_RESPONSE = st.dictionaries(
    st.sampled_from([
        "status", "meets_requirement", "is_valid", "is_verified", "admission", "attestation", "proof_ref",
        "query_semantics_verified", "verification_scope", "advisory_only", "final_answer",
    ]),
    st.one_of(
        st.sampled_from([
            "VERIFIED", "ADMIT", "UNVERIFIABLE", "BLOCKED", "verified", "VERIFIED ", "t",
            "translated_expression_only", "sha256:" + "e" * 64,
        ]),
        _JSON,
    ),
)


@hypothesis_settings(max_examples=300, deadline=None)
@given(data=_RESPONSE)
def test_no_server_response_gives_a_verified_sdk_result(data):
    sent = copy.deepcopy(data)

    result = advisory_result(data, 1.0)
    response = result.result

    assert result.status in CONSENSUS_STATUSES
    assert result.is_verified is False
    assert (result.attestation, result.proof_ref, result.admission) == (None, None, None)
    assert not set(response) & {"attestation", "proof_ref", "admission"}
    assert (response["status"], response["meets_requirement"], response["advisory_only"]) == (
        result.status, False, True,
    )
    assert is_admitted(response) is False
    assert VerificationResult.from_dict(response).is_verified is False
    with pytest.raises(AttestationError):
        _attestation_of(response)
    assert data == sent
    assert all(response[key] == value for key, value in data.items() if key not in _READ)
