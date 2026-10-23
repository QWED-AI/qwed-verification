"""#320 (part B): batch items and the statistics Verification Context.

The verify routes sign every VERIFIED result and enforce the attestation as
mandatory (core/trust.py). The batch did not: natural-language and logic
items used the advisory wrapper (``require_attestation=False``), and code,
fact and SQL items returned the verifier's result with no trust step at all,
so a batch caller got an authoritative VERIFIED that no attestation was ever
issued for. Every item type now takes its route's trust step.

Batch code, fact and SQL items sign from worker threads, so the shared
attestation service is created under a lock: two first calls racing must not
each build a service with its own key.

``StatsVerifier.to_verification_context`` builds a document from a result it
is handed and has no token for. It used the advisory wrapper and blocked a
VERIFIED result by a hard-coded branch; mandatory enforcement now decides the
document, as in the shared bridge, without signing, and the evidence stays
the verifier's own result.
"""

import asyncio
import re
from pathlib import Path

import pytest

from qwed_new.core import batch as batch_module
from qwed_new.core import trust
from qwed_new.core.attestation import AttestationResult, AttestationStatus
from qwed_new.core.batch import BatchItem, BatchVerificationService, VerificationType
from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.fact_verifier import FactVerifier
from qwed_new.core.sql_verifier import SQLVerifier
from qwed_new.core.stats_verifier import StatsVerifier


def _proven(**fields):
    return DiagnosticResult.verified(
        "proven",
        developer_fields={"is_valid": True, **fields},
        evidence={"proof": "stand-in"},
    )


class _ControlPlane:
    async def process_natural_language(self, query, organization_id=None):
        dr = _proven(translated_expression="2+2=4", verification_scope="translated_expression_only")
        return {"diagnostic": dr.to_dict()}

    async def process_logic_query(self, query, organization_id=None):
        return {"status": "SAT", "model": {"x": "6"}, "dsl_code": "(GT x 5)"}


@pytest.fixture
def stand_ins(monkeypatch):
    monkeypatch.setattr(CodeVerifier, "verify_code", lambda self, code, language="python": _proven())
    monkeypatch.setattr(FactVerifier, "verify_fact", lambda self, claim, context="", **kw: _proven())
    monkeypatch.setattr(SQLVerifier, "verify_sql", lambda self, query, schema_ddl="", dialect="sqlite": _proven())


ITEMS = {
    VerificationType.NATURAL_LANGUAGE: "what is two plus two",
    VerificationType.LOGIC: "(GT x 5)",
    VerificationType.MATH: "x + x = 2*x",
    VerificationType.CODE: "result = 1 + 1",
    VerificationType.FACT: "the sky is blue",
    VerificationType.SQL: "SELECT 1",
}


def _verify(kind):
    service = BatchVerificationService()
    service._control_plane = _ControlPlane()  # the property builds one lazily
    # A SQL item needs a schema, as /verify/sql does (#503).
    params = {"schema_ddl": "CREATE TABLE t (id INT)"} if kind is VerificationType.SQL else {}
    item = BatchItem(id=kind.value, query=ITEMS[kind], verification_type=kind, params=params)
    return asyncio.run(service._verify_item(item, organization_id=1))


def _signing_fails(monkeypatch):
    def fail(**kwargs):
        return AttestationResult(status=AttestationStatus.BLOCKED, token=None, error_code="SIGNING_FAILURE", error="x")

    monkeypatch.setattr(trust, "create_verification_attestation", fail)


def _signed(monkeypatch):
    seen = []
    original = trust.create_verification_attestation

    def capture(**kwargs):
        seen.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(trust, "create_verification_attestation", capture)
    return seen


# ---------------------------------------------------------------- the batch

@pytest.mark.parametrize("kind", list(ITEMS))
def test_a_batch_item_is_signed_and_stays_verified(stand_ins, monkeypatch, kind):
    seen = _signed(monkeypatch)

    out = _verify(kind)

    assert out["status"] == "VERIFIED"
    assert out["proof_ref"]
    assert len(seen) == 1
    assert seen[0]["proof_hash"] == out["proof_ref"]


@pytest.mark.parametrize("kind", list(ITEMS))
def test_a_batch_item_is_blocked_when_signing_fails(stand_ins, monkeypatch, kind):
    # Before #320 every one of these came back VERIFIED regardless.
    _signing_fails(monkeypatch)

    out = _verify(kind)

    assert out["status"] == "BLOCKED"
    assert out["proof_ref"] is None


@pytest.mark.parametrize("kind, engine", [
    (VerificationType.NATURAL_LANGUAGE, "natural_language"),
    (VerificationType.LOGIC, "logic"),
    (VerificationType.MATH, "math"),
    (VerificationType.CODE, "code"),
    (VerificationType.FACT, "fact"),
    (VerificationType.SQL, "sql"),
])
def test_a_batch_item_is_signed_as_its_route_signs_it(stand_ins, monkeypatch, kind, engine):
    seen = _signed(monkeypatch)

    _verify(kind)

    assert seen[0]["engine"] == engine
    # A natural-language verdict covers the translated expression (#320).
    expected = "2+2=4" if kind is VerificationType.NATURAL_LANGUAGE else ITEMS[kind]
    assert seen[0]["query"] == expected


def test_a_code_item_is_admitted_on_the_enforced_verdict(stand_ins, monkeypatch):
    assert _verify(VerificationType.CODE)["admission"] == "ADMIT"

    _signing_fails(monkeypatch)

    out = _verify(VerificationType.CODE)
    assert out["status"] == "BLOCKED"
    assert out["admission"] == "BLOCKED"


def test_concurrent_first_signers_share_one_attestation_service(monkeypatch):
    """Batch code, fact and SQL items sign from worker threads. Two first
    calls racing must not each build a service with its own key, or a token
    signed by one fails the other's check (#502 review)."""
    import threading
    import time

    from qwed_new.core import attestation

    class SlowService(attestation.AttestationService):
        def __init__(self, *args, **kwargs):
            time.sleep(0.05)  # widen the window the race needs
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(attestation, "AttestationService", SlowService)
    monkeypatch.setattr(attestation, "_default_service", None)

    start = threading.Barrier(8)
    services = []

    def first_call():
        start.wait()
        services.append(attestation.get_attestation_service())

    threads = [threading.Thread(target=first_call) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len({id(s) for s in services}) == 1


def test_the_batch_has_no_advisory_trust_step():
    source = Path(batch_module.__file__).read_text(encoding="utf-8")

    assert not re.search(r"require_attestation\s*=\s*False", source)
    assert "create_verification_attestation" not in source


# ---------------------------------------------------------------- statistics

def test_a_verified_stats_result_is_blocked_by_mandatory_enforcement(monkeypatch):
    from qwed_new.core import stats_verifier

    calls = []
    original = stats_verifier.enforce_trust_decision

    def capture(result, **kwargs):
        calls.append(kwargs)
        return original(result, **kwargs)

    monkeypatch.setattr(stats_verifier, "enforce_trust_decision", capture)

    doc = StatsVerifier().to_verification_context(_proven(), "mean of a == 2")
    doc.validate()
    payload = doc.to_dict()

    assert calls == [{"require_attestation": True, "query": "mean of a == 2"}]
    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["decision"]["admission"] == "DENY"
    assert payload["context"]["evidence"]["proof_ref"] is None


def test_the_stats_evidence_keeps_what_the_verifier_observed():
    observed = {"observed_result": 2.0, "dataset_sha256": "a" * 64, "generated_code": "result = df['a'].mean()"}

    doc = StatsVerifier().to_verification_context(_proven(**observed), "mean of a == 2")
    evidence = doc.to_dict()["context"]["evidence"]["evidence"]

    # The enforcement's BLOCKED result carries gate fields only; the
    # document keeps the verifier's own report for review (#502 review).
    for key, value in observed.items():
        assert evidence["developer_fields"][key] == value
    assert evidence["agent_message"] == "proven"


def test_the_stats_document_is_not_signed(monkeypatch):
    seen = _signed(monkeypatch)

    StatsVerifier().to_verification_context(_proven(), "mean of a == 2")

    assert seen == []
