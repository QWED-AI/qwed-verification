"""#320 (part B): batch items and the statistics Verification Context.

The verify routes sign every VERIFIED result and enforce the attestation as
mandatory (core/trust.py). The batch did not: natural-language and logic
items used the advisory wrapper (``require_attestation=False``), and code,
fact and SQL items returned the verifier's result with no trust step at all,
so a batch caller got an authoritative VERIFIED that no attestation was ever
issued for. Every item type now takes its route's trust step.

``StatsVerifier.to_verification_context`` builds a document from a result it
is handed and has no token for. It enforced the attestation as optional, so
the document's evidence recorded an unattested VERIFIED. It now enforces it
as mandatory, as the shared bridge does, without signing.
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
    item = BatchItem(id=kind.value, query=ITEMS[kind], verification_type=kind)
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


def test_the_batch_has_no_advisory_trust_step():
    source = Path(batch_module.__file__).read_text(encoding="utf-8")

    assert not re.search(r"require_attestation\s*=\s*False", source)
    assert "create_verification_attestation" not in source


# ---------------------------------------------------------------- statistics

def test_a_verified_stats_result_is_not_recorded_as_an_unattested_verdict():
    doc = StatsVerifier().to_verification_context(_proven(observed_result=2.0), "mean of a == 2")
    doc.validate()
    payload = doc.to_dict()

    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["decision"]["admission"] == "DENY"
    evidence = payload["context"]["evidence"]["evidence"]
    # The evidence said VERIFIED, with its proof_ref, before #320.
    assert evidence["status"] == "BLOCKED"
    assert evidence["proof_ref"] is None
    assert evidence["developer_fields"]["verdict_status"] == "VERIFIED"


def test_the_stats_document_is_not_signed(monkeypatch):
    seen = _signed(monkeypatch)

    StatsVerifier().to_verification_context(_proven(), "mean of a == 2")

    assert seen == []
