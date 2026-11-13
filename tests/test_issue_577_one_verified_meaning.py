"""#577: the attestation, the audit row and the batch summary each decided "verified" differently.

- The attestation signed ``verified: true`` unless ``is_valid`` was false, so a
  result with no ``is_valid``, such as a logic result, was signed as verified
  next to an admission of BLOCKED.
- Audit rows stored ``is_authoritative``, which is true for every VERIFIED
  result, so SQL proven unsafe was stored as verified.
- The batch summary counted statuses only, so an item proven false counted as
  verified.

"Verified" now has one meaning, ``claim_verified``: VERIFIED with ``is_valid``
true.
"""

from unittest.mock import patch

import pytest

from qwed_new.api import main as api_main
from qwed_new.core.attestation import get_attestation_service
from qwed_new.core.consensus_verifier import ConsensusResult, EngineResult
from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus, aggregate_batch_diagnostic, claim_verified
from qwed_new.core.trust import attest_and_enforce
from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)

UNSAFE_SQL = "SELECT name FROM users WHERE id = 5 OR 1=1"
SCHEMA = "CREATE TABLE users (id INT, name TEXT)"


def _signed_verified(token):
    return get_attestation_service().verify_attestation(token)[1]["qwed"]["result"]["verified"]


def _audit_rows(monkeypatch):
    rows = []
    monkeypatch.setattr(api_main, "_safe_commit_log", rows.append)
    return rows


def _png(width, height):
    size = width.to_bytes(4, "big") + height.to_bytes(4, "big")
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + size + b"A" * 16


@pytest.mark.parametrize("status, is_valid, verified", [
    ("VERIFIED", True, True),
    # Proven false, as SQL proven unsafe is.
    ("VERIFIED", False, False),
    # No is_valid: it says nothing about the claim.
    ("VERIFIED", None, False),
    ("UNVERIFIABLE", True, False),
    ("BLOCKED", True, False),
])
def test_verified_means_verified_and_valid(status, is_valid, verified):
    fields = {"constraint_id": "x"} if is_valid is None else {"constraint_id": "x", "is_valid": is_valid}
    if status == "VERIFIED":
        result = DiagnosticResult.verified("m", fields, {"e": 1})
    elif status == "BLOCKED":
        result = DiagnosticResult.blocked("m", fields)
    else:
        result = DiagnosticResult.unverifiable("m", fields)

    assert claim_verified(result) is verified


def test_sql_proven_unsafe_is_not_verified_in_the_attestation_or_the_audit_row(client, monkeypatch):  # noqa: F811
    # It was signed and stored as verified: is_valid false is not "not valid"
    # to is_authoritative.
    rows = _audit_rows(monkeypatch)

    body = client.post("/verify/sql", json={"query": UNSAFE_SQL, "schema_ddl": SCHEMA}).json()

    assert body["status"] == "VERIFIED"
    assert body["is_valid"] is False
    assert body["admission"] == "BLOCKED"
    assert _signed_verified(body["attestation"]) is False
    assert [row.is_verified for row in rows] == [False]


def test_a_result_with_no_is_valid_is_not_signed_as_verified():
    # A logic result has no is_valid, and was signed verified: true beside an
    # admission of BLOCKED.
    result = DiagnosticResult.verified("SAT", {"constraint_id": "logic.sat"}, {"model": "x = 1"})

    signed = attest_and_enforce(result, engine="logic", query="(GT x 0)")

    assert _signed_verified(signed.attestation) is False


def test_a_size_claim_proven_true_is_still_verified(client, monkeypatch):  # noqa: F811
    rows = _audit_rows(monkeypatch)
    files = {"image": ("i.png", _png(800, 600), "image/png")}

    body = client.post("/verify/image", files=files, data={"claim": "800x600"}).json()

    assert body["status"] == "VERIFIED"
    assert _signed_verified(body["attestation"]) is True
    assert [row.is_verified for row in rows] == [True]


def test_a_verified_consensus_is_not_verified_anywhere(client, monkeypatch):  # noqa: F811
    # Two engines agreed on an answer to the model's translation of the query
    # (#585). The response said meets_requirement true, the token verified:
    # true and the audit row verified, though nothing verified the claim.
    rows = _audit_rows(monkeypatch)
    chain = [EngineResult(name, "method", 4, 1.0, 1.0, True, status="VERIFIED") for name in ("SymPy", "Z3")]
    consensus = ConsensusResult(
        final_answer=4, confidence=0.999, engines_used=2, agreement_status="unanimous",
        verification_chain=chain, total_latency_ms=1.0, status=DiagnosticStatus.VERIFIED,
        verified_evidence={"agreement_status": "unanimous", "answer": "4", "query": "What is 2 + 2?"},
    )

    async def verify_async(**kwargs):
        return consensus

    with patch.object(api_main.consensus_verifier, "verify_async", verify_async):
        body = client.post("/verify/consensus", json={"query": "What is 2 + 2?"}).json()

    assert body["status"] == "VERIFIED"
    assert body["meets_requirement"] is False
    assert _signed_verified(body["attestation"]) is False
    assert [row.is_verified for row in rows] == [False]


def _item(status, is_valid):
    fields = {} if is_valid is None else {"is_valid": is_valid}
    return {"status": status, "developer_fields": fields}


@pytest.mark.parametrize("items, summary, status", [
    # Proven false: refuted, so blocked, and the batch is BLOCKED.
    ([_item("VERIFIED", False)], {"verified": 0, "blocked": 1, "unverifiable": 0}, "BLOCKED"),
    # No is_valid: unverifiable.
    ([_item("VERIFIED", None)], {"verified": 0, "blocked": 0, "unverifiable": 1}, "UNVERIFIABLE"),
    ([_item("VERIFIED", True), _item("VERIFIED", True)], {"verified": 2, "blocked": 0, "unverifiable": 0}, "VERIFIED"),
])
def test_the_batch_summary_counts_verified_as_the_routes_do(items, summary, status):
    # It counted every VERIFIED item as verified, so a batch of items proven
    # false was VERIFIED.
    result = aggregate_batch_diagnostic(
        items, ["claim"] * len(items), engine="Test",
        constraints={"verified": "v", "blocked": "b", "unverifiable": "u", "empty": "e"},
        messages={"verified": "v", "blocked": "b", "unverifiable": "u", "empty": "e"},
    )

    counted = result.developer_fields["summary"]
    assert {key: counted[key] for key in summary} == summary
    assert result.status.value == status
