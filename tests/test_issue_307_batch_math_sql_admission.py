"""#307 follow-up: batch maths and SQL items return and store their admission.

``/verify/math`` and ``/verify/sql`` return an admission beside the verdict,
because a VERIFIED verdict is not "safe to use": a proven-false identity and a
proven-malicious query are both VERIFIED, and neither is admitted. Their batch
items returned the verdict only, and their audit rows stored no admission, so
a batch caller had to read ``is_valid`` to tell the two apart. Both now return
the admission their route decides, and the row stores it.
"""

import asyncio
import json

import pytest
from sqlmodel import select

from qwed_new.core import trust
from qwed_new.core.attestation import AttestationResult, AttestationStatus
from qwed_new.core.batch import BatchItem, BatchVerificationService, VerificationType
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.models import VerificationLog
from qwed_new.core.sql_verifier import SQLVerifier
from tests.test_issue_477_audit_batch_agents import _batch, env  # noqa: F401

SCHEMA = "CREATE TABLE users (id INT)"


def _verify(kind, query, params=None):
    if params is None:
        params = {"schema_ddl": SCHEMA} if kind is VerificationType.SQL else {}
    item = BatchItem(id="i", query=query, verification_type=kind, params=params)
    return asyncio.run(BatchVerificationService()._verify_item(item, organization_id=1))


def _signing_fails(monkeypatch):
    def fail(**kwargs):
        return AttestationResult(status=AttestationStatus.BLOCKED, token=None, error_code="SIGNING_FAILURE", error="x")

    monkeypatch.setattr(trust, "create_verification_attestation", fail)


def _sql_verdict(monkeypatch, *, is_valid):
    proven = DiagnosticResult.verified(
        "query proven safe" if is_valid else "query proven malicious",
        developer_fields={"is_valid": is_valid},
        evidence={"query": "q", "safe": is_valid},
    )
    monkeypatch.setattr(SQLVerifier, "verify_sql", lambda self, query, schema_ddl="", dialect="sqlite": proven)


# ---------------------------------------------------------------- maths

@pytest.mark.parametrize("query, status, admission", [
    ("x + x = 2*x", "VERIFIED", "ADMIT"),
    ("x + x = x", "VERIFIED", "BLOCKED"),  # proven false, as on /verify/math (#530)
    ("x + x", "UNVERIFIABLE", "BLOCKED"),  # no claim, only a simplification
])
def test_a_math_item_returns_its_admission(query, status, admission):
    out = _verify(VerificationType.MATH, query)

    assert out["status"] == status
    assert out["admission"] == admission


@pytest.mark.parametrize("query", ["x/x = 1", "(x**2 - 1)/(x - 1) = x + 1"])
def test_a_domain_restricted_identity_is_not_admitted(query):
    # simplify cancels the removable singularity, so the difference is 0; as
    # on /verify/math the identity holds only where both sides are defined
    # (#429), so it is not proven, and must not be admitted (#503 review).
    from qwed_new.core.verifier import DOMAIN_RESTRICTED_IDENTITY

    out = _verify(VerificationType.MATH, query)

    assert out["status"] == "UNVERIFIABLE"
    assert out["constraint_id"] == DOMAIN_RESTRICTED_IDENTITY
    assert out["admission"] == "BLOCKED"


def test_a_math_item_is_not_admitted_when_signing_fails(monkeypatch):
    _signing_fails(monkeypatch)

    out = _verify(VerificationType.MATH, "x + x = 2*x")

    assert out["status"] == "BLOCKED"
    assert out["admission"] == "BLOCKED"


# ---------------------------------------------------------------- SQL

def test_a_safe_sql_item_is_admitted(monkeypatch):
    _sql_verdict(monkeypatch, is_valid=True)

    out = _verify(VerificationType.SQL, "SELECT 1")

    assert out["status"] == "VERIFIED"
    assert out["admission"] == "ADMIT"


def test_a_proven_malicious_sql_item_is_verified_but_not_admitted(monkeypatch):
    _sql_verdict(monkeypatch, is_valid=False)

    out = _verify(VerificationType.SQL, "DROP TABLE users")

    # The verdict is unchanged; the admission is the separate decision.
    assert out["status"] == "VERIFIED"
    assert out["developer_fields"]["is_valid"] is False
    assert out["admission"] == "BLOCKED"


@pytest.mark.parametrize("params", [{}, {"schema_ddl": ""}, {"schema_ddl": None}])
def test_a_sql_item_without_a_schema_fails_as_the_route_refuses_it(monkeypatch, params):
    # /verify/sql answers 400 without a schema: the verifier would skip the
    # table check, so a query against an undeclared table could be admitted
    # (#503 review). The item fails before the verifier runs.
    called = []
    monkeypatch.setattr(SQLVerifier, "verify_sql", lambda *a, **k: called.append(1))

    with pytest.raises(ValueError, match="schema_ddl"):
        _verify(VerificationType.SQL, "SELECT * FROM secrets", params=params)
    assert called == []


def test_a_sql_item_is_not_admitted_when_signing_fails(monkeypatch):
    _sql_verdict(monkeypatch, is_valid=True)
    _signing_fails(monkeypatch)

    out = _verify(VerificationType.SQL, "SELECT 1")

    assert out["status"] == "BLOCKED"
    assert out["admission"] == "BLOCKED"


# ---------------------------------------------------------------- the rows

def test_the_batch_rows_store_what_the_items_return(env, monkeypatch):  # noqa: F811
    _sql_verdict(monkeypatch, is_valid=False)

    body = _batch(env, [
        {"query": "x + x = 2*x", "type": "math"},
        {"query": "x + x = x", "type": "math"},
        {"query": "DROP TABLE users", "type": "sql", "params": {"schema_ddl": SCHEMA}},
        {"query": "SELECT * FROM secrets", "type": "sql"},  # no schema: the item fails
    ]).json()

    env.session.expire_all()
    rows = env.session.exec(select(VerificationLog).where(VerificationLog.organization_id == env.org.id)).all()
    stored = {json.loads(r.result)["batch_item_id"]: r.admission for r in rows}
    returned = {item["id"]: (item["result"] or {}).get("admission") for item in body["items"]}

    assert sorted(returned.values(), key=str) == ["ADMIT", "BLOCKED", "BLOCKED", None]
    assert stored == returned
    failed = [item for item in body["items"] if item["status"] == "failed"]
    assert [item["error"] for item in failed] == ["Missing 'schema_ddl'"]
