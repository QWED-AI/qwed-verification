"""#307 (part): audit rows store the admission decision their route made.

``/audit/logs`` could show a row's verdict but not its admission: the rows
did not store one, so the dashboard showed "admission not recorded" for every
row. A VERIFIED verdict is not an admission (code proven unsafe is VERIFIED
and BLOCKED), so the dashboard needs both.

Now a row stores the admission its route decided and returned: the
natural-language, code, math and SQL routes, the agent route (which decides
one by the natural-language rule) and batch code items. Routes that decide
none store null. The admission is covered by the entry hash, so it cannot be
set or cleared on a stored row; rows written before it was stored still
verify.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlmodel import Session, select

from qwed_new.api import batch_audit
from qwed_new.api import main as api_main
from qwed_new.core.audit_logger import get_audit_logger
from qwed_new.core.batch import BatchItem, VerificationType
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.models import VerificationLog
from qwed_new.core.schema_migrations import add_missing_columns
from qwed_new.core.tenant_context import TenantContext

ORG_ID = 1


@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(organization_id=ORG_ID, organization_name="Org", tier="free", api_key="k")
    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    def _mock_session():
        # A plain function, not MagicMock itself: FastAPI would read MagicMock's
        # constructor parameters as query parameters.
        return MagicMock()

    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _last_row(engine):
    with Session(engine) as session:
        return session.exec(select(VerificationLog).order_by(VerificationLog.id.desc())).first()


def _verify(engine, row_id):
    with Session(engine) as session:
        return get_audit_logger().verify_log_entry(row_id, session)


# ---------------------------------------------------------------- routes that decide

@pytest.mark.parametrize("expression", ["2+2=4", "2+2=5"])
def test_a_math_row_stores_the_admission_the_route_returned(client, isolated_audit_chain, expression):
    response = client.post("/verify/math", json={"expression": expression})

    row = _last_row(isolated_audit_chain)
    assert response.json()["admission"] in ("ADMIT", "BLOCKED")
    assert row.admission == response.json()["admission"]
    assert _verify(isolated_audit_chain, row.id)["valid"] is True


def test_a_code_row_stores_the_admission_the_route_returned(client, isolated_audit_chain):
    response = client.post("/verify/code", json={"code": "import os\nos.system('rm -rf /')", "language": "python"})

    row = _last_row(isolated_audit_chain)
    assert row.admission == response.json()["admission"]
    assert row.admission in ("ADMIT", "BLOCKED")


def test_a_sql_row_stores_the_admission_the_route_returned(client, isolated_audit_chain):
    response = client.post(
        "/verify/sql",
        json={"query": "SELECT name FROM users", "schema_ddl": "CREATE TABLE users (id INT, name TEXT)"},
    )

    row = _last_row(isolated_audit_chain)
    assert row.admission == response.json()["admission"]


def test_a_natural_language_row_stores_the_admission_the_route_returned(client, isolated_audit_chain):
    async def nl(query, organization_id=None, preferred_provider=None):
        return {"diagnostic": DiagnosticResult.unverifiable("not proven").to_dict()}

    with patch.object(api_main.control_plane, "process_natural_language", nl):
        response = client.post("/verify/natural_language", json={"query": "what is 2+2"})

    row = _last_row(isolated_audit_chain)
    assert response.json()["admission"] == "BLOCKED"
    assert row.admission == "BLOCKED"


# ---------------------------------------------------------------- routes that do not

def test_a_route_that_decides_no_admission_stores_null(client, isolated_audit_chain):
    async def logic(query, organization_id=None, preferred_provider=None):
        return {"status": "SAT", "model": {"x": "6"}}

    with patch.object(api_main.control_plane, "process_logic_query", logic):
        response = client.post("/verify/logic", json={"query": "(GT x 5)"})

    row = _last_row(isolated_audit_chain)
    assert "admission" not in response.json()
    assert row.admission is None
    assert _verify(isolated_audit_chain, row.id)["valid"] is True


# ---------------------------------------------------------------- batch

@pytest.mark.parametrize("vtype, status, result, expected", [
    ("code", "completed", {"status": "VERIFIED", "admission": "BLOCKED"}, "BLOCKED"),
    ("code", "completed", {"status": "VERIFIED", "admission": "ADMIT"}, "ADMIT"),
    ("code", "completed", {"status": "VERIFIED", "admission": "MAYBE"}, None),
    ("code", "failed", None, None),
    ("code", "completed", "not a dict", None),
    ("math", "completed", {"status": "VERIFIED", "admission": "ADMIT"}, None),
    ("logic", "completed", {"status": "SAT"}, None),
])
def test_a_batch_row_stores_only_a_code_items_admission(vtype, status, result, expected):
    item = BatchItem(id="j-0", query="q", verification_type=VerificationType(vtype), status=status, result=result)

    assert batch_audit.batch_item_admission(item) == expected


# ---------------------------------------------------------------- the hash

def _append(admission):
    return int(get_audit_logger().log_verification(
        organization_id=ORG_ID, user_id=None, query="q", result={"status": "VERIFIED"},
        is_verified=True, domain="CODE", admission=admission,
    ))


@pytest.mark.parametrize("stored, changed_to", [("BLOCKED", "ADMIT"), ("BLOCKED", None), (None, "ADMIT")])
def test_the_admission_cannot_be_changed_on_a_stored_row(isolated_audit_chain, stored, changed_to):
    row_id = _append(stored)
    with Session(isolated_audit_chain) as session:
        session.exec(text("UPDATE verificationlog SET admission = :a WHERE id = :i").bindparams(a=changed_to, i=row_id))
        session.commit()

    result = _verify(isolated_audit_chain, row_id)

    assert result["valid"] is False
    assert result["checks"]["hash_valid"] is False


def test_a_row_hashed_before_admission_was_covered_still_verifies(isolated_audit_chain):
    """A #484 row: its hash covers the caller fields but has no admission key."""
    logger = get_audit_logger()
    row_id = _append(None)
    with Session(isolated_audit_chain) as session:
        row = session.get(VerificationLog, row_id)
        old_hash = logger._compute_hash(logger._reconstruct_pre_admission_log_data(row))
        row.entry_hash = old_hash
        row.hmac_signature = logger._compute_hmac(old_hash)
        session.add(row)
        session.commit()

    assert _verify(isolated_audit_chain, row_id)["valid"] is True

    # Giving that old row an admission later breaks it.
    with Session(isolated_audit_chain) as session:
        session.exec(text("UPDATE verificationlog SET admission = 'ADMIT' WHERE id = :i").bindparams(i=row_id))
        session.commit()
    assert _verify(isolated_audit_chain, row_id)["valid"] is False


@pytest.mark.parametrize("shape", ["pre_caller", "legacy"])
def test_a_row_from_before_484_cannot_be_given_an_admission(isolated_audit_chain, shape):
    """Both caller fields null and hashed from an older shape: it verifies as
    it is, and setting an admission on it breaks it (#307 review)."""
    logger = get_audit_logger()
    row_id = _append(None)
    with Session(isolated_audit_chain) as session:
        row = session.get(VerificationLog, row_id)
        row.api_key_id = None
        row.verifier_version = None
        payload = (
            logger._reconstruct_pre_caller_log_data(row)
            if shape == "pre_caller"
            else logger._reconstruct_legacy_log_data(row)
        )
        row.entry_hash = logger._compute_hash(payload)
        row.hmac_signature = logger._compute_hmac(row.entry_hash)
        session.add(row)
        session.commit()

    assert _verify(isolated_audit_chain, row_id)["valid"] is True

    with Session(isolated_audit_chain) as session:
        session.exec(text("UPDATE verificationlog SET admission = 'ADMIT' WHERE id = :i").bindparams(i=row_id))
        session.commit()
    result = _verify(isolated_audit_chain, row_id)
    assert result["valid"] is False
    assert result["checks"]["hash_valid"] is False


# ---------------------------------------------------------------- reading it back

def test_the_audit_log_routes_return_the_stored_admission(isolated_audit_chain, monkeypatch):
    from qwed_new.auth import audit_routes

    blocked, none = _append("BLOCKED"), _append(None)
    user = MagicMock(organization_id=ORG_ID, role="admin", is_active=True)
    with Session(isolated_audit_chain) as session:
        api_main.app.dependency_overrides[audit_routes.get_session] = lambda: session
        api_main.app.dependency_overrides[api_main.get_session] = lambda: session
        reader = audit_routes._READER.dependency
        api_main.app.dependency_overrides[reader] = lambda: user
        try:
            client = TestClient(api_main.app)
            logs = {row["id"]: row for row in client.get("/audit/logs").json()["logs"]}
            detail = client.get(f"/audit/logs/{blocked}").json()
        finally:
            api_main.app.dependency_overrides.clear()

    assert logs[str(blocked)]["admission"] == "BLOCKED"
    assert logs[str(none)]["admission"] is None
    assert detail["admission"] == "BLOCKED"


def test_the_migration_adds_the_admission_column(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE verificationlog (id INTEGER PRIMARY KEY, organization_id INTEGER, query VARCHAR)"
        ))

    added = add_missing_columns(engine)

    assert "verificationlog.admission" in added
    assert "admission" in {c["name"] for c in inspect(engine).get_columns("verificationlog")}
