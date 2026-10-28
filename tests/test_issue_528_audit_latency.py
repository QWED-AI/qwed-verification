"""#528: the audit log stores how long each verification took.

``GET /audit/logs`` returned ``latency_ms`` as a fixed 0 for every row, and
``VerificationLog`` had no latency field, so a client could not tell a real 0
from "not measured".

Now ``RequestTimingMiddleware`` records when each request starts, and the
audit logger stores the whole milliseconds from then to the row's append as
``latency_ms``, covered by the entry hash. Rows written outside a request,
and rows written before this change, have null. ``/audit/logs``, the log
detail and the CSV exports return the stored value.
"""

import asyncio
import csv
import io
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine, select

from qwed_new.api import main as api_main
from qwed_new.auth.security import create_access_token
from qwed_new.core import audit_logger as audit_module
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.models import Organization, User, VerificationLog
from qwed_new.core.request_caller import RequestTimingMiddleware, request_latency_ms
from qwed_new.core.schema_migrations import add_missing_columns
from qwed_new.core.tenant_context import TenantContext

ORG_ID = 1
NL_OUTPUT = {"diagnostic": DiagnosticResult.unverifiable("not proven").to_dict()}
SLOW_SECONDS = 0.06


@pytest.fixture
def client(isolated_audit_chain):
    # The audit-chain engine also holds the organisation and its owner, so
    # /audit/logs reads the rows the routes wrote.
    SQLModel.metadata.create_all(isolated_audit_chain)
    with Session(isolated_audit_chain) as session:
        session.add(Organization(id=ORG_ID, name="acme", display_name="Acme"))
        session.add(User(id=1, email="owner@acme.example.com", password_hash="x", organization_id=ORG_ID, role="owner"))
        session.commit()
    tenant = TenantContext(organization_id=ORG_ID, organization_name="Acme", tier="free", api_key="k")

    async def slow_nl(query, organization_id=None, preferred_provider=None):
        await asyncio.sleep(SLOW_SECONDS)
        return dict(NL_OUTPUT)

    def session_for_request():
        with Session(isolated_audit_chain) as session:
            yield session

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = session_for_request
    try:
        with patch("qwed_new.api.main.check_rate_limit"), \
                patch.object(api_main.control_plane, "process_natural_language", slow_nl), \
                patch.object(api_main.batch_service.control_plane, "process_natural_language", slow_nl):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _rows(engine):
    with Session(engine) as session:
        return session.exec(select(VerificationLog).order_by(VerificationLog.id)).all()


def _owner():
    return {"Authorization": f"Bearer {create_access_token({'sub': '1'})}"}


def _set(engine, row_id, **fields):
    with Session(engine) as session:
        row = session.get(VerificationLog, row_id)
        row.sqlmodel_update(fields)
        session.add(row)
        session.commit()


def _trail_valid(org_id=ORG_ID):
    return audit_module.get_audit_logger().verify_audit_trail(org_id)["valid"]


# ---------------------------------------------------------------- measuring

def test_a_route_stores_how_long_it_took(client, isolated_audit_chain):
    assert client.post("/verify/natural_language", json={"query": "what is 2+2"}).status_code == 200

    (row,) = _rows(isolated_audit_chain)
    assert isinstance(row.latency_ms, int)
    # The verifier slept SLOW_SECONDS; the row's latency includes it.
    assert row.latency_ms >= SLOW_SECONDS * 1000 - 1
    assert _trail_valid()


def test_each_batch_item_stores_a_latency(client, isolated_audit_chain):
    client.post("/verify/batch", json={"items": [
        {"query": "what is 2+2", "type": "natural_language"},
        {"query": "2+2=4", "type": "math"},
    ]})

    rows = _rows(isolated_audit_chain)
    assert len(rows) == 2
    assert all(isinstance(r.latency_ms, int) and r.latency_ms >= 0 for r in rows)


def test_a_row_written_outside_a_request_has_no_latency(isolated_audit_chain):
    assert request_latency_ms() is None

    audit_module.get_audit_logger().log_verification(ORG_ID, None, "q", {"status": "VERIFIED"}, True, "MATH")

    (row,) = _rows(isolated_audit_chain)
    assert row.latency_ms is None
    assert _trail_valid()


def test_the_middleware_sets_the_start_only_for_http_requests():
    seen = {}

    async def app(scope, receive, send):
        seen[scope["type"]] = request_latency_ms()

    middleware = RequestTimingMiddleware(app)
    asyncio.run(middleware({"type": "http"}, None, None))
    asyncio.run(middleware({"type": "lifespan"}, None, None))

    assert isinstance(seen["http"], int)
    assert seen["lifespan"] is None
    # Reset after the request: nothing leaks into the next one.
    assert request_latency_ms() is None


# ---------------------------------------------------------------- the hash covers it

def test_changing_or_clearing_the_latency_breaks_the_chain(client, isolated_audit_chain):
    client.post("/verify/natural_language", json={"query": "what is 2+2"})
    (row,) = _rows(isolated_audit_chain)
    measured = row.latency_ms

    _set(isolated_audit_chain, row.id, latency_ms=measured + 1000)
    assert not _trail_valid()

    _set(isolated_audit_chain, row.id, latency_ms=None)
    assert not _trail_valid()

    _set(isolated_audit_chain, row.id, latency_ms=measured)
    assert _trail_valid()


def test_a_row_hashed_before_latency_was_covered_still_verifies(isolated_audit_chain):
    # Rewrite a row's hash as a release before #528 wrote it: no latency_ms
    # key in the hashed payload.
    logger = audit_module.get_audit_logger()
    logger.log_verification(ORG_ID, None, "q", {"status": "VERIFIED"}, True, "MATH")
    (row,) = _rows(isolated_audit_chain)
    old_hash = logger._compute_hash(logger._reconstruct_pre_latency_log_data(row))
    _set(isolated_audit_chain, row.id, entry_hash=old_hash, hmac_signature=logger._compute_hmac(old_hash))

    assert _trail_valid()

    # Setting a latency on such a row is caught: no older shape covers it.
    _set(isolated_audit_chain, row.id, latency_ms=5)
    assert not _trail_valid()


# ---------------------------------------------------------------- what the routes return

def test_audit_logs_return_the_stored_latency_and_null_when_not_measured(client, isolated_audit_chain):
    client.post("/verify/natural_language", json={"query": "measured"})
    audit_module.get_audit_logger().log_verification(ORG_ID, None, "unmeasured", {"status": "VERIFIED"}, True, "MATH")
    measured, _unmeasured = _rows(isolated_audit_chain)

    logs = client.get("/audit/logs", headers=_owner()).json()["logs"]
    by_query = {log["request_input"]: log["latency_ms"] for log in logs}

    assert by_query == {"measured": measured.latency_ms, "unmeasured": None}
    assert measured.latency_ms is not None
    detail = client.get(f"/audit/logs/{measured.id}", headers=_owner()).json()
    assert detail["latency_ms"] == measured.latency_ms


def test_the_csv_export_carries_the_latency(client, isolated_audit_chain):
    client.post("/verify/natural_language", json={"query": "measured"})
    (row,) = _rows(isolated_audit_chain)

    rows = list(csv.DictReader(io.StringIO(client.get("/audit/export", headers=_owner()).text)))

    assert [r["Latency (ms)"] for r in rows] == [str(row.latency_ms)]


# ---------------------------------------------------------------- an existing database

def test_the_migration_adds_the_latency_column(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE verificationlog (id INTEGER PRIMARY KEY, organization_id INTEGER, query VARCHAR)"
        ))

    added = add_missing_columns(engine)

    assert "verificationlog.latency_ms" in added
    assert "latency_ms" in {c["name"] for c in inspect(engine).get_columns("verificationlog")}


def test_latency_is_not_read_from_the_stored_result(client, isolated_audit_chain):
    # The value comes from the request's clock, not from anything the
    # verifier or caller put in the result.
    client.post("/verify/natural_language", json={"query": "what is 2+2"})
    (row,) = _rows(isolated_audit_chain)

    assert "latency_ms" not in json.loads(row.result)
