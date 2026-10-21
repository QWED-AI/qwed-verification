"""#476: the "SOC 2" report returned fixed PASS values that nothing checked.

`GET /admin/compliance/report/soc2/{org_id}` returned `security_controls` and
`compliance_status` blocks of fixed strings ("audit_trail_complete": "PASS",
"access_control": "RBAC + API Keys", ...), and counted `SecurityEvent` rows
of a type nothing writes ("BLOCKED"), so `threats_blocked` and `block_rate`
were always 0. It called itself a SOC 2 Type II report, which is an auditor's
attestation the server cannot issue.

The report is now a "Security activity summary": the fixed blocks are gone,
events are counted by the types actually written, and `audit_trail` comes
from `verify_audit_trail` over the period, failing closed. The URL is
unchanged.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import generate_api_key
from qwed_new.core import audit_logger as audit_module
from qwed_new.core import compliance_exporter as exporter_module
from qwed_new.core.audit_logger import AUDIT_SECRET_ENV_VAR
from qwed_new.core.compliance_exporter import ComplianceExporter
from qwed_new.core.models import (
    ApiKey,
    Organization,
    SecurityEvent,
    User,
    VerificationLog,
)

exporter = ComplianceExporter()


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'summary.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(exporter_module, "engine", engine)
    monkeypatch.setattr(audit_module, "engine", engine)
    monkeypatch.setenv(AUDIT_SECRET_ENV_VAR, "audit-fixture-value")
    # A fresh process-wide logger, so no chain head leaks between tests.
    monkeypatch.setattr(audit_module, "_default_logger", None)
    session = Session(engine)
    org = Organization(name="acme", display_name="Acme")
    session.add(org)
    session.commit()
    session.refresh(org)
    yield SimpleNamespace(engine=engine, session=session, org=org)
    session.close()


def _log(org_id, query="2+2"):
    return audit_module.get_audit_logger().log_verification(
        organization_id=org_id, user_id=None, query=query,
        result={"status": "VERIFIED"}, is_verified=True, domain="math",
    )


def _event(db, event_type, *, days_ago=0):
    db.session.add(SecurityEvent(
        organization_id=db.org.id, event_type=event_type, query="q", reason="r",
        timestamp=datetime.now(timezone.utc) - timedelta(days=days_ago),
    ))
    db.session.commit()


def _values(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _values(value)
    elif isinstance(node, list):
        for value in node:
            yield from _values(value)
    else:
        yield node


# ---------------------------------------------------------------- no fixed claims

def test_the_report_no_longer_carries_fixed_claims(db):
    report = exporter.generate_soc2_report(db.org.id)

    assert report["report_type"] == "Security activity summary"
    assert "not a SOC 2 report" in report["disclaimer"]
    for removed in ("security_controls", "compliance_status"):
        assert removed not in report
    for removed in ("threats_blocked", "block_rate"):
        assert removed not in report["metrics"]
    assert "PASS" not in set(_values(report))
    assert report["report_version"] == "2.0"


# ---------------------------------------------------------------- audit trail

def test_a_signed_trail_is_verified(db):
    _log(db.org.id, "1+1")
    _log(db.org.id, "2+2")

    trail = exporter.generate_soc2_report(db.org.id)["audit_trail"]

    assert trail["status"] == "VERIFIED"
    assert trail["total_entries"] == trail["verified_entries"] == 2
    assert trail["failed_entries"] == 0
    assert trail["errors"] == []
    assert "does not show that every request was recorded" in trail["scope"]


def test_a_tampered_entry_is_not_verified(db):
    _log(db.org.id, "1+1")
    log_id = int(_log(db.org.id, "2+2"))
    row = db.session.get(VerificationLog, log_id)
    row.result = '{"status": "FAILED"}'
    db.session.add(row)
    db.session.commit()

    trail = exporter.generate_soc2_report(db.org.id)["audit_trail"]

    assert trail["status"] == "NOT_VERIFIED"
    assert trail["failed_entries"] == 1
    assert trail["errors"]


def test_unsigned_legacy_entries_are_not_verified(db):
    db.session.add(VerificationLog(
        organization_id=db.org.id, query="old", result="{}", is_verified=True, domain="math",
    ))
    db.session.commit()

    trail = exporter.generate_soc2_report(db.org.id)["audit_trail"]

    assert trail["status"] == "NOT_VERIFIED"
    assert trail["legacy_entries"] == 1
    assert trail["verified_entries"] == 0


def test_an_empty_trail_is_not_reported_as_verified(db):
    trail = exporter.generate_soc2_report(db.org.id)["audit_trail"]

    assert trail["status"] == "NO_ENTRIES"
    assert trail["total_entries"] == 0


def test_the_check_fails_closed_without_the_audit_key(db, monkeypatch):
    _log(db.org.id)
    monkeypatch.delenv(AUDIT_SECRET_ENV_VAR)
    monkeypatch.setattr(audit_module, "_default_logger", None)

    trail = exporter.generate_soc2_report(db.org.id)["audit_trail"]

    assert trail["status"] == "NOT_VERIFIED"
    assert "could not be checked" in trail["errors"][0]


def test_another_organisations_entries_are_not_counted(db):
    other = Organization(name="globex", display_name="Globex")
    db.session.add(other)
    db.session.commit()
    db.session.refresh(other)
    _log(other.id)

    trail = exporter.generate_soc2_report(db.org.id)["audit_trail"]

    assert trail["status"] == "NO_ENTRIES"


# ---------------------------------------------------------------- events

def test_events_are_counted_by_the_types_actually_written(db):
    _event(db, "SECRET_LEAK_AUTO_REVOKED")
    _event(db, "SECRET_LEAK_AUTO_REVOKED")
    _event(db, "INJECTION_DETECTED")
    _event(db, "SECRET_LEAK_AUTO_REVOKED", days_ago=120)  # outside the 90-day period

    metrics = exporter.generate_soc2_report(db.org.id)["metrics"]

    assert metrics["security_events_detected"] == 3
    assert metrics["security_events_by_type"] == {"INJECTION_DETECTED": 1, "SECRET_LEAK_AUTO_REVOKED": 2}


# ---------------------------------------------------------------- route

def _get_report_as_admin(db):
    user = User(email="admin@test", password_hash="x", organization_id=db.org.id, role="admin")
    db.session.add(user)
    db.session.commit()
    db.session.refresh(user)
    raw, digest = generate_api_key()
    db.session.add(ApiKey(key_hash=digest, key_preview=raw[:8], organization_id=db.org.id, user_id=user.id))
    db.session.commit()

    main.app.dependency_overrides[main.get_session] = lambda: db.session
    try:
        return TestClient(main.app).get(
            f"/admin/compliance/report/soc2/{db.org.id}", headers={"x-api-key": raw}
        )
    finally:
        main.app.dependency_overrides.clear()


def test_the_route_returns_the_summary_at_the_same_url(db):
    _log(db.org.id)

    response = _get_report_as_admin(db)

    assert response.status_code == 200
    body = response.json()
    assert body["report_type"] == "Security activity summary"
    assert body["audit_trail"]["status"] == "VERIFIED"


def test_the_route_builds_the_report_off_the_event_loop(db, monkeypatch):
    # The audit check queries the database for every entry in the period, so
    # the route must not run it on the event loop (it would stall the worker).
    seen = []

    def report(org_id):
        try:
            asyncio.get_running_loop()
            seen.append("on the event loop")
        except RuntimeError:
            seen.append("in a worker thread")
        return {"org": org_id}

    monkeypatch.setattr(main.compliance_exporter, "generate_soc2_report", report)

    assert _get_report_as_admin(db).status_code == 200
    assert seen == ["in a worker thread"]
