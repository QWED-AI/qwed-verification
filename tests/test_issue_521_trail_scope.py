"""#521: the whole-chain check does not describe itself as a check "in the period".

``GET /admin/compliance/verify-trail`` with no ``start`` or ``end`` checks
every entry of the organisation, but its ``scope`` said "audit entries
recorded in the period". The scope now names the whole trail when neither
bound is given, and the period otherwise.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.core import audit_logger as audit_module
from qwed_new.core import compliance_exporter as exporter_module
from qwed_new.core.audit_logger import AUDIT_SECRET_ENV_VAR
from qwed_new.core.compliance_exporter import ComplianceExporter
from qwed_new.core.models import Organization, User
from tests.test_issue_485_compliance_session import _bearer, _log

WHOLE = "every audit entry recorded for the organisation"
PERIOD = "recorded in the period"
CAVEAT = "It does not show that every request was recorded."


@pytest.fixture
def env(tmp_path, monkeypatch):
    """One organisation with a signed-in owner, on its own database."""
    engine = create_engine(f"sqlite:///{tmp_path / 'trail521.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(audit_module, "engine", engine)
    monkeypatch.setattr(exporter_module, "engine", engine)
    monkeypatch.setenv(AUDIT_SECRET_ENV_VAR, "audit-fixture-value")
    monkeypatch.setattr(audit_module, "_default_logger", None)
    session = Session(engine)
    org = Organization(name="acme", display_name="Acme")
    session.add(org)
    session.commit()
    owner = User(email="owner@test", password_hash="x", organization_id=org.id, role="owner")
    session.add(owner)
    session.commit()
    session.refresh(org)
    session.refresh(owner)

    main.app.dependency_overrides[main.get_session] = lambda: session
    yield SimpleNamespace(org=org, owner=owner, client=TestClient(main.app))
    main.app.dependency_overrides.clear()
    session.close()


def _trail(env, query=""):
    return env.client.get(
        f"/admin/compliance/verify-trail{query}", headers=_bearer(env.owner)
    ).json()


def _at(when):
    return when.isoformat().replace("+", "%2B")


def test_the_whole_chain_check_names_the_whole_trail(env):
    _log(env.org.id)

    trail = _trail(env)

    assert trail["status"] == "VERIFIED"
    assert WHOLE in trail["scope"]
    assert PERIOD not in trail["scope"]
    assert trail["scope"].endswith(CAVEAT)


def test_an_empty_trail_with_no_period_names_the_whole_trail(env):
    trail = _trail(env)

    assert trail["status"] == "NO_ENTRIES"
    assert WHOLE in trail["scope"]


@pytest.mark.parametrize("bounds", ["start", "end", "both"])
def test_a_check_with_a_period_names_the_period(env, bounds):
    _log(env.org.id)
    now = datetime.now(timezone.utc)
    query = {
        "start": f"?start={_at(now - timedelta(hours=1))}",
        "end": f"?end={_at(now + timedelta(hours=1))}",
        "both": f"?start={_at(now - timedelta(hours=1))}&end={_at(now + timedelta(hours=1))}",
    }[bounds]

    trail = _trail(env, query)

    assert trail["status"] == "VERIFIED"
    assert PERIOD in trail["scope"]
    assert WHOLE not in trail["scope"]
    assert trail["scope"].endswith(CAVEAT)


def test_a_check_that_cannot_run_keeps_the_right_scope(monkeypatch):
    def _broken():
        raise RuntimeError("no audit key")

    monkeypatch.setattr(exporter_module, "get_audit_logger", _broken)
    now = datetime.now(timezone.utc)

    whole = ComplianceExporter.audit_trail_check(1)
    period = ComplianceExporter.audit_trail_check(1, now - timedelta(days=1), now)

    assert whole["status"] == period["status"] == "NOT_VERIFIED"
    assert WHOLE in whole["scope"]
    assert PERIOD in period["scope"]
