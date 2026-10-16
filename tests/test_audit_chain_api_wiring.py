"""The API appends verification rows to the signed audit chain.

Before this wiring, every /verify/* endpoint wrote VerificationLog rows straight
through the request session, so entry_hash, hmac_signature and previous_hash
stayed empty. /admin/compliance/verify/{log_id} and verify_audit_trail could
never verify an API-written row, and the CSV export marked them 'Legacy'.

The ``isolated_audit_chain`` fixture (tests/conftest.py) gives each test its
own chain database and a fresh process-wide AuditLogger.
"""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api import main as api_main
from qwed_new.api import verification_context_routes
from qwed_new.auth import audit_routes
from qwed_new.core import audit_logger as audit_module
from qwed_new.core.audit_logger import (
    AUDIT_SECRET_ENV_VAR,
    AuditLogger,
    SecurityError,
    get_audit_logger,
)
from qwed_new.core.models import VerificationLog
from qwed_new.core.tenant_context import TenantContext

ORG_ID = 1


@pytest.fixture
def client():
    tenant = TenantContext(
        organization_id=ORG_ID, organization_name="Org", tier="free", api_key="k"
    )
    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = lambda: MagicMock()
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _rows(engine):
    with Session(engine) as session:
        return session.exec(select(VerificationLog).order_by(VerificationLog.id)).all()


def _verify(engine, log_id):
    with Session(engine) as session:
        return AuditLogger().verify_log_entry(log_id, session)


def _insert_unchained(engine, **overrides):
    """Write a row the way the API did before the wiring: no chain fields."""
    fields = dict(
        organization_id=ORG_ID, query="old", result="{}", is_verified=False, domain="MATH"
    )
    fields.update(overrides)
    with Session(engine) as session:
        row = VerificationLog(**fields)
        session.add(row)
        session.commit()
        return row.id


def test_verify_endpoint_writes_a_verifiable_chained_row(client, isolated_audit_chain):
    first = client.post("/verify/math", json={"expression": "2+2=4"})
    second = client.post("/verify/math", json={"expression": "3+3=6"})
    assert first.status_code == 200 and second.status_code == 200

    rows = _rows(isolated_audit_chain)
    assert len(rows) == 2
    for row in rows:
        assert row.entry_hash and row.hmac_signature
    assert rows[0].previous_hash is None
    assert rows[1].previous_hash == rows[0].entry_hash

    for row in rows:
        check = _verify(isolated_audit_chain, row.id)
        assert check["valid"] is True, check
        assert check["legacy"] is False

    trail = AuditLogger().verify_audit_trail(organization_id=ORG_ID)
    assert trail["valid"] is True
    assert trail["verified_entries"] == 2
    assert trail["legacy_entries"] == []


def test_edited_api_row_is_detected(client, isolated_audit_chain):
    assert client.post("/verify/math", json={"expression": "2+2=4"}).status_code == 200
    row_id = _rows(isolated_audit_chain)[0].id
    with Session(isolated_audit_chain) as session:
        row = session.get(VerificationLog, row_id)
        row.is_verified = not row.is_verified
        session.add(row)
        session.commit()

    check = _verify(isolated_audit_chain, row_id)
    assert check["valid"] is False
    assert check["checks"]["hash_valid"] is False


def test_missing_signing_key_fails_the_request_closed(client, isolated_audit_chain, monkeypatch):
    monkeypatch.delenv(AUDIT_SECRET_ENV_VAR, raising=False)

    response = client.post("/verify/math", json={"expression": "2+2=4"})

    assert response.status_code == 500
    assert response.json()["detail"] == "audit persistence failed"
    assert _rows(isolated_audit_chain) == []


def test_missing_signing_key_stops_startup(monkeypatch):
    monkeypatch.delenv(AUDIT_SECRET_ENV_VAR, raising=False)
    monkeypatch.setattr(api_main, "_enforce_environment_integrity", lambda: None)
    monkeypatch.setattr(api_main, "create_db_and_tables", lambda: None)

    with pytest.raises(SecurityError, match=AUDIT_SECRET_ENV_VAR):
        with TestClient(api_main.app):
            pass


def test_unverifiable_head_fails_the_request_closed(client, isolated_audit_chain):
    assert client.post("/verify/math", json={"expression": "2+2=4"}).status_code == 200
    # An unchained row after a chained one was not written by a pre-chain
    # server: it was added out of band, so appends stop.
    _insert_unchained(isolated_audit_chain)

    response = client.post("/verify/math", json={"expression": "3+3=6"})

    assert response.status_code == 500
    assert len(_rows(isolated_audit_chain)) == 2


def test_legacy_rows_stay_unverified_and_new_rows_start_a_segment(client, isolated_audit_chain):
    legacy_id = _insert_unchained(isolated_audit_chain, result="not json")

    assert client.post("/verify/math", json={"expression": "2+2=4"}).status_code == 200
    assert client.post("/verify/math", json={"expression": "3+3=6"}).status_code == 200

    legacy, first, second = _rows(isolated_audit_chain)
    assert legacy.id == legacy_id
    assert first.previous_hash is None
    assert second.previous_hash == first.entry_hash

    legacy_check = _verify(isolated_audit_chain, legacy_id)
    assert legacy_check["valid"] is False
    assert legacy_check["legacy"] is True
    assert _verify(isolated_audit_chain, first.id)["valid"] is True
    assert _verify(isolated_audit_chain, second.id)["valid"] is True

    trail = AuditLogger().verify_audit_trail(organization_id=ORG_ID)
    assert trail["valid"] is False
    assert trail["legacy_entries"] == [legacy_id]
    assert trail["failed_entries"] == []
    assert trail["verified_entries"] == 2


def test_segment_start_after_a_chained_row_is_rejected(isolated_audit_chain):
    """A chained row with no previous_hash is only valid before any other chained row."""
    logger = get_audit_logger()
    logger.log_verification(ORG_ID, None, "a", {"v": 1}, True, "MATH")
    # A second logger with no in-memory head, reading a forged head: a second
    # "genesis" is still refused at verification time.
    with Session(isolated_audit_chain) as session:
        forged = VerificationLog(
            organization_id=ORG_ID, query="b", result='{"v": 2}', is_verified=True,
            domain="MATH", previous_hash=None,
        )
        session.add(forged)
        session.commit()
        payload = logger._reconstruct_log_data(forged)
        forged.entry_hash = logger._compute_hash(payload)
        forged.hmac_signature = logger._compute_hmac(forged.entry_hash)
        session.add(forged)
        session.commit()
        forged_id = forged.id

    check = _verify(isolated_audit_chain, forged_id)
    assert check["valid"] is False
    assert check["checks"]["chain_valid"] is False


def test_string_result_is_stored_verbatim_and_must_be_json(isolated_audit_chain):
    logger = get_audit_logger()
    serialised = '{"b": 1, "a": "café"}'
    log_id = int(logger.log_verification(ORG_ID, None, "q", serialised, True, "MATH"))

    assert _rows(isolated_audit_chain)[0].result == serialised
    assert _verify(isolated_audit_chain, log_id)["valid"] is True

    with pytest.raises(SecurityError, match="not valid JSON"):
        logger.log_verification(ORG_ID, None, "q", "Consensus: blocked", False, "CONSENSUS")


def test_concurrent_appends_in_one_process_keep_the_chain(isolated_audit_chain):
    logger = get_audit_logger()
    errors = []

    def append(worker):
        for i in range(10):
            try:
                logger.log_verification(ORG_ID, None, f"{worker}-{i}", {"i": i}, True, "MATH")
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

    threads = [threading.Thread(target=append, args=(w,)) for w in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    trail = AuditLogger().verify_audit_trail(organization_id=ORG_ID)
    assert trail["valid"] is True
    assert trail["verified_entries"] == 40


def test_second_writer_is_refused_rather_than_forking(isolated_audit_chain):
    """Single writer: another process appending makes this one stop, not fork."""
    ours = get_audit_logger()
    ours.log_verification(ORG_ID, None, "a", {"v": 1}, True, "MATH")
    AuditLogger().log_verification(ORG_ID, None, "b", {"v": 2}, True, "MATH")

    with pytest.raises(SecurityError, match="continuity mismatch"):
        ours.log_verification(ORG_ID, None, "c", {"v": 3}, True, "MATH")
    assert AuditLogger().verify_audit_trail(organization_id=ORG_ID)["valid"] is True


def test_verification_context_log_is_chained(isolated_audit_chain):
    tenant = TenantContext(organization_id=ORG_ID, organization_name="Org", tier="free")
    verification_context_routes._safe_commit_context_log(
        object(), tenant, "query", {"status": "VERIFIED"}, True
    )

    (row,) = _rows(isolated_audit_chain)
    assert row.domain == "VERIFICATION_CONTEXT"
    assert _verify(isolated_audit_chain, row.id)["valid"] is True


def test_verification_context_log_fails_closed_without_key(isolated_audit_chain, monkeypatch):
    monkeypatch.delenv(AUDIT_SECRET_ENV_VAR, raising=False)
    tenant = TenantContext(organization_id=ORG_ID, organization_name="Org", tier="free")

    with pytest.raises(HTTPException) as excinfo:
        verification_context_routes._safe_commit_context_log(
            object(), tenant, "query", {"status": "VERIFIED"}, True
        )
    assert excinfo.value.status_code == 500
    assert _rows(isolated_audit_chain) == []


def test_seeded_sample_rows_are_chained(isolated_audit_chain):
    user = SimpleNamespace(organization_id=ORG_ID, id=None)

    asyncio.run(audit_routes.seed_sample_data(current_user=user, session=None))

    rows = _rows(isolated_audit_chain)
    assert len(rows) == 10
    assert all(row.result == '{"sample": true}' for row in rows)
    trail = AuditLogger().verify_audit_trail(organization_id=ORG_ID)
    assert trail["valid"] is True
    assert trail["verified_entries"] == 10


def test_process_wide_logger_is_reused():
    assert get_audit_logger() is get_audit_logger()
    assert audit_module._default_logger is get_audit_logger()
