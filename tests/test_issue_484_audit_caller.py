"""#484: each audit row records the API key that made it and the server version.

VerificationLog had no API key id and no verifier version, so a row could not
say who wrote it or with what release. Rows now carry ``api_key_id`` (from
``get_current_tenant``, through ``core/request_caller.py``) and
``verifier_version`` (``qwed_new.__version__``). Both are covered by the entry
hash. ``core/schema_migrations.py`` adds the columns to an existing table at
startup. The audit routes return both fields.

The ``isolated_audit_chain`` fixture (tests/conftest.py) gives each test its
own chain database and a fresh AuditLogger.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text, update
from sqlmodel import Session, SQLModel, select

from qwed_new import __version__
from qwed_new.api import main
from qwed_new.auth.security import create_access_token, generate_api_key
from qwed_new.core import audit_logger as audit_module
from qwed_new.core.audit_logger import AuditLogger, get_audit_logger
from qwed_new.core.models import ApiKey, Organization, User, VerificationLog
from qwed_new.core.request_caller import request_api_key_id
from qwed_new.core.schema_migrations import add_missing_columns

# ---------------------------------------------------------------- migration

def _old_database(path):
    """A verificationlog table as releases before #484 created it."""
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE verificationlog (id INTEGER PRIMARY KEY, organization_id INTEGER, "
            "user_id INTEGER, query VARCHAR, result VARCHAR, is_verified BOOLEAN, domain VARCHAR, "
            "timestamp DATETIME, entry_hash VARCHAR, hmac_signature VARCHAR, previous_hash VARCHAR, "
            "raw_llm_output VARCHAR)"
        ))
        connection.execute(text(
            "INSERT INTO verificationlog (organization_id, query, result, is_verified, domain) "
            "VALUES (1, 'old', '{}', 1, 'MATH')"
        ))
    return engine


def test_the_migration_adds_both_columns_to_an_existing_table(tmp_path):
    engine = _old_database(tmp_path / "old.db")

    added = add_missing_columns(engine)

    assert added == ["verificationlog.api_key_id", "verificationlog.verifier_version"]
    columns = {c["name"] for c in inspect(engine).get_columns("verificationlog")}
    assert {"api_key_id", "verifier_version"} <= columns
    with engine.connect() as connection:
        row = connection.execute(text("SELECT api_key_id, verifier_version, query FROM verificationlog")).one()
    assert tuple(row) == (None, None, "old")  # existing rows read as not recorded


def test_the_migration_is_a_no_op_the_second_time(tmp_path):
    engine = _old_database(tmp_path / "old.db")
    add_missing_columns(engine)

    assert add_missing_columns(engine) == []


def test_the_migration_leaves_a_missing_table_to_create_all(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")

    assert add_missing_columns(engine) == []
    assert "verificationlog" not in inspect(engine).get_table_names()


def test_a_new_database_already_has_both_columns(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'new.db'}")
    SQLModel.metadata.create_all(engine)

    assert add_missing_columns(engine) == []


# ---------------------------------------------------------------- writing rows

@pytest.fixture
def env(isolated_audit_chain):
    """Every table on the chain database, one organisation, a key, a viewer."""
    engine = isolated_audit_chain
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    org = add(Organization(name="acme", display_name="Acme"))
    owner = add(User(email="owner@test", password_hash="x", organization_id=org.id, role="owner"))
    raw, digest = generate_api_key()
    key = add(ApiKey(key_hash=digest, key_preview=f"{raw[:8]}...", organization_id=org.id,
                     user_id=owner.id, name="ci"))

    main.app.dependency_overrides[main.get_session] = lambda: session
    client = TestClient(main.app)
    token = create_access_token({"sub": str(owner.id)})

    def verify(expression):
        with patch("qwed_new.api.main.check_rate_limit"):
            response = client.post("/verify/math", json={"expression": expression}, headers={"x-api-key": raw})
        assert response.status_code == 200, response.text

    def get(path):
        response = client.get(path, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200, response.text
        return response.json()

    def rows():
        session.expire_all()
        return session.exec(select(VerificationLog).order_by(VerificationLog.id)).all()

    def check(log_id):
        session.expire_all()
        return AuditLogger().verify_log_entry(log_id, session)

    def tamper(log_id, **values):
        """Change a stored row behind the logger's back, as a database writer could."""
        with engine.begin() as connection:
            connection.execute(update(VerificationLog).where(VerificationLog.id == log_id).values(**values))

    yield SimpleNamespace(org=org, key=key, verify=verify, get=get, rows=rows, check=check, tamper=tamper)
    main.app.dependency_overrides.clear()
    session.close()


def test_a_request_with_an_api_key_records_the_key_and_the_version(env):
    env.verify("2+2=4")

    [row] = env.rows()
    assert row.api_key_id == env.key.id
    assert row.verifier_version == __version__
    assert env.check(row.id)["valid"] is True


def test_a_row_written_without_an_api_key_records_none(env):
    # A user session or the audit seed writes through the logger without
    # get_current_tenant, so no key is recorded; the version still is.
    log_id = int(get_audit_logger().log_verification(
        organization_id=env.org.id, user_id=None, query="seed", result={"sample": True},
        is_verified=True, domain="MATH",
    ))

    row = next(r for r in env.rows() if r.id == log_id)
    assert row.api_key_id is None
    assert row.verifier_version == __version__
    assert env.check(log_id)["valid"] is True


def test_one_requests_key_does_not_reach_a_later_write(env):
    env.verify("2+2=4")
    assert request_api_key_id() is None  # the request's context stayed its own

    log_id = int(get_audit_logger().log_verification(
        organization_id=env.org.id, user_id=None, query="later", result={}, is_verified=True, domain="MATH",
    ))
    assert next(r for r in env.rows() if r.id == log_id).api_key_id is None


@pytest.mark.parametrize("values", [
    {"api_key_id": 999},
    {"verifier_version": "0.0.1"},
    {"api_key_id": None, "verifier_version": None},
])
def test_changing_or_clearing_the_caller_breaks_the_hash(env, values):
    env.verify("2+2=4")
    [row] = env.rows()

    env.tamper(row.id, **values)

    result = env.check(row.id)
    assert result["valid"] is False
    assert result["checks"]["hash_valid"] is False


def _pre_caller_row(env):
    """A row hashed as releases before #484 hashed it: no caller fields."""
    logger = get_audit_logger()
    row = VerificationLog(organization_id=env.org.id, query="before", result="{}", is_verified=True,
                          domain="MATH", timestamp=datetime.now(timezone.utc))
    row.entry_hash = logger._compute_hash(logger._reconstruct_pre_caller_log_data(row))
    row.hmac_signature = logger._compute_hmac(row.entry_hash)
    with Session(audit_module.engine) as session:
        session.add(row)
        session.commit()
        return row.id


def test_a_row_written_before_484_still_verifies(env):
    log_id = _pre_caller_row(env)

    assert env.check(log_id)["valid"] is True


def test_setting_a_caller_on_a_row_written_before_484_breaks_the_hash(env):
    # The older payload shapes are only accepted while both fields are null,
    # so a caller cannot be added to an old row without the key.
    log_id = _pre_caller_row(env)

    env.tamper(log_id, api_key_id=env.key.id)

    assert env.check(log_id)["checks"]["hash_valid"] is False


# ---------------------------------------------------------------- the routes

def test_both_routes_return_the_caller(env):
    env.verify("2+2=4")
    [row] = env.rows()

    listed = env.get("/audit/logs")["logs"][0]
    detail = env.get(f"/audit/logs/{row.id}")

    for body in (listed, detail):
        assert body["api_key_id"] == str(env.key.id)
        assert body["verifier_version"] == __version__


def test_a_row_written_before_484_reads_as_not_recorded(env):
    log_id = _pre_caller_row(env)

    detail = env.get(f"/audit/logs/{log_id}")

    assert detail["api_key_id"] is None
    assert detail["verifier_version"] is None
