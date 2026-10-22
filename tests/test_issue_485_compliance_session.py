"""#485: the compliance routes take a signed-in session, and check the whole chain.

The compliance routes authenticated with an ``x-api-key`` only, so a user
signed in to the dashboard had to paste an owner or admin key into the
browser. And the only check was one entry at a time
(``/admin/compliance/verify/{log_id}``); nothing exposed
``verify_audit_trail``.

Now the compliance routes also accept ``Authorization: Bearer <jwt>`` for an
active owner or admin of an active organisation (the same rules as the
user-session routes), and ``GET /admin/compliance/verify-trail`` checks every
entry of the caller's organisation in a period.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import create_access_token, generate_api_key
from qwed_new.core import audit_logger as audit_module
from qwed_new.core import compliance_exporter as exporter_module
from qwed_new.core.audit_logger import AUDIT_SECRET_ENV_VAR
from qwed_new.core.models import ApiKey, Organization, User, VerificationLog

ROLES = ("viewer", "member", "admin", "owner")


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'compliance485.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(audit_module, "engine", engine)
    monkeypatch.setattr(exporter_module, "engine", engine)
    monkeypatch.setenv(AUDIT_SECRET_ENV_VAR, "audit-fixture-value")
    monkeypatch.setattr(audit_module, "_default_logger", None)
    session = Session(engine)

    def org(name):
        o = Organization(name=name, display_name=name.title())
        session.add(o)
        session.commit()
        session.refresh(o)
        return o

    def user(o, role):
        u = User(email=f"{role}-{o.id}@test", password_hash="x", organization_id=o.id, role=role)
        session.add(u)
        session.commit()
        session.refresh(u)
        return u

    def key_for(u):
        raw, digest = generate_api_key()
        session.add(ApiKey(key_hash=digest, key_preview=raw[:8], organization_id=u.organization_id, user_id=u.id))
        session.commit()
        return raw

    acme, globex = org("acme"), org("globex")
    users = {role: user(acme, role) for role in ROLES}
    other_owner = user(globex, "owner")

    main.app.dependency_overrides[main.get_session] = lambda: session
    yield SimpleNamespace(
        session=session, acme=acme, globex=globex, users=users, other_owner=other_owner,
        key_for=key_for, client=TestClient(main.app),
    )
    main.app.dependency_overrides.clear()
    session.close()


def _bearer(u):
    return {"Authorization": f"Bearer {create_access_token({'sub': str(u.id)})}"}


def _log(org_id, query="2+2"):
    return int(audit_module.get_audit_logger().log_verification(
        organization_id=org_id, user_id=None, query=query,
        result={"status": "VERIFIED"}, is_verified=True, domain="math",
    ))


# ---------------------------------------------------------------- session auth

@pytest.mark.parametrize("who", ["owner", "admin"])
def test_a_signed_in_owner_or_admin_can_run_the_compliance_routes(env, who):
    log_id = _log(env.acme.id)
    headers = _bearer(env.users[who])

    assert env.client.get(f"/admin/compliance/verify/{log_id}", headers=headers).json()["valid"] is True
    assert env.client.get("/admin/compliance/verify-trail", headers=headers).json()["status"] == "VERIFIED"
    assert env.client.get(
        f"/admin/compliance/export/csv?organization_id={env.acme.id}", headers=headers
    ).status_code == 200
    assert env.client.get(
        f"/admin/compliance/report/soc2/{env.acme.id}", headers=headers
    ).json()["audit_trail"]["status"] == "VERIFIED"


@pytest.mark.parametrize("who", ["viewer", "member"])
def test_a_signed_in_member_or_viewer_is_refused(env, who):
    log_id = _log(env.acme.id)
    headers = _bearer(env.users[who])

    assert env.client.get(f"/admin/compliance/verify/{log_id}", headers=headers).status_code == 403
    assert env.client.get("/admin/compliance/verify-trail", headers=headers).status_code == 403


def test_an_inactive_user_or_organisation_is_refused(env):
    owner = env.users["owner"]
    owner.is_active = False
    env.session.add(owner)
    env.session.commit()
    assert env.client.get("/admin/compliance/verify-trail", headers=_bearer(owner)).status_code == 403

    owner.is_active = True
    env.acme.is_active = False
    env.session.add(owner)
    env.session.add(env.acme)
    env.session.commit()
    assert env.client.get("/admin/compliance/verify-trail", headers=_bearer(owner)).status_code == 403


@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer not-a-jwt"},
    {"Authorization": "Basic abc"},
])
def test_no_or_a_bad_credential_is_401(env, headers):
    assert env.client.get("/admin/compliance/verify-trail", headers=headers).status_code == 401


def test_a_token_for_a_user_that_no_longer_exists_is_401(env):
    headers = {"Authorization": f"Bearer {create_access_token({'sub': '999999'})}"}

    assert env.client.get("/admin/compliance/verify-trail", headers=headers).status_code == 401


def test_a_session_reads_only_its_own_organisation(env):
    other_log = _log(env.globex.id)
    headers = _bearer(env.users["owner"])

    assert env.client.get(f"/admin/compliance/verify/{other_log}", headers=headers).status_code == 404
    assert env.client.get(
        f"/admin/compliance/report/soc2/{env.globex.id}", headers=headers
    ).status_code == 403
    assert env.client.get("/admin/compliance/verify-trail", headers=headers).json()["status"] == "NO_ENTRIES"


def test_an_api_key_still_works_and_wins_over_a_session(env):
    _log(env.acme.id)
    owner_key = env.key_for(env.users["owner"])
    viewer_key = env.key_for(env.users["viewer"])

    assert env.client.get(
        "/admin/compliance/verify-trail", headers={"x-api-key": owner_key}
    ).json()["status"] == "VERIFIED"
    # Both sent: the key is used, so a viewer's key is refused despite an owner's session.
    both = {"x-api-key": viewer_key, **_bearer(env.users["owner"])}
    assert env.client.get("/admin/compliance/verify-trail", headers=both).status_code == 403


def test_other_admin_routes_still_need_an_api_key(env):
    response = env.client.get(f"/admin/security/threats/{env.acme.id}", headers=_bearer(env.users["owner"]))

    assert response.status_code == 401


# ---------------------------------------------------------------- whole chain

def _trail(env, query=""):
    return env.client.get(f"/admin/compliance/verify-trail{query}", headers=_bearer(env.users["owner"])).json()


def test_an_intact_chain_is_verified_with_a_proof_ref(env):
    ids = [_log(env.acme.id, f"{i}+{i}") for i in range(3)]

    trail = _trail(env)

    assert trail["organization_id"] == env.acme.id
    assert trail["status"] == "VERIFIED"
    assert trail["total_entries"] == trail["verified_entries"] == 3
    assert trail["first_failed_entry_id"] is None
    assert trail["evidence"]["first_entry_id"] == ids[0]
    assert trail["evidence"]["last_entry_id"] == ids[-1]
    assert trail["proof_ref"].startswith("sha256:")
    assert trail["start"] is None
    assert trail["end"] is None


def test_a_broken_chain_names_the_first_failing_entry(env):
    ids = [_log(env.acme.id, f"{i}+{i}") for i in range(4)]
    for tampered in (ids[1], ids[3]):
        row = env.session.get(VerificationLog, tampered)
        row.result = '{"status": "FAILED"}'
        env.session.add(row)
    env.session.commit()

    trail = _trail(env)

    assert trail["status"] == "NOT_VERIFIED"
    assert trail["first_failed_entry_id"] == ids[1]
    assert trail["total_entries"] == 4
    assert trail["proof_ref"] is None


def test_the_period_bounds_the_entries_checked(env):
    _log(env.acme.id)
    now = datetime.now(timezone.utc)

    inside = _trail(env, f"?start={(now - timedelta(hours=1)).isoformat()}".replace("+", "%2B"))
    later = _trail(env, f"?start={(now + timedelta(hours=1)).isoformat()}".replace("+", "%2B"))
    # A time without a zone is read as UTC.
    naive = _trail(env, f"?end={(now - timedelta(hours=1)).replace(tzinfo=None).isoformat()}")

    assert inside["status"] == "VERIFIED"
    assert inside["total_entries"] == 1
    assert later["status"] == "NO_ENTRIES"
    assert naive["status"] == "NO_ENTRIES"
    assert naive["end"].endswith("+00:00")


def test_a_time_with_another_offset_is_converted_to_utc(env):
    _log(env.acme.id)
    india = timezone(timedelta(hours=5, minutes=30))
    # Two hours ago in UTC, written in +05:30: the entry (now) is after it.
    start = (datetime.now(timezone.utc) - timedelta(hours=2)).astimezone(india)
    # Three hours from now in +05:30 would read as earlier than now if the
    # offset were dropped; converted, it is after the entry.
    end = (datetime.now(timezone.utc) + timedelta(hours=3)).astimezone(india)

    trail = _trail(env, f"?start={start.isoformat()}&end={end.isoformat()}".replace("+", "%2B"))

    assert trail["status"] == "VERIFIED"
    assert trail["total_entries"] == 1
    assert trail["start"] == start.astimezone(timezone.utc).isoformat()
    assert trail["end"] == end.astimezone(timezone.utc).isoformat()


def test_a_token_whose_subject_is_not_a_user_id_is_401(env):
    headers = {"Authorization": f"Bearer {create_access_token({'sub': 'not-a-number'})}"}

    assert env.client.get("/admin/compliance/verify-trail", headers=headers).status_code == 401


# ---------------------------------------------------------------- one ordered pass

def _count_statements(engine, run):
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        run()
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    return len(statements)


def test_the_trail_check_does_not_query_per_entry(env):
    check = audit_module.get_audit_logger().verify_audit_trail
    _log(env.acme.id, "0+0")
    few = _count_statements(audit_module.engine, lambda: check(env.acme.id))
    for i in range(1, 30):
        _log(env.acme.id, f"{i}+{i}")

    many = _count_statements(audit_module.engine, lambda: check(env.acme.id))

    assert many == few


def test_the_one_pass_check_agrees_with_checking_each_entry(env):
    """Legacy rows, another organisation's rows in between, tampered rows and a
    row whose clock went back: the trail result matches verify_log_entry."""
    logger = audit_module.get_audit_logger()
    legacy = VerificationLog(organization_id=env.acme.id, query="old", result="{}", is_verified=True, domain="math")
    env.session.add(legacy)
    env.session.commit()
    env.session.refresh(legacy)
    ids = []
    for i in range(6):
        ids.append(_log(env.acme.id, f"{i}+{i}"))
        _log(env.globex.id, f"other {i}")
    tampered = env.session.get(VerificationLog, ids[2])
    tampered.result = '{"status": "FAILED"}'
    skewed = env.session.get(VerificationLog, ids[4])
    skewed.timestamp = skewed.timestamp - timedelta(days=365)
    env.session.add(tampered)
    env.session.add(skewed)
    env.session.commit()
    start = datetime.now(timezone.utc) - timedelta(days=1)

    trail = logger.verify_audit_trail(env.acme.id, start_date=start)

    with Session(audit_module.engine) as session:
        expected = {i: logger.verify_log_entry(i, session) for i in [legacy.id, *ids] if i != ids[4]}
    assert trail["total_entries"] == len(expected)
    assert trail["verified_entries"] == sum(r["valid"] for r in expected.values())
    assert trail["failed_entries"] == [i for i, r in expected.items() if not r["valid"] and not r.get("legacy")]
    assert trail["legacy_entries"] == [legacy.id]
    assert trail["failed_entries"] == [ids[2]]
    assert ids[4] not in trail["failed_entries"]
    assert trail["first_entry_id"] == legacy.id
    assert trail["last_entry_id"] == ids[-1]


def test_start_after_end_is_400(env):
    response = env.client.get(
        "/admin/compliance/verify-trail?start=2026-10-02T00:00:00&end=2026-10-01T00:00:00",
        headers=_bearer(env.users["owner"]),
    )

    assert response.status_code == 400
