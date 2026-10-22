"""#486: a read endpoint for security events, and when a key was last used.

``SecurityEvent`` rows could only be read as a summary
(``/admin/security/threats/{org_id}``), and ``ApiKey.last_used_at`` was never
set: both places that would set it were commented out.

Now ``GET /admin/security/events`` lists the organisation's events for owners
and admins (API key or signed-in session), newest first with a ``before``
cursor, with anything shaped like a credential masked. And an API key's
``last_used_at`` is set when it authenticates, at most once a minute.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import create_access_token, generate_api_key
from qwed_new.core import api_key_usage
from qwed_new.core.models import ApiKey, Organization, SecurityEvent, User
from qwed_new.core.tenant_context import get_current_tenant

ROLES = ("viewer", "member", "admin", "owner")


@pytest.fixture
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'events486.db'}")
    SQLModel.metadata.create_all(engine)
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
        k = ApiKey(key_hash=digest, key_preview=raw[:8], organization_id=u.organization_id, user_id=u.id)
        session.add(k)
        session.commit()
        session.refresh(k)
        return raw, k

    acme, globex = org("acme"), org("globex")
    users = {role: user(acme, role) for role in ROLES}
    other_owner = user(globex, "owner")

    main.app.dependency_overrides[main.get_session] = lambda: session
    yield SimpleNamespace(
        engine=engine, session=session, acme=acme, globex=globex, users=users,
        other_owner=other_owner, key_for=key_for, client=TestClient(main.app),
    )
    main.app.dependency_overrides.clear()
    session.close()


def _bearer(u):
    return {"Authorization": f"Bearer {create_access_token({'sub': str(u.id)})}"}


def _event(env, org, event_type="SECRET_LEAK_AUTO_REVOKED", *, minutes_ago=0, reason="leak", query="leaked key qwed_liv"):
    e = SecurityEvent(
        organization_id=org.id, event_type=event_type, query=query, reason=reason, severity="high",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    )
    env.session.add(e)
    env.session.commit()
    env.session.refresh(e)
    return e


def _events(env, query="", headers=None):
    return env.client.get(f"/admin/security/events{query}", headers=headers or _bearer(env.users["owner"]))


# ---------------------------------------------------------------- events

@pytest.mark.parametrize("who", ["owner", "admin"])
def test_owners_and_admins_list_their_events_newest_first(env, who):
    old = _event(env, env.acme, minutes_ago=10)
    new = _event(env, env.acme, minutes_ago=1)
    _event(env, env.globex)

    body = _events(env, headers=_bearer(env.users[who])).json()

    assert [e["id"] for e in body["events"]] == [str(new.id), str(old.id)]
    assert body["events"][0]["event_type"] == "SECRET_LEAK_AUTO_REVOKED"
    assert body["events"][0]["severity"] == "high"
    assert body["next_before"] is None


def test_an_owner_api_key_works_too(env):
    _event(env, env.acme)
    raw, _ = env.key_for(env.users["owner"])

    assert _events(env, headers={"x-api-key": raw}).json()["total"] == 1


@pytest.mark.parametrize("who", ["viewer", "member"])
def test_members_and_viewers_are_refused(env, who):
    assert _events(env, headers=_bearer(env.users[who])).status_code == 403


def test_no_credential_is_401(env):
    assert env.client.get("/admin/security/events").status_code == 401


def test_pages_with_a_before_cursor(env):
    made = [_event(env, env.acme, minutes_ago=m) for m in (5, 4, 3, 2, 1)]
    newest_first = [str(e.id) for e in reversed(made)]

    first = _events(env, "?limit=2").json()
    second = _events(env, f"?limit=2&before={first['next_before']}").json()
    third = _events(env, f"?limit=2&before={second['next_before']}").json()

    assert [e["id"] for e in first["events"]] == newest_first[:2]
    assert [e["id"] for e in second["events"]] == newest_first[2:4]
    assert [e["id"] for e in third["events"]] == newest_first[4:]
    assert third["next_before"] is None


def test_a_cursor_from_another_organisation_or_unknown_is_404(env):
    other = _event(env, env.globex)

    assert _events(env, f"?before={other.id}").status_code == 404
    assert _events(env, "?before=999999").status_code == 404


def test_filters_by_event_type(env):
    _event(env, env.acme, "SECRET_LEAK_AUTO_REVOKED")
    wanted = _event(env, env.acme, "INJECTION_DETECTED")

    body = _events(env, "?event_type=INJECTION_DETECTED").json()

    assert [e["id"] for e in body["events"]] == [str(wanted.id)]


@pytest.mark.parametrize("limit", [0, 201])
def test_the_limit_is_bounded(env, limit):
    assert _events(env, f"?limit={limit}").status_code == 422


def test_a_credential_in_an_event_is_masked(env):
    raw, _ = env.key_for(env.users["member"])
    token = "agent_" + "ab" * 32
    _event(env, env.acme, reason=f"found {raw} in a gist", query=f"agent token {token}")

    (shown,) = _events(env).json()["events"]

    assert raw not in shown["reason"]
    assert token not in shown["query"]
    assert "[redacted credential]" in shown["reason"]
    assert "[redacted credential]" in shown["query"]


# ---------------------------------------------------------------- last_used_at

def _stored_last_used(env, key):
    env.session.expire_all()
    return env.session.get(ApiKey, key.id).last_used_at


def test_an_admin_request_records_when_the_key_was_used(env):
    raw, key = env.key_for(env.users["owner"])
    assert key.last_used_at is None

    _events(env, headers={"x-api-key": raw})

    assert _stored_last_used(env, key) is not None


def test_a_verify_request_records_when_the_key_was_used(env):
    raw, key = env.key_for(env.users["member"])

    tenant = asyncio.run(get_current_tenant(x_api_key=raw, session=env.session))

    assert tenant.api_key_id == key.id
    assert _stored_last_used(env, key) is not None


def _updates(engine, run):
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE APIKEY"):
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        run()
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    return len(statements)


def test_a_busy_key_is_written_at_most_once_a_minute(env):
    raw, _ = env.key_for(env.users["owner"])

    writes = _updates(env.engine, lambda: [_events(env, headers={"x-api-key": raw}) for _ in range(5)])

    assert writes == 1


def test_a_stale_value_is_written_again(env):
    raw, key = env.key_for(env.users["owner"])
    stale = datetime.now(timezone.utc) - timedelta(minutes=2)
    key.last_used_at = stale
    env.session.add(key)
    env.session.commit()

    _events(env, headers={"x-api-key": raw})

    assert api_key_usage._as_utc(_stored_last_used(env, key)) > stale + timedelta(minutes=1)


def test_a_refused_key_is_not_recorded(env):
    raw, key = env.key_for(env.users["owner"])
    key.is_active = False
    env.session.add(key)
    env.session.commit()

    assert _events(env, headers={"x-api-key": raw}).status_code == 403
    assert _stored_last_used(env, key) is None


def test_another_worker_that_wrote_first_wins(env):
    _, key = env.key_for(env.users["owner"])
    stale_copy = SimpleNamespace(id=key.id, last_used_at=None)
    fresh = datetime.now(timezone.utc)
    key.last_used_at = fresh
    env.session.add(key)
    env.session.commit()

    wrote = api_key_usage.record_api_key_use(env.session, stale_copy, now=fresh + timedelta(seconds=5))

    assert wrote is False
    assert api_key_usage._as_utc(_stored_last_used(env, key)) == fresh


def test_a_failed_write_never_fails_the_request():
    session = MagicMock()
    session.exec.side_effect = OperationalError("UPDATE apikey", {}, Exception("database is locked"))

    wrote = api_key_usage.record_api_key_use(session, SimpleNamespace(id=1, last_used_at=None))

    assert wrote is False
    session.rollback.assert_called_once()
