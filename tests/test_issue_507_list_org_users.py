"""#507: list the users of an organisation.

There was no route that listed an organisation's users: ``/auth/me`` returns
the signed-in user, and the security activity summary only a count. Keys have
owners and security events carry a ``user_id``, so a client could name a user
only by id.

``GET /auth/users`` returns every user of the caller's organisation (id,
email, role, is_active, created_at) to an owner or admin, with an API key or a
signed-in session. Members and viewers are refused, and no other
organisation's user is ever returned.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import create_access_token, generate_api_key
from qwed_new.core.models import ApiKey, Organization, User

ROLES = ("owner", "admin", "member", "viewer")


@pytest.fixture
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'users507.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    def key_for(u):
        raw, digest = generate_api_key()
        add(ApiKey(key_hash=digest, key_preview=raw[:8], organization_id=u.organization_id, user_id=u.id))
        return raw

    acme = add(Organization(name="acme", display_name="Acme"))
    globex = add(Organization(name="globex", display_name="Globex"))
    users = {role: add(User(email=f"{role}@acme.example.com", password_hash="x",
                            organization_id=acme.id, role=role)) for role in ROLES}
    users["former"] = add(User(email="former@acme.example.com", password_hash="x",
                               organization_id=acme.id, role="member", is_active=False))
    outsider = add(User(email="owner@globex.example.com", password_hash="x",
                        organization_id=globex.id, role="owner"))

    main.app.dependency_overrides[main.get_session] = lambda: session
    yield SimpleNamespace(
        session=session, acme=acme, globex=globex, users=users, outsider=outsider,
        add=add, key_for=key_for, client=TestClient(main.app),
    )
    main.app.dependency_overrides.clear()
    session.close()


def _bearer(u):
    return {"Authorization": f"Bearer {create_access_token({'sub': str(u.id)})}"}


def _users(env, headers):
    return env.client.get("/auth/users", headers=headers)


# ---------------------------------------------------------------- who may list

@pytest.mark.parametrize("who", ["owner", "admin"])
def test_an_owner_or_admin_session_lists_their_organisations_users(env, who):
    response = _users(env, _bearer(env.users[who]))

    assert response.status_code == 200
    body = response.json()
    # The inactive user included, nobody from globex.
    assert [u["email"] for u in body] == [
        "owner@acme.example.com", "admin@acme.example.com", "member@acme.example.com",
        "viewer@acme.example.com", "former@acme.example.com",
    ]
    assert body[0] == {
        "id": str(env.users["owner"].id),
        "email": "owner@acme.example.com",
        "role": "owner",
        "is_active": True,
        "created_at": body[0]["created_at"],
    }
    assert body[-1]["is_active"] is False
    assert all(u["created_at"].endswith("Z") for u in body)


def test_users_come_oldest_first_then_by_id(env):
    # Creation times that disagree with the ids: sorting by id alone gives
    # another order. The tied pair (member, viewer) comes back in id order,
    # but SQLite returns tied rows in rowid order anyway, so a missing id
    # tie-break is checked on the query instead (next test).
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    offsets = {"owner": 3, "admin": 0, "viewer": 1, "member": 1, "former": 2}
    for name, hours in offsets.items():
        env.users[name].created_at = start + timedelta(hours=hours)
        env.add(env.users[name])
    # member was created before viewer, so has the lower id of the tied pair.
    assert env.users["member"].id < env.users["viewer"].id

    body = _users(env, _bearer(env.users["owner"])).json()

    assert [u["email"].split("@")[0] for u in body] == ["admin", "member", "viewer", "former", "owner"]


def test_the_query_orders_by_time_then_id(env):
    # The rows cannot show a missing tie-break on SQLite (see above); the
    # ORDER BY clause can.
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        flat = " ".join(statement.replace('"', "").split())
        if "FROM user " in flat and "ORDER BY" in flat:
            statements.append(flat)

    engine = env.session.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert _users(env, _bearer(env.users["owner"])).status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", capture)

    assert len(statements) == 1
    assert statements[0].split("ORDER BY", 1)[1].strip() == "user.created_at, user.id"


@pytest.mark.parametrize("who", ["owner", "admin"])
def test_an_owner_or_admin_api_key_lists_them_too(env, who):
    response = _users(env, {"x-api-key": env.key_for(env.users[who])})

    assert response.status_code == 200
    assert len(response.json()) == 5


@pytest.mark.parametrize("who", ["member", "viewer"])
def test_a_member_or_viewer_is_refused_by_session_and_by_key(env, who):
    assert _users(env, _bearer(env.users[who])).status_code == 403
    assert _users(env, {"x-api-key": env.key_for(env.users[who])}).status_code == 403


def test_another_organisations_owner_sees_only_their_own_users(env):
    body = _users(env, _bearer(env.outsider)).json()

    assert [u["email"] for u in body] == ["owner@globex.example.com"]


def test_no_password_hash_or_permissions_are_returned(env):
    body = _users(env, _bearer(env.users["owner"])).json()

    assert all(set(u) == {"id", "email", "role", "is_active", "created_at"} for u in body)


# ---------------------------------------------------------------- refused callers

@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer not-a-jwt"}])
def test_no_or_a_bad_credential_is_401(env, headers):
    assert _users(env, headers).status_code == 401


@pytest.mark.parametrize("what", ["user", "organisation"])
def test_an_inactive_owner_or_organisation_is_refused(env, what):
    target = env.users["owner"] if what == "user" else env.acme
    target.is_active = False
    env.add(target)

    assert _users(env, _bearer(env.users["owner"])).status_code == 403


def test_an_api_key_wins_over_a_session(env):
    # Both sent: the viewer's key is used, so an owner's session does not lift it.
    both = {"x-api-key": env.key_for(env.users["viewer"]), **_bearer(env.users["owner"])}

    assert _users(env, both).status_code == 403


def test_openapi_lists_the_model_and_both_credentials(env):
    spec = env.client.get("/openapi.json").json()
    route = spec["paths"]["/auth/users"]["get"]

    assert {"APIKeyHeader": []} in route["security"]
    assert {"SessionBearer": []} in route["security"]
    assert set(spec["components"]["schemas"]["OrgUser"]["properties"]) == {
        "id", "email", "role", "is_active", "created_at",
    }
