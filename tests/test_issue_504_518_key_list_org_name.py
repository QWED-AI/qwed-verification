"""#504, #518: the key list and the user object carry what the dashboard shows.

``GET /auth/api-keys`` returned no expiry, no rotation flag and no owner,
although ``ApiKey`` stores all three, so a client could not show that a key
expires tomorrow, must be rotated, or belongs to someone else (#504).
``/auth/me`` and the sign-in ``user`` object returned the organisation's id
but not its name, so the dashboard could only show "Organisation 1" (#518).

Now each listed key carries ``expires_at``, ``rotation_required`` and
``owner`` (id and email, or null), and the user object carries ``org_name``.
"""

import secrets
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import create_access_token, generate_api_key, hash_password
from qwed_new.core.models import ApiKey, Organization, User
from qwed_new.core.rate_limiter import rate_limiter

# Made per run, so no credential sits in the source.
PASSWORD = secrets.token_urlsafe(16)


@pytest.fixture
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'keys504.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    def key(org, owner=None, name="k", **fields):
        _, digest = generate_api_key()
        return add(ApiKey(key_hash=digest, key_preview="qwed_live_...", organization_id=org.id,
                          user_id=owner.id if owner else None, name=name, **fields))

    acme = add(Organization(name="acme-e2e", display_name="QWED E2E Test Org"))
    globex = add(Organization(name="globex", display_name="Globex"))
    users = {
        role: add(User(email=f"{role}@acme.example.com", password_hash="x", organization_id=acme.id, role=role))
        for role in ("owner", "admin", "member")
    }
    outsider = add(User(email="owner@globex.example.com", password_hash="x", organization_id=globex.id, role="owner"))

    main.app.dependency_overrides[main.get_session] = lambda: session
    rate_limiter.ip_requests.clear()
    rate_limiter._expiries.clear()

    def call(method, path, who, **kwargs):
        token = create_access_token({"sub": str(users[who].id)})
        return TestClient(main.app).request(method, path, headers={"Authorization": f"Bearer {token}"}, **kwargs)

    yield SimpleNamespace(
        engine=engine, session=session, acme=acme, globex=globex, users=users, outsider=outsider,
        add=add, key=key, call=call,
    )
    main.app.dependency_overrides.clear()
    rate_limiter.ip_requests.clear()
    rate_limiter._expiries.clear()
    session.close()


def _listed(env, who="owner"):
    response = env.call("GET", "/auth/api-keys", who)
    assert response.status_code == 200
    return {item["id"]: item for item in response.json()}


# ---------------------------------------------------------------- key list (#504)

def test_a_key_that_expires_and_one_that_does_not(env):
    when = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    expiring = env.key(env.acme, env.users["owner"], expires_at=when)
    lasting = env.key(env.acme, env.users["owner"])

    items = _listed(env)

    # Always with its UTC offset, also where SQLite reads the time back naive.
    assert items[str(expiring.id)]["expires_at"] == "2030-01-02T03:04:05Z"
    assert items[str(lasting.id)]["expires_at"] is None
    assert items[str(lasting.id)]["created_at"].endswith("Z")


def test_the_rotation_flag_is_returned_as_stored(env):
    flagged = env.key(env.acme, env.users["owner"], rotation_required=True)
    plain = env.key(env.acme, env.users["owner"])

    items = _listed(env)

    assert items[str(flagged.id)]["rotation_required"] is True
    assert items[str(plain.id)]["rotation_required"] is False


def test_each_key_names_its_owner(env):
    keys = {role: env.key(env.acme, u) for role, u in env.users.items()}

    items = _listed(env)

    for role, k in keys.items():
        assert items[str(k.id)]["owner"] == {"id": str(env.users[role].id), "email": f"{role}@acme.example.com"}


def test_a_key_with_no_user_has_a_null_owner(env):
    orphan = env.key(env.acme)

    assert _listed(env)[str(orphan.id)]["owner"] is None


def test_a_user_from_another_organisation_is_never_shown_as_owner(env):
    # A key in acme whose user row belongs to globex: the admin path refuses
    # such a key, and the list must not reveal that user's email either.
    crossed = env.key(env.acme, env.outsider)

    item = _listed(env)[str(crossed.id)]

    assert item["owner"] is None
    assert "globex" not in str(item)


def test_a_member_still_sees_only_their_own_keys_with_themselves_as_owner(env):
    own = env.key(env.acme, env.users["member"])
    env.key(env.acme, env.users["owner"])

    items = _listed(env, "member")

    assert list(items) == [str(own.id)]
    assert items[str(own.id)]["owner"]["email"] == "member@acme.example.com"


def test_the_owners_are_read_in_one_query(env):
    for role in ("owner", "admin", "member"):
        env.key(env.acme, env.users[role])
        env.key(env.acme, env.users[role])
    selects = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT") and "FROM user" in statement.replace('"', ""):
            selects.append(statement)

    event.listen(env.engine, "before_cursor_execute", capture)
    try:
        _listed(env)
    finally:
        event.remove(env.engine, "before_cursor_execute", capture)

    # One for the caller's role check, one for every key's owner.
    assert len(selects) == 2


def test_the_openapi_model_lists_the_new_fields(env):
    spec = TestClient(main.app).get("/openapi.json").json()
    item = spec["components"]["schemas"]["APIKeyListItem"]["properties"]

    assert {"expires_at", "rotation_required", "owner"} <= set(item)


# ---------------------------------------------------------------- organisation name (#518)

def test_me_returns_the_organisations_name(env):
    body = env.call("GET", "/auth/me", "admin").json()

    assert body == {
        "id": str(env.users["admin"].id),
        "email": "admin@acme.example.com",
        "org_id": str(env.acme.id),
        "org_name": "QWED E2E Test Org",
        "role": "admin",
    }


def test_signin_returns_the_organisations_name(env):
    user = env.users["owner"]
    user.password_hash = hash_password(PASSWORD)
    env.add(user)

    response = TestClient(main.app).post("/auth/signin", json={"email": "owner@acme.example.com", "password": PASSWORD})

    assert response.status_code == 200
    assert response.json()["user"]["org_name"] == "QWED E2E Test Org"
    assert response.json()["user"]["org_id"] == str(env.acme.id)


def test_signup_returns_the_new_organisations_name(env):
    response = TestClient(main.app).post("/auth/signup", json={
        "email": "new@initech.example.com", "password": PASSWORD, "organization_name": "Initech Ltd",
    })

    assert response.status_code == 200
    assert response.json()["user"]["org_name"] == "Initech Ltd"


@pytest.mark.parametrize("what", ["user", "organisation"])
def test_me_refuses_an_inactive_user_or_organisation(env, what):
    target = env.users["owner"] if what == "user" else env.acme
    target.is_active = False
    env.add(target)

    response = env.call("GET", "/auth/me", "owner")

    assert response.status_code == 403
    assert "org_name" not in response.text


def test_me_still_needs_a_token(env):
    assert TestClient(main.app).get("/auth/me").status_code == 401


def test_the_name_is_the_display_name_not_the_unique_slug(env):
    env.acme.display_name = "Acme, Renamed"
    env.add(env.acme)

    assert env.call("GET", "/auth/me", "owner").json()["org_name"] == "Acme, Renamed"
