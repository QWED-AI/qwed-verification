"""#505, #506: key rotation and the threat summary take a signed-in session.

``POST /admin/keys/rotate`` and ``GET /admin/security/threats/{org_id}``
authenticated with an ``x-api-key`` only, so qwed-dashboard, which signs in
with a session and holds no API key, could not offer either.

Now both also accept ``Authorization: Bearer <jwt>``, as the compliance routes
do since #485. Every other rule is unchanged: the threat summary is for an
owner or admin of their own organisation; anyone from member up may rotate
their own key, an owner or admin another user's key, never a key owned by a
higher-privileged user, and never a revoked key or one in another
organisation. An API key still wins when both are sent.
"""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import create_access_token, generate_api_key, hash_api_key
from qwed_new.core import key_rotation, threat_detector
from qwed_new.core.models import ApiKey, Organization, SecurityEvent, User

ROLES = ("viewer", "member", "admin", "owner")


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'rotate505.db'}")
    SQLModel.metadata.create_all(engine)
    # rotate_key and get_threat_summary open their own sessions.
    monkeypatch.setattr(key_rotation, "engine", engine)
    monkeypatch.setattr(threat_detector, "engine", engine)
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

    def event(o, severity="high"):
        session.add(SecurityEvent(
            organization_id=o.id, event_type="BLOCKED", query="q", reason="r", severity=severity,
        ))
        session.commit()

    acme, globex = org("acme"), org("globex")
    users = {role: user(acme, role) for role in ROLES}
    other_owner = user(globex, "owner")

    main.app.dependency_overrides[main.get_session] = lambda: session
    yield SimpleNamespace(
        session=session, acme=acme, globex=globex, users=users, other_owner=other_owner,
        key_for=key_for, event=event, client=TestClient(main.app),
    )
    main.app.dependency_overrides.clear()
    session.close()


def _bearer(u):
    return {"Authorization": f"Bearer {create_access_token({'sub': str(u.id)})}"}


def _rotate(env, key_id, headers):
    return env.client.post(f"/admin/keys/rotate?key_id={key_id}", headers=headers)


def _threats(env, org_id, headers):
    return env.client.get(f"/admin/security/threats/{org_id}", headers=headers)


# ---------------------------------------------------------------- threat summary (#506)

@pytest.mark.parametrize("who", ["owner", "admin"])
def test_a_signed_in_owner_or_admin_gets_their_threat_summary(env, who):
    env.event(env.acme)
    env.event(env.acme)
    env.event(env.globex)

    response = _threats(env, env.acme.id, _bearer(env.users[who]))

    assert response.status_code == 200
    body = response.json()
    assert body["organization_id"] == env.acme.id
    # Only acme's two events, not globex's.
    assert body["metrics"]["total_events"] == 2
    assert body["metrics"]["high_severity_events"] == 2


@pytest.mark.parametrize("who", ["viewer", "member"])
def test_a_signed_in_member_or_viewer_cannot_read_the_threat_summary(env, who):
    assert _threats(env, env.acme.id, _bearer(env.users[who])).status_code == 403


def test_a_session_cannot_read_another_organisations_threat_summary(env):
    assert _threats(env, env.globex.id, _bearer(env.users["owner"])).status_code == 403


def test_an_api_key_still_reads_the_threat_summary_and_wins_over_a_session(env):
    owner_key, _ = env.key_for(env.users["owner"])
    member_key, _ = env.key_for(env.users["member"])

    assert _threats(env, env.acme.id, {"x-api-key": owner_key}).status_code == 200
    # Both sent: the member's key is used, so an owner's session does not lift it.
    both = {"x-api-key": member_key, **_bearer(env.users["owner"])}
    assert _threats(env, env.acme.id, both).status_code == 403


# ---------------------------------------------------------------- key rotation (#505)

@pytest.mark.parametrize("who", ["member", "admin", "owner"])
def test_a_signed_in_user_can_rotate_their_own_key(env, who):
    _, own = env.key_for(env.users[who])

    response = _rotate(env, own.id, _bearer(env.users[who]))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "rotated"
    assert body["old_key_id"] == own.id
    env.session.expire_all()
    new = env.session.get(ApiKey, body["new_key_id"])
    # The new secret is the replacement key's, for the same owner and organisation.
    assert new.key_hash == hash_api_key(body["new_key_secret"])
    assert (new.user_id, new.organization_id) == (env.users[who].id, env.acme.id)
    assert env.session.get(ApiKey, own.id).revoked_at is not None


@pytest.mark.parametrize(("who", "target"), [
    ("owner", "admin"),
    ("owner", "member"),
    ("admin", "member"),
    ("admin", "viewer"),
])
def test_a_signed_in_owner_or_admin_can_rotate_a_lower_or_equal_users_key(env, who, target):
    _, key = env.key_for(env.users[target])

    assert _rotate(env, key.id, _bearer(env.users[who])).status_code == 200


@pytest.mark.parametrize(("who", "target"), [
    ("member", "admin"),
    ("member", "viewer"),
    ("admin", "owner"),
])
def test_a_session_cannot_rotate_a_key_it_may_not(env, who, target):
    _, key = env.key_for(env.users[target])

    assert _rotate(env, key.id, _bearer(env.users[who])).status_code == 403
    env.session.expire_all()
    assert env.session.get(ApiKey, key.id).revoked_at is None


def test_a_signed_in_viewer_cannot_rotate_even_their_own_key(env):
    _, own = env.key_for(env.users["viewer"])

    assert _rotate(env, own.id, _bearer(env.users["viewer"])).status_code == 403


def test_a_session_cannot_rotate_another_organisations_or_a_revoked_key(env):
    _, foreign = env.key_for(env.other_owner)
    _, revoked = env.key_for(env.users["member"])
    _rotate(env, revoked.id, _bearer(env.users["member"]))

    owner = _bearer(env.users["owner"])
    # 404, not 403: the route does not confirm a key in another organisation exists.
    assert _rotate(env, foreign.id, owner).status_code == 404
    assert _rotate(env, revoked.id, owner).status_code == 404


def test_an_api_key_still_rotates_and_wins_over_a_session(env):
    member_key, member_own = env.key_for(env.users["member"])
    _, admin_own = env.key_for(env.users["admin"])

    assert _rotate(env, member_own.id, {"x-api-key": member_key}).status_code == 200
    # Both sent: the member's key is used, so an owner's session does not let
    # it rotate an admin's key. (The member key was just rotated, so mint another.)
    member_key, _ = env.key_for(env.users["member"])
    both = {"x-api-key": member_key, **_bearer(env.users["owner"])}
    assert _rotate(env, admin_own.id, both).status_code == 403


# ---------------------------------------------------------------- both routes

@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer not-a-jwt"},
])
def test_no_or_a_bad_credential_is_401(env, headers):
    _, key = env.key_for(env.users["owner"])

    assert _threats(env, env.acme.id, headers).status_code == 401
    assert _rotate(env, key.id, headers).status_code == 401


def test_an_inactive_signed_in_user_is_refused(env):
    owner = env.users["owner"]
    _, key = env.key_for(owner)
    owner.is_active = False
    env.session.add(owner)
    env.session.commit()

    assert _threats(env, env.acme.id, _bearer(owner)).status_code == 403
    assert _rotate(env, key.id, _bearer(owner)).status_code == 403


def test_openapi_lists_the_bearer_token_for_both_routes(env):
    spec = env.client.get("/openapi.json").json()

    for path, method in (("/admin/security/threats/{org_id}", "get"), ("/admin/keys/rotate", "post")):
        security = spec["paths"][path][method]["security"]
        assert {"APIKeyHeader": []} in security
        assert {"SessionBearer": []} in security
