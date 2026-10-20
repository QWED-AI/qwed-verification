"""#478: role checks on the API-key and audit routes; rbac.py removed.

The user-session (JWT) routes under /auth/api-keys and /audit only required a
logged-in user, so any role could create keys, list and revoke every key in
the organisation (the owner's included), and read and export the whole audit
log. Each route now names the roles it allows (auth/roles.py), refuses an
inactive user or organisation, and refuses any role not on its list.

One test per role per route, so the access rules stay pinned when an invite
or members feature adds a second user to an organisation.
"""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth import roles
from qwed_new.auth.security import create_access_token, generate_api_key
from qwed_new.core.models import ApiKey, Organization, User, VerificationLog

ROLES = ("viewer", "member", "admin", "owner")


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'roles.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    emails = iter(range(1000))

    def user(org, role, active=True):
        return add(User(email=f"user{next(emails)}@test", password_hash="x",
                        organization_id=org.id, role=role, is_active=active))

    def key(org, owner):
        raw, digest = generate_api_key()
        return add(ApiKey(key_hash=digest, key_preview=f"{raw[:8]}...", organization_id=org.id,
                          user_id=owner.id, name=f"{owner.role}-key"))

    acme = add(Organization(name="acme", display_name="Acme"))
    globex = add(Organization(name="globex", display_name="Globex"))
    defunct = add(Organization(name="defunct", display_name="Defunct", is_active=False))

    users = {role: user(acme, role) for role in ROLES}
    users["second_admin"] = user(acme, "admin")
    users["inactive"] = user(acme, "admin", active=False)
    users["unknown_role"] = user(acme, "superuser")
    users["defunct_admin"] = user(defunct, "admin")
    users["globex_owner"] = user(globex, "owner")

    keys = {name: key(acme, u) for name, u in users.items() if u.organization_id == acme.id}
    keys["globex_owner"] = key(globex, users["globex_owner"])

    logs = [add(VerificationLog(organization_id=acme.id, query="q", result="{}", is_verified=True, domain="MATH")),
            add(VerificationLog(organization_id=globex.id, query="q", result="{}", is_verified=True, domain="MATH"))]

    main.app.dependency_overrides[main.get_session] = lambda: session
    monkeypatch.delenv("QWED_ENABLE_AUDIT_SEED", raising=False)
    client = TestClient(main.app)  # a 500 raises, with its traceback

    def call(method, path, who, **kwargs):
        token = create_access_token({"sub": str(users[who].id)})
        return client.request(method, path, headers={"Authorization": f"Bearer {token}"}, **kwargs)

    yield SimpleNamespace(call=call, users=users, keys=keys, logs=logs, session=session)
    main.app.dependency_overrides.clear()
    session.close()


def _is_active(env, name):
    env.session.expire_all()
    return env.session.get(ApiKey, env.keys[name].id).is_active


# ---------------------------------------------------------------- shared rules

@pytest.mark.parametrize("who, detail", [
    ("inactive", roles.INACTIVE_USER),
    ("defunct_admin", roles.INACTIVE_ORG),
    ("unknown_role", roles.INSUFFICIENT_ROLE),
])
@pytest.mark.parametrize("method, path", [
    ("POST", "/auth/api-keys"),
    ("GET", "/auth/api-keys"),
    ("DELETE", "/auth/api-keys/1"),
    ("GET", "/audit/logs"),
    ("GET", "/audit/logs/1"),
    ("GET", "/audit/export"),
    ("POST", "/audit/seed"),
])
def test_inactive_users_inactive_orgs_and_unknown_roles_are_refused(env, who, detail, method, path):
    kwargs = {"json": {"name": "k"}} if method == "POST" and "api-keys" in path else {}
    response = env.call(method, path, who, **kwargs)

    assert response.status_code == 403
    assert response.json()["detail"] == detail


def test_a_missing_token_is_still_401(env):
    assert TestClient(main.app).get("/auth/api-keys").status_code == 401


# ---------------------------------------------------------------- create key

@pytest.mark.parametrize("who, status", [("viewer", 403), ("member", 200), ("admin", 200), ("owner", 200)])
def test_creating_a_key_needs_member_or_higher(env, who, status):
    response = env.call("POST", "/auth/api-keys", who, json={"name": "new"})

    assert response.status_code == status
    if status == 200:
        assert response.json()["key"]
        created = env.session.get(ApiKey, int(response.json()["id"]))
        assert created.user_id == env.users[who].id


# ---------------------------------------------------------------- list keys

def _listed(env, who):
    response = env.call("GET", "/auth/api-keys", who)
    assert response.status_code == 200
    return {int(item["id"]) for item in response.json()}


@pytest.mark.parametrize("who", ["viewer", "member"])
def test_viewers_and_members_list_only_their_own_keys(env, who):
    assert _listed(env, who) == {env.keys[who].id}


@pytest.mark.parametrize("who", ["admin", "owner"])
def test_admins_and_owners_list_every_key_in_their_organisation(env, who):
    acme_keys = {k.id for name, k in env.keys.items() if name != "globex_owner"}

    listed = _listed(env, who)

    assert listed == acme_keys
    assert env.keys["globex_owner"].id not in listed


# ---------------------------------------------------------------- revoke keys

@pytest.mark.parametrize("who", ROLES)
def test_every_role_can_revoke_its_own_key(env, who):
    response = env.call("DELETE", f"/auth/api-keys/{env.keys[who].id}", who)

    assert response.status_code == 200
    assert not _is_active(env, who)
    assert env.session.get(ApiKey, env.keys[who].id).revoked_at is not None


@pytest.mark.parametrize("who, target", [
    ("viewer", "member"), ("viewer", "owner"),
    ("member", "viewer"), ("member", "admin"), ("member", "owner"),
])
def test_viewers_and_members_cannot_revoke_another_users_key(env, who, target):
    response = env.call("DELETE", f"/auth/api-keys/{env.keys[target].id}", who)

    # 404, not 403: they cannot list that key, so do not confirm it exists.
    assert response.status_code == 404
    assert _is_active(env, target)


@pytest.mark.parametrize("who, target, status", [
    ("admin", "viewer", 200),
    ("admin", "member", 200),
    ("admin", "second_admin", 200),  # same rank, as for key rotation
    ("admin", "owner", 403),
    ("owner", "admin", 200),
    ("owner", "member", 200),
])
def test_admins_and_owners_revoke_keys_of_users_who_do_not_outrank_them(env, who, target, status):
    response = env.call("DELETE", f"/auth/api-keys/{env.keys[target].id}", who)

    assert response.status_code == status
    assert _is_active(env, target) is (status != 200)


@pytest.mark.parametrize("key_id", ["abc", "1.5", "-", "0", "-1", "99999", str(2**63), "9" * 40])
def test_a_bad_or_unknown_key_id_is_404_not_500(env, key_id):
    assert env.call("DELETE", f"/auth/api-keys/{key_id}", "owner").status_code == 404


def test_a_key_in_another_organisation_is_404_even_for_an_owner(env):
    response = env.call("DELETE", f"/auth/api-keys/{env.keys['globex_owner'].id}", "owner")

    assert response.status_code == 404
    assert _is_active(env, "globex_owner")


# ---------------------------------------------------------------- audit

@pytest.mark.parametrize("who", ROLES)
def test_every_role_can_read_its_organisations_logs(env, who):
    listing = env.call("GET", "/audit/logs", who)
    detail = env.call("GET", f"/audit/logs/{env.logs[0].id}", who)

    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert detail.status_code == 200


def test_a_log_in_another_organisation_is_404(env):
    assert env.call("GET", f"/audit/logs/{env.logs[1].id}", "owner").status_code == 404


@pytest.mark.parametrize("who, status", [("viewer", 403), ("member", 403), ("admin", 200), ("owner", 200)])
def test_only_admins_and_owners_can_export_the_log(env, who, status):
    response = env.call("GET", "/audit/export", who)

    assert response.status_code == status
    if status == 200:
        assert response.headers["content-type"].startswith("text/csv")


@pytest.mark.parametrize("who, status", [("viewer", 403), ("member", 403), ("admin", 404), ("owner", 404)])
def test_only_admins_and_owners_reach_the_seed_route(env, who, status):
    # Seeding is off by default, so admins and owners get past the role check
    # and then the 404; viewers and members are refused before it.
    assert env.call("POST", "/audit/seed", who).status_code == status


# ---------------------------------------------------------------- one ranking

def test_admin_routes_and_user_routes_share_one_role_ranking():
    assert main._ROLE_RANK is roles.ROLE_RANK
    assert set(roles.ROLE_RANK) == set(ROLES)
    assert roles.READ_ROLES == frozenset(ROLES)
    assert roles.WRITE_ROLES == frozenset({"member", "admin", "owner"})
    assert roles.ADMIN_ROLES == frozenset({"admin", "owner"})


@pytest.mark.parametrize("actor, target, expected", [
    ("owner", "owner", True), ("owner", "admin", True), ("admin", "owner", False),
    ("admin", "admin", True), ("member", "viewer", True),
    ("superuser", "viewer", False), ("superuser", "superuser", False), (None, "viewer", False),
    ("viewer", None, True),
])
def test_an_unknown_role_never_outranks_anyone(actor, target, expected):
    assert roles.outranks_or_equals(actor, target) is expected


def test_the_unused_rbac_module_is_gone():
    with pytest.raises(ModuleNotFoundError):
        __import__("qwed_new.core.rbac")


def test_no_route_left_on_bare_get_current_user():
    # Every api-key and audit route goes through a role check.
    for route in main.app.routes:
        path = getattr(route, "path", "")
        if path.startswith(("/auth/api-keys", "/audit/")):
            calls = {dep.call.__qualname__ for dep in route.dependant.dependencies}
            assert "get_current_user" not in calls, path
            assert any("require_user_role" in name for name in calls), path
