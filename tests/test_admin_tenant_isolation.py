"""#222: admin endpoints must be authenticated (RBAC working, not dead 401),
authorized by role, and scoped to the caller's own organization. A key from one
tenant must never read another tenant's data or rotate another tenant's keys."""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

import qwed_new.api.main as main
from qwed_new.api.main import app, get_session
from qwed_new.auth.security import generate_api_key, hash_api_key
from qwed_new.core.models import ApiKey, Organization, User, VerificationLog


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'admin.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def org(name):
        o = Organization(name=name, display_name=name.title())
        session.add(o); session.commit(); session.refresh(o)
        return o

    def user(o, role):
        u = User(email=f"{role}@{o.name}.test", password_hash="x", organization_id=o.id, role=role)
        session.add(u); session.commit(); session.refresh(u)
        return u

    def key(o, u):
        raw, digest = generate_api_key()
        k = ApiKey(key_hash=digest, key_preview=f"{raw[:8]}...{raw[-4:]}",
                   organization_id=o.id, user_id=u.id)
        session.add(k); session.commit(); session.refresh(k)
        return raw, k

    def log(o):
        v = VerificationLog(organization_id=o.id, query="q", result="{}", is_verified=True, domain="MATH")
        session.add(v); session.commit(); session.refresh(v)
        return v

    org_a, org_b = org("acme"), org("globex")
    admin_a, admin_b = user(org_a, "admin"), user(org_b, "admin")
    member_a = user(org_a, "member")
    raw_a, key_a = key(org_a, admin_a)
    raw_b, key_b = key(org_b, admin_b)
    raw_member, key_member = key(org_a, member_a)
    log_a, log_b = log(org_a), log(org_b)

    # Isolate downstreams: this test is about authorization, not their internals.
    monkeypatch.setattr(main.compliance_exporter, "export_audit_trail_csv", lambda org_id: "col\n1\n")
    monkeypatch.setattr(main.compliance_exporter, "generate_soc2_report", lambda org_id: {"org": org_id})
    monkeypatch.setattr(main.threat_detector, "get_threat_summary", lambda org_id: {"org": org_id})
    monkeypatch.setattr(main.key_manager, "rotate_key",
                        lambda kid: (SimpleNamespace(id=999, key_preview="qwed_new...9999"), "raw-new-secret"))

    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app, raise_server_exceptions=False)
    yield SimpleNamespace(client=client, org_a=org_a, org_b=org_b, raw_a=raw_a, raw_b=raw_b,
                          raw_member=raw_member, key_a=key_a, key_b=key_b, log_a=log_a, log_b=log_b)
    app.dependency_overrides.clear()
    session.close()


def _h(raw):
    return {"x-api-key": raw}


def test_admin_endpoints_are_reachable_for_an_authorized_admin(env):
    # RBAC is no longer dead code: a valid admin key reaches the handler (200),
    # not the old blanket 401.
    r = env.client.get(f"/admin/compliance/export/csv?organization_id={env.org_a.id}", headers=_h(env.raw_a))
    assert r.status_code == 200


def test_cannot_export_another_tenants_data(env):
    r = env.client.get(f"/admin/compliance/export/csv?organization_id={env.org_b.id}", headers=_h(env.raw_a))
    assert r.status_code == 403


def test_cannot_read_another_tenants_soc2_or_threats(env):
    assert env.client.get(f"/admin/compliance/report/soc2/{env.org_b.id}", headers=_h(env.raw_a)).status_code == 403
    assert env.client.get(f"/admin/security/threats/{env.org_b.id}", headers=_h(env.raw_a)).status_code == 403
    assert env.client.get(f"/admin/compliance/report/soc2/{env.org_a.id}", headers=_h(env.raw_a)).status_code == 200


def test_cannot_verify_another_tenants_audit_log(env):
    # Own log: reachable. Another tenant's log: 404 (existence not revealed).
    assert env.client.get(f"/admin/compliance/verify/{env.log_b.id}", headers=_h(env.raw_a)).status_code == 404
    assert env.client.get(f"/admin/compliance/verify/{env.log_a.id}", headers=_h(env.raw_a)).status_code != 403


def test_cannot_rotate_another_tenants_key(env):
    # Rotating tenant B's key with tenant A's credentials is refused (404).
    r = env.client.post(f"/admin/keys/rotate?key_id={env.key_b.id}", headers=_h(env.raw_a))
    assert r.status_code == 404


def test_can_rotate_own_key_and_receive_new_secret(env):
    r = env.client.post(f"/admin/keys/rotate?key_id={env.key_a.id}", headers=_h(env.raw_a))
    assert r.status_code == 200
    assert r.json()["new_key_secret"] == "raw-new-secret"


def test_member_role_cannot_use_admin_only_endpoint(env):
    r = env.client.get(f"/admin/compliance/export/csv?organization_id={env.org_a.id}", headers=_h(env.raw_member))
    assert r.status_code == 403


def test_missing_key_is_unauthorized(env):
    r = env.client.get(f"/admin/compliance/export/csv?organization_id={env.org_a.id}")
    assert r.status_code == 401
