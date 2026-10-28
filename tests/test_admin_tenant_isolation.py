"""#222: admin endpoints must be authenticated (RBAC working, not dead 401),
authorized by role, and scoped to the caller's own organization. A key from one
tenant must never read another tenant's data or rotate another tenant's keys, no
caller may rotate a key owned by a higher-privileged user, and the gate fails
closed on expired/revoked keys, foreign-org users and inactive organizations."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

import qwed_new.api.main as main
from qwed_new.auth.security import generate_api_key
from qwed_new.core.models import ApiKey, Organization, User, VerificationLog


class _StubAuditLogger:
    def verify_log_entry(self, log_id, session):
        return {"log_id": log_id, "verified": True}


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'admin.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def org(name, active=True):
        o = Organization(name=name, display_name=name.title(), is_active=active)
        session.add(o); session.commit(); session.refresh(o)
        return o

    def user(o, role, email=None):
        u = User(email=email or f"{role}-{o.id}@test", password_hash="x",
                 organization_id=o.id, role=role)
        session.add(u); session.commit(); session.refresh(u)
        return u

    def key(o, u, expires_at=None, is_active=True, revoked_at=None):
        raw, digest = generate_api_key()
        k = ApiKey(key_hash=digest, key_preview=f"{raw[:8]}...{raw[-4:]}",
                   organization_id=o.id, user_id=u.id,
                   expires_at=expires_at, is_active=is_active, revoked_at=revoked_at)
        session.add(k); session.commit(); session.refresh(k)
        return raw, k

    def log(o):
        v = VerificationLog(organization_id=o.id, query="q", result="{}", is_verified=True, domain="MATH")
        session.add(v); session.commit(); session.refresh(v)
        return v

    org_a, org_b = org("acme"), org("globex")
    org_dead = org("defunct", active=False)
    owner_a = user(org_a, "owner", "owner@acme")
    admin_a, admin_b = user(org_a, "admin"), user(org_b, "admin")
    member_a = user(org_a, "member")
    admin_dead = user(org_dead, "admin")

    raw_a, key_a = key(org_a, admin_a)
    raw_b, key_b = key(org_b, admin_b)
    raw_member, key_member = key(org_a, member_a)
    raw_owner, key_owner = key(org_a, owner_a)
    # A key in org A whose owning user actually belongs to org B (should be refused).
    raw_crossorg, key_crossorg = key(org_a, admin_b)
    raw_expired, key_expired = key(org_a, admin_a, expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    raw_dead, key_dead = key(org_dead, admin_dead)
    _, key_revoked = key(org_a, member_a, is_active=False, revoked_at=datetime.now(timezone.utc))
    log_a, log_b = log(org_a), log(org_b)

    monkeypatch.setattr(main.compliance_exporter, "export_audit_trail",
                        lambda org_id, start=None, end=None, max_rows=None: ("col\n1\n", False))
    monkeypatch.setattr(main.compliance_exporter, "generate_soc2_report", lambda org_id: {"org": org_id})
    monkeypatch.setattr(main.threat_detector, "get_threat_summary", lambda org_id: {"org": org_id})

    # Stateful stub: record which key was rotated and bind the new secret to that
    # key's tenant, so the success test proves the route rotated the right key.
    rotated_ids = []

    def rotate_key(kid):
        rotated_ids.append(kid)
        t = session.get(ApiKey, kid)
        assert t is not None
        return (SimpleNamespace(id=999, key_preview="qwed_new...9999",
                                organization_id=t.organization_id, user_id=t.user_id),
                f"raw-new-secret-{t.organization_id}-{t.user_id}")

    monkeypatch.setattr(main.key_manager, "rotate_key", rotate_key)
    monkeypatch.setattr("qwed_new.core.audit_logger.AuditLogger", _StubAuditLogger)

    main.app.dependency_overrides[main.get_session] = lambda: session
    client = TestClient(main.app, raise_server_exceptions=False)
    yield SimpleNamespace(
        client=client, org_a=org_a, org_b=org_b,
        raw_a=raw_a, raw_b=raw_b, raw_member=raw_member, raw_owner=raw_owner,
        raw_crossorg=raw_crossorg, raw_expired=raw_expired, raw_dead=raw_dead,
        key_a=key_a, key_b=key_b, key_member=key_member, key_owner=key_owner, key_revoked=key_revoked,
        log_a=log_a, log_b=log_b, rotated_ids=rotated_ids,
    )
    main.app.dependency_overrides.clear()
    session.close()


def _h(raw):
    return {"x-api-key": raw}


def _export(env, raw, org_id):
    return env.client.get(f"/admin/compliance/export/csv?organization_id={org_id}", headers=_h(raw))


def _rotate(env, raw, key_id):
    return env.client.post(f"/admin/keys/rotate?key_id={key_id}", headers=_h(raw))


def test_admin_endpoints_are_reachable_for_an_authorized_admin(env):
    # RBAC is no longer dead code: a valid admin key reaches the handler (200).
    assert _export(env, env.raw_a, env.org_a.id).status_code == 200


def test_cannot_export_another_tenants_data(env):
    assert _export(env, env.raw_a, env.org_b.id).status_code == 403


def test_cannot_read_another_tenants_soc2_or_threats(env):
    assert env.client.get(f"/admin/compliance/report/soc2/{env.org_b.id}", headers=_h(env.raw_a)).status_code == 403
    assert env.client.get(f"/admin/security/threats/{env.org_b.id}", headers=_h(env.raw_a)).status_code == 403
    assert env.client.get(f"/admin/compliance/report/soc2/{env.org_a.id}", headers=_h(env.raw_a)).status_code == 200


def test_can_verify_own_audit_log_but_not_another_tenants(env):
    assert env.client.get(f"/admin/compliance/verify/{env.log_a.id}", headers=_h(env.raw_a)).status_code == 200
    # Another tenant's log: 404 (existence not revealed).
    assert env.client.get(f"/admin/compliance/verify/{env.log_b.id}", headers=_h(env.raw_a)).status_code == 404


def test_cannot_rotate_another_tenants_key(env):
    assert _rotate(env, env.raw_a, env.key_b.id).status_code == 404


def test_admin_can_rotate_own_key_and_receive_new_secret(env):
    r = _rotate(env, env.raw_a, env.key_a.id)
    assert r.status_code == 200
    # The route rotated exactly the requested key, and returned that key's secret.
    assert env.rotated_ids == [env.key_a.id]
    assert r.json()["new_key_secret"] == f"raw-new-secret-{env.org_a.id}-{env.key_a.user_id}"


def test_member_cannot_rotate_an_admins_key(env):
    assert _rotate(env, env.raw_member, env.key_a.id).status_code == 403


def test_member_can_rotate_their_own_key(env):
    assert _rotate(env, env.raw_member, env.key_member.id).status_code == 200


def test_admin_cannot_rotate_an_owners_key(env):
    assert _rotate(env, env.raw_a, env.key_owner.id).status_code == 403


def test_cannot_rotate_a_revoked_key(env):
    # A revoked/inactive key must not be rotated into a fresh live secret.
    assert _rotate(env, env.raw_a, env.key_revoked.id).status_code == 404


def test_member_role_cannot_use_admin_only_endpoint(env):
    assert _export(env, env.raw_member, env.org_a.id).status_code == 403


def test_key_whose_user_is_in_another_org_is_refused(env):
    # The key is scoped to org A, but its owning user belongs to org B.
    assert _export(env, env.raw_crossorg, env.org_a.id).status_code == 403


def test_expired_key_is_refused(env):
    assert _export(env, env.raw_expired, env.org_a.id).status_code == 403


def test_inactive_organization_is_refused(env):
    assert _export(env, env.raw_dead, env.org_a.id).status_code == 403


def test_missing_key_is_unauthorized(env):
    assert env.client.get(f"/admin/compliance/export/csv?organization_id={env.org_a.id}").status_code == 401
