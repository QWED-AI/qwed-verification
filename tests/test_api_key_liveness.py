"""#389 (CWE-613): the tenant auth boundary must reject expired and revoked API
keys, not just inactive ones. is_active stays True after a key's expires_at
lapses (nothing flips it), so filtering on is_active alone let an expired key keep
authenticating for every /verify/* route. is_api_key_live is the shared gate; the
tenant dependency (get_current_tenant) and the key middleware (get_api_key) must
both consult it."""
import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.auth.middleware import get_api_key
from qwed_new.auth.security import generate_api_key, is_api_key_live
from qwed_new.core.models import ApiKey, Organization
from qwed_new.core.tenant_context import get_current_tenant


# --- is_api_key_live unit coverage (duck-typed on the row's attributes) -------

def _key(is_active=True, revoked_at=None, expires_at=None):
    return SimpleNamespace(is_active=is_active, revoked_at=revoked_at, expires_at=expires_at)


def test_live_key_is_live():
    assert is_api_key_live(_key(expires_at=datetime.now(timezone.utc) + timedelta(days=1))) is True


def test_no_expiry_is_live():
    assert is_api_key_live(_key(expires_at=None)) is True


def test_inactive_is_not_live():
    assert is_api_key_live(_key(is_active=False)) is False


def test_revoked_is_not_live_even_if_active():
    assert is_api_key_live(_key(revoked_at=datetime.now(timezone.utc))) is False


def test_expired_aware_is_not_live():
    assert is_api_key_live(_key(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))) is False


def test_expired_naive_is_treated_as_utc_and_not_live():
    # key_rotation writes expires_at naive; a naive past value must still expire.
    assert is_api_key_live(_key(expires_at=datetime.utcnow() - timedelta(days=1))) is False


def test_future_naive_expiry_is_live():
    assert is_api_key_live(_key(expires_at=datetime.utcnow() + timedelta(days=1))) is True


def test_injected_now_is_used_instead_of_the_wall_clock():
    # A caller can inject a server-controlled reference instant; expiry is judged
    # against it, not the wall clock.
    expires = datetime(2026, 6, 1, tzinfo=timezone.utc)
    key = _key(expires_at=expires)
    assert is_api_key_live(key, now=datetime(2026, 5, 31, tzinfo=timezone.utc)) is True
    assert is_api_key_live(key, now=datetime(2026, 6, 2, tzinfo=timezone.utc)) is False


# --- integration: the auth boundaries actually enforce it ---------------------

@pytest.fixture
def seeded(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'live.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    session = Session(engine)
    org = Organization(name="acme", display_name="Acme", is_active=True)
    session.add(org); session.commit(); session.refresh(org)

    def mint(expires_at=None, is_active=True, revoked_at=None):
        raw, digest = generate_api_key()
        k = ApiKey(key_hash=digest, key_preview="qwed_live_...1234",
                   organization_id=org.id, user_id=1, name="k",
                   is_active=is_active, expires_at=expires_at, revoked_at=revoked_at)
        session.add(k); session.commit(); session.refresh(k)
        return raw

    yield SimpleNamespace(session=session, mint=mint)
    session.close()


def test_tenant_boundary_accepts_a_live_key(seeded):
    raw = seeded.mint(expires_at=datetime.now(timezone.utc) + timedelta(days=30))
    ctx = asyncio.run(get_current_tenant(x_api_key=raw, session=seeded.session))
    assert ctx.organization_name == "acme"


def test_tenant_boundary_rejects_an_expired_key(seeded):
    # is_active stays True; only the expires_at check rejects it (#389).
    raw = seeded.mint(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    call = get_current_tenant(x_api_key=raw, session=seeded.session)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(call)
    assert exc.value.status_code == 401


def test_tenant_boundary_rejects_a_revoked_but_active_key(seeded):
    # revoked_at set while is_active is still True: the SQL is_active filter
    # alone would let this through; liveness is what catches it.
    raw = seeded.mint(revoked_at=datetime.now(timezone.utc))
    call = get_current_tenant(x_api_key=raw, session=seeded.session)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(call)
    assert exc.value.status_code == 401


def test_middleware_rejects_an_expired_key(seeded):
    raw = seeded.mint(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    call = get_api_key(api_key_header=raw, session=seeded.session)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(call)
    assert exc.value.status_code == 403


def test_middleware_accepts_a_live_key(seeded):
    raw = seeded.mint(expires_at=datetime.now(timezone.utc) + timedelta(days=30))
    key = asyncio.run(get_api_key(api_key_header=raw, session=seeded.session))
    assert key.organization_id is not None
