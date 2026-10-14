"""#452: KeyManager.rotate_key must be atomic — two concurrent rotations of the
same key may mint only one replacement, and an already inactive/revoked key is
not rotated into a fresh live secret."""
import threading
from types import SimpleNamespace

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from qwed_new.auth.security import generate_api_key
from qwed_new.core import key_rotation as kr
from qwed_new.core.models import ApiKey


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    # File-based sqlite with cross-thread access and a busy timeout, so the
    # concurrent test exercises real lock contention without spurious errors.
    engine = create_engine(
        f"sqlite:///{tmp_path / 'keys.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    SQLModel.metadata.create_all(engine)
    raw, digest = generate_api_key()
    with Session(engine) as s:
        k = ApiKey(key_hash=digest, key_preview="qwed_live_...1234",
                   organization_id=1, user_id=1, name="k", is_active=True)
        s.add(k); s.commit(); s.refresh(k)
        key_id = k.id
    # rotate_key and create_key both use the module-level engine.
    monkeypatch.setattr(kr, "engine", engine)
    return SimpleNamespace(engine=engine, key_id=key_id)


def _active_keys(engine, org_id=1):
    with Session(engine) as s:
        return s.exec(select(ApiKey).where(
            ApiKey.organization_id == org_id, ApiKey.is_active == True)).all()


def test_second_rotation_of_same_key_mints_nothing(seeded):
    km = kr.KeyManager()
    new1, raw1 = km.rotate_key(seeded.key_id)
    assert new1 is not None
    assert raw1
    # The original key is now revoked; rotating it again claims nothing.
    new2, raw2 = km.rotate_key(seeded.key_id)
    assert new2 is None
    assert raw2 is None
    # Exactly one live key remains in the org: the single replacement.
    assert len(_active_keys(seeded.engine)) == 1


def test_rotate_unknown_key_returns_none(seeded):
    assert kr.KeyManager().rotate_key(999999) == (None, None)


def test_failed_mint_rolls_back_the_revoke(seeded, monkeypatch):
    # If minting the replacement fails, the revoke must roll back so the account
    # is never left with no active key.
    km = kr.KeyManager()

    def boom(*args, **kwargs):
        raise RuntimeError("mint failed")

    monkeypatch.setattr(km, "_build_key", boom)
    with pytest.raises(RuntimeError):
        km.rotate_key(seeded.key_id)
    # The original key is still active and not revoked.
    with Session(seeded.engine) as s:
        key = s.get(ApiKey, seeded.key_id)
        assert key.is_active is True
        assert key.revoked_at is None
    assert len(_active_keys(seeded.engine)) == 1


def test_rotate_refuses_a_key_already_marked_revoked(seeded):
    # is_active=True but revoked_at set is an inconsistent/revoked state.
    with Session(seeded.engine) as s:
        key = s.get(ApiKey, seeded.key_id)
        from datetime import datetime, timezone
        key.revoked_at = datetime.now(timezone.utc)
        s.add(key); s.commit()
    assert kr.KeyManager().rotate_key(seeded.key_id) == (None, None)


def test_concurrent_rotations_mint_exactly_one_replacement(seeded):
    km = kr.KeyManager()
    results = []
    lock = threading.Lock()
    start = threading.Barrier(2)

    def go():
        start.wait()  # release both threads together to force contention
        r = km.rotate_key(seeded.key_id)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [r for r in results if r[0] is not None]
    losers = [r for r in results if r[0] is None]
    assert len(winners) == 1, results
    assert len(losers) == 1, results
    # Exactly one live replacement key, never two.
    assert len(_active_keys(seeded.engine)) == 1
