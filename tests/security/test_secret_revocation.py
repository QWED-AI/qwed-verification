"""Tests for the verified-leak revocation sink (issue #368).

Covers the acceptance criteria: found/revoke + owner email, already-revoked
idempotency, unknown-token tally with no action, notify-failure-keeps-
revocation, and no plaintext token in logs or stored rows.

Hermetic: isolated temp-file sqlite engine per test + its own lookup secret.
"""

import logging

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from qwed_new.api.secret_revocation import (
    REVOKED_EVENT_TYPE,
    revoke_leaked_keys,
)
from qwed_new.api.secret_scanning_routes import SecretMatch
from qwed_new.auth.security import generate_api_key, hash_api_key
from qwed_new.core.alerting import AlertManager
from qwed_new.core.models import ApiKey, Organization, SecurityEvent, User


@pytest.fixture
def session_factory(tmp_path, monkeypatch):
    """Isolated DB + lookup secret. Yields a session factory for the sink."""
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "test-sink-lookup-secret")
    db_path = tmp_path / "sink_test.db"
    test_engine = create_engine(f"sqlite:///{db_path}")
    SQLModel.metadata.create_all(test_engine)
    return lambda: Session(test_engine)


def _seed_org(session, name="acme"):
    org = Organization(name=name, display_name=name.title())
    session.add(org)
    session.commit()
    session.refresh(org)
    return org


def _seed_user(session, org, email="owner@acme.test", role="owner"):
    user = User(
        email=email,
        password_hash="not-a-real-hash",
        organization_id=org.id,
        role=role,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _seed_key(session, org, user=None, name="leak-me"):
    raw, digest = generate_api_key()
    assert digest == hash_api_key(raw)
    key = ApiKey(
        key_hash=digest,
        key_preview=f"{raw[:10]}...{raw[-4:]}",
        organization_id=org.id,
        user_id=user.id if user else None,
        name=name,
    )
    session.add(key)
    session.commit()
    session.refresh(key)
    return raw, key


def _match(token, source="commit"):
    return SecretMatch(
        token=token,
        type="qwed_live_api_key",
        url="https://github.com/octo/Hello-World/blob/1234/foo.txt",
        source=source,
    )


def _mails(monkeypatch):
    sent = []

    def _fake(self, recipient, subject, body):
        sent.append((recipient, subject, body))

    monkeypatch.setattr(AlertManager, "send_owner_email", _fake)
    return sent


def _fresh_key_row(session_factory, digest):
    with session_factory() as session:
        return session.exec(select(ApiKey).where(ApiKey.key_hash == digest)).first()


def test_revoke_found_active_key_and_notify_owner(session_factory, monkeypatch):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, key = _seed_key(session, org, user)
        preview = key.key_preview

    outcome = revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome == {"revoked": 1, "already_revoked": 0, "unknown": 0, "errors": 0}
    row = _fresh_key_row(session_factory, hash_api_key(raw))
    assert row.is_active is False
    assert row.revoked_at is not None
    assert len(sent) == 1
    recipient, subject, body = sent[0]
    assert recipient == "owner@acme.test"
    assert preview in body
    assert raw not in body
    assert raw not in subject


def test_revocation_audit_row_has_no_plaintext(session_factory, monkeypatch):
    _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, key = _seed_key(session, org, user)

    revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    with session_factory() as session:
        events = session.exec(
            select(SecurityEvent).where(SecurityEvent.event_type == REVOKED_EVENT_TYPE)
        ).all()
        assert len(events) == 1
        stored = " ".join(
            f"{e.query} {e.reason} {e.event_type}" for e in events
        )
        assert raw not in stored
        assert key.key_preview in stored


def test_already_revoked_is_idempotent_no_renotify(session_factory, monkeypatch):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, key = _seed_key(session, org, user)
        key.is_active = False
        from datetime import datetime

        key.revoked_at = datetime.utcnow()
        session.add(key)
        session.commit()

    outcome = revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome["already_revoked"] == 1
    assert outcome["revoked"] == 0
    assert sent == []


def test_unknown_token_no_action_tallied(session_factory, monkeypatch, caplog):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        _seed_key(session, org, user)

    stranger = "qwed_live_" + "Z" * 30 + "000000"
    with caplog.at_level(logging.INFO, logger="qwed_new.api.secret_revocation"):
        outcome = revoke_leaked_keys([_match(stranger)], session_factory=session_factory)

    assert outcome == {"revoked": 0, "already_revoked": 0, "unknown": 1, "errors": 0}
    assert sent == []
    assert stranger not in caplog.text


def test_notify_failure_keeps_revocation(session_factory, monkeypatch):
    def _boom(self, recipient, subject, body):
        raise RuntimeError("smtp down")

    monkeypatch.setattr(AlertManager, "send_owner_email", _boom)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    outcome = revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome["revoked"] == 1
    row = _fresh_key_row(session_factory, hash_api_key(raw))
    assert row.is_active is False


def test_owner_falls_back_to_org_owner(session_factory, monkeypatch):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        owner = _seed_user(session, org, email="boss@acme.test", role="owner")
        _seed_user(session, org, email="member@acme.test", role="member")
        raw, _key = _seed_key(session, org, user=None)
        owner_id = owner.id

    outcome = revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome["revoked"] == 1
    assert sent and sent[0][0] == "boss@acme.test"
    assert owner_id is not None


def test_no_reachable_owner_revokes_without_email(session_factory, monkeypatch, caplog):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        raw, _key = _seed_key(session, org, user=None)

    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_revocation"):
        outcome = revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome["revoked"] == 1
    assert sent == []
    assert "no reachable owner" in caplog.text


def test_duplicate_delivery_notifies_once(session_factory, monkeypatch):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    outcome = revoke_leaked_keys(
        [_match(raw), _match(raw, source="gist_content")],
        session_factory=session_factory,
    )

    assert outcome["revoked"] == 1
    assert outcome["already_revoked"] == 1
    assert len(sent) == 1


def test_mixed_batch_counts(session_factory, monkeypatch):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw_a, _ = _seed_key(session, org, user, name="a")
        raw_b, key_b = _seed_key(session, org, user, name="b")
        key_b.is_active = False
        session.add(key_b)
        session.commit()

    outcome = revoke_leaked_keys(
        [_match(raw_a), _match(raw_b), _match("qwed_live_" + "Q" * 30 + "000000")],
        session_factory=session_factory,
    )

    assert outcome == {"revoked": 1, "already_revoked": 1, "unknown": 1, "errors": 0}
    assert len(sent) == 1
