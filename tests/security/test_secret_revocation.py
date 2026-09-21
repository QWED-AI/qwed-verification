"""Tests for the verified-leak revocation sink (issue #368).

Covers the acceptance criteria: found/revoke + owner email, already-revoked
idempotency, unknown-token tally with no action, notify-failure-keeps-
revocation, and no plaintext token in logs or stored rows.

Hermetic: isolated temp-file sqlite engine per test + its own lookup secret.
"""

import logging
from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

import qwed_new.api.secret_revocation as revocation_module
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

    outcome = revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)

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

    revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    with session_factory() as session:
        events = session.exec(
            select(SecurityEvent).where(SecurityEvent.event_type == revocation_module.REVOKED_EVENT_TYPE)
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

    outcome = revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)

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
        outcome = revocation_module.revoke_leaked_keys([_match(stranger)], session_factory=session_factory)

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

    outcome = revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)

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

    outcome = revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome["revoked"] == 1
    assert sent[0][0] == "boss@acme.test"
    assert owner_id is not None


def test_no_reachable_owner_revokes_without_email(session_factory, monkeypatch, caplog):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        raw, _key = _seed_key(session, org, user=None)

    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_revocation"):
        outcome = revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome["revoked"] == 1
    assert sent == []
    assert "no reachable owner" in caplog.text


def test_duplicate_delivery_notifies_once(session_factory, monkeypatch):
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    outcome = revocation_module.revoke_leaked_keys(
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

    outcome = revocation_module.revoke_leaked_keys(
        [_match(raw_a), _match(raw_b), _match("qwed_live_" + "Q" * 30 + "000000")],
        session_factory=session_factory,
    )

    assert outcome == {"revoked": 1, "already_revoked": 1, "unknown": 1, "errors": 0}
    assert len(sent) == 1


def test_concurrent_revoke_single_winner_no_double_email(session_factory, monkeypatch):
    """CodeAnt race review on #380: two deliveries racing on one active key
    must produce exactly one revocation + one email. Deterministic: session A
    SELECTs while active, session B wins first, A's conditional UPDATE then
    loses by rowcount (no threads, no timing dependence)."""

    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)
        key_id = _key.id

    session_a = session_factory()
    session_b = session_factory()
    try:
        key_a = session_a.exec(select(ApiKey).where(ApiKey.id == key_id)).first()
        key_b = session_b.exec(select(ApiKey).where(ApiKey.id == key_id)).first()
        assert key_a.is_active
        assert key_b.is_active
        match = _match(raw)
        fixed_now = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
        assert (
            revocation_module._try_revoke(session_b, key_b, match, revoked_at=fixed_now)
            is True
        )
        session_b.commit()
        # Naive-column storage drops tzinfo on round-trip (the column is
        # naive by repo-wide convention); the instant must match exactly.
        assert key_b.revoked_at == fixed_now.replace(tzinfo=None)
        assert revocation_module._try_revoke(session_a, key_a, match) is False
    finally:
        session_a.close()
        session_b.close()

    outcome = revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)
    assert outcome["already_revoked"] == 1
    assert outcome["revoked"] == 0
    assert sent == []


def test_digest_failure_aborts_batch_loudly(session_factory, monkeypatch):
    """CodeRabbit fail-closed on #380: a digest failure means enforcement
    cannot run, so the batch aborts with an exception instead of a quiet
    errors tally."""
    _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET")
    batch = [
        _match(raw),
        _match("qwed_live_" + "Q" * 30 + "000000"),
    ]
    with pytest.raises(RuntimeError):
        revocation_module.revoke_leaked_keys(batch, session_factory=session_factory)


def test_send_owner_email_success(monkeypatch):
    """Real send_owner_email path with stubbed SMTP (covers alerting.py)."""
    import smtplib

    from qwed_new.core.alerting import AlertManager

    seen = {}

    class _FakeSMTP:
        def __init__(self, host, port, timeout=None):
            seen["host"], seen["port"], seen["timeout"] = host, port, timeout

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self):
            seen["tls"] = True

        def login(self, user, password):
            seen["login"] = (user, password)

        def send_message(self, msg):
            seen["msg"] = msg

    monkeypatch.setenv("SMTP_USER", "bot@qwed.test")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    manager = AlertManager()

    manager.send_owner_email("owner@acme.test", "subject-line", "body-text")

    assert seen["login"] == ("bot@qwed.test", "pw")
    assert seen["timeout"] == 10
    assert seen["msg"]["To"] == "owner@acme.test"
    assert "subject-line" in seen["msg"]["Subject"]
    assert "body-text" in seen["msg"].as_string()


def test_send_owner_email_rejects_bad_recipient(monkeypatch):
    from qwed_new.core.alerting import AlertManager

    monkeypatch.setenv("SMTP_USER", "bot@qwed.test")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")

    manager = AlertManager()
    with pytest.raises(ValueError, match="valid recipient"):
        manager.send_owner_email("not-an-email", "s", "b")


def test_send_owner_email_missing_smtp_config(monkeypatch):
    from qwed_new.core.alerting import AlertManager

    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)

    manager = AlertManager()
    with pytest.raises(RuntimeError, match="not configured"):
        manager.send_owner_email("owner@acme.test", "s", "b")


def test_send_owner_email_smtp_failure_propagates(monkeypatch):
    """Delivery errors propagate so the caller (revoke sink) can log them."""
    import smtplib

    from qwed_new.core.alerting import AlertManager

    class _DownSMTP:
        def __init__(self, host, port, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self):
            pass

        def login(self, user, password):
            pass

        def send_message(self, msg):
            raise RuntimeError("smtp down")

    monkeypatch.setenv("SMTP_USER", "bot@qwed.test")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    monkeypatch.setattr(smtplib, "SMTP", _DownSMTP)

    manager = AlertManager()
    with pytest.raises(RuntimeError, match="smtp down"):
        manager.send_owner_email("owner@acme.test", "s", "b")


def test_race_loss_counted_via_sink_not_notified(session_factory, monkeypatch):
    """The lose-the-race branch inside the sink (rollback + already_revoked,
    no email) — forced deterministically by stubbing _try_revoke False."""

    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    monkeypatch.setattr(revocation_module, "_try_revoke", lambda *a, **k: False)
    outcome = revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)

    assert outcome == {"revoked": 0, "already_revoked": 1, "unknown": 0, "errors": 0}
    assert sent == []
    row = _fresh_key_row(session_factory, hash_api_key(raw))
    assert row.is_active is True


def test_match_processing_error_revokes_siblings_then_raises(session_factory, monkeypatch):
    """A per-row failure must not block sibling revocations — but the batch
    still fails loudly at the end (CodeRabbit fail-closed on #380)."""
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw_bad, _key_bad = _seed_key(session, org, user, name="bad")
        raw_good, _key_good = _seed_key(session, org, user, name="good")

    real_try_revoke = revocation_module._try_revoke

    def _flaky(session, api_key, match, **kwargs):
        if api_key.name == "bad":
            raise RuntimeError("db down")
        return real_try_revoke(session, api_key, match)

    monkeypatch.setattr(revocation_module, "_try_revoke", _flaky)
    with pytest.raises(revocation_module.LeakBatchIncomplete):
        revocation_module.revoke_leaked_keys(
            [_match(raw_bad), _match(raw_good)],
            session_factory=session_factory,
        )

    with session_factory() as session:
        bad_row = session.exec(
            select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_bad))
        ).first()
        good_row = session.exec(
            select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_good))
        ).first()
        assert bad_row.is_active is True
        assert good_row.is_active is False
    assert len(sent) == 1


def test_token_embedded_in_url_redacted_everywhere(session_factory, monkeypatch, caplog):
    """CodeRabbit CWE-312 on #380: a filename (or any metadata) echoing the
    token must not propagate it into audit rows, emails, or logs."""
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    leaky_url = f"https://github.com/octo/Hello-World/blob/1234/{raw}.txt"
    leaky = SecretMatch(token=raw, type="qwed_live_api_key", url=leaky_url, source="commit")
    with caplog.at_level(logging.INFO, logger="qwed_new.api.secret_revocation"):
        outcome = revocation_module.revoke_leaked_keys([leaky], session_factory=session_factory)

    assert outcome["revoked"] == 1
    # Sink logs carry counts only — the URL never reaches them at all.
    assert raw not in caplog.text
    assert len(sent) == 1
    assert raw not in sent[0][2]
    assert "[REDACTED]" in sent[0][2]
    with session_factory() as session:
        events = session.exec(
            select(SecurityEvent).where(SecurityEvent.event_type == revocation_module.REVOKED_EVENT_TYPE)
        ).all()
        assert len(events) == 1
        assert raw not in events[0].reason
        assert "[REDACTED]" in events[0].reason


def test_redact_token_empty_token_noop():
    assert revocation_module._redact_token("https://example.test/x", "") == "https://example.test/x"


def test_sanitized_copy_carries_no_plaintext_token():
    """Sentry HIGH on #380: the sanitized copy must not retain the token —
    it rides into tracebacks and error-reporter locals on downstream failure."""
    raw = "qwed_live_" + "R" * 30 + "000000"
    original = _match(raw)
    safe = revocation_module._sanitized_match(original, raw)

    assert safe.token != raw
    assert raw not in safe.model_dump_json()
    assert original.token == raw


def test_default_session_factory_constructs():
    """Covers the production factory without touching the database."""
    session = revocation_module._default_session_factory()
    try:
        assert session is not None
    finally:
        session.close()
