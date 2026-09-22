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
        key.revoked_at = datetime.now(timezone.utc)
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


def test_resolve_failure_revokes_without_error(session_factory, monkeypatch, caplog):
    """Greptile T-Rex on #380: owner resolution raising after commit must
    not misreport completed enforcement as failed — best effort, no error.
    Greptile P1 on #380: a later key in the same batch must still revoke,
    proving the poisoned transaction was rolled back before continuing."""
    real_resolve = revocation_module._resolve_owner_email

    def _boom_on_bad(session, api_key):
        if api_key.name == "bad-resolve":
            raise RuntimeError("db down")
        return real_resolve(session, api_key)

    monkeypatch.setattr(revocation_module, "_resolve_owner_email", _boom_on_bad)
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw_bad, _ = _seed_key(session, org, user, name="bad-resolve")
        raw_good, _ = _seed_key(session, org, user, name="good")

    with caplog.at_level(logging.ERROR, logger="qwed_new.api.secret_revocation"):
        outcome = revocation_module.revoke_leaked_keys(
            [_match(raw_bad), _match(raw_good)], session_factory=session_factory
        )

    assert outcome == {"revoked": 2, "already_revoked": 0, "unknown": 0, "errors": 0}
    assert len(sent) == 1  # only the resolvable owner is notified
    assert _fresh_key_row(session_factory, hash_api_key(raw_bad)).is_active is False
    assert _fresh_key_row(session_factory, hash_api_key(raw_good)).is_active is False


def test_redaction_expansion_clamped_siblings_still_revoke(session_factory, monkeypatch):
    """Sentry LOW on #380: a short token repeated through a metadata field
    expands under redaction ("a"*64 -> "[REDACTED]"*64); the sanitized copy
    must clamp to the field cap instead of raising ValidationError and
    aborting the batch around a legitimate sibling key."""
    sent = _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw_good, _ = _seed_key(session, org, user, name="good")

    evil = SecretMatch(
        token="a",
        type="qwed_live_api_key",
        url="https://x.test/a",
        source="a" * 64,
    )
    outcome = revocation_module.revoke_leaked_keys(
        [_match(raw_good), evil], session_factory=session_factory
    )

    assert outcome == {"revoked": 1, "already_revoked": 0, "unknown": 1, "errors": 0}
    assert len(sent) == 1
    assert _fresh_key_row(session_factory, hash_api_key(raw_good)).is_active is False


def test_sanitize_failure_scrubs_sanitize_frame(session_factory, monkeypatch):
    """Sentry MEDIUM on #380: if _sanitized_match itself raises, its frame —
    which binds the plaintext `token` and the token-bearing `match` — must
    be scrubbed like the other token-holding frames, not left in the
    traceback for a locals-capturing reporter. The stub keeps real
    `model_fields` so the redaction helper runs and the explosion happens
    inside the `SecretMatch(...)` constructor call — i.e. inside the
    sanitize frame under test."""
    real_model = revocation_module.SecretMatch

    class _BoomModel:
        model_fields = real_model.model_fields

        def __init__(self, **kwargs):
            raise RuntimeError("sanitize exploded")

    monkeypatch.setattr(revocation_module, "SecretMatch", _BoomModel)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    batch = [_match(raw)]
    with pytest.raises(RuntimeError, match="sanitize exploded") as excinfo:
        revocation_module.revoke_leaked_keys(batch, session_factory=session_factory)

    frames = []
    seen = set()
    error = excinfo.value
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        tb = error.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_name == "_sanitized_match":
                frames.append(tb.tb_frame)
            tb = tb.tb_next
        error = error.__cause__ or error.__context__
    assert frames, "expected a _sanitized_match frame in the traceback"
    for frame in frames:
        assert "token" not in frame.f_locals
        assert "match" not in frame.f_locals
        assert all(raw not in str(value) for value in frame.f_locals.values())


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
        # Compare as instants: UTCDateTime (new sqlmodel) preserves tzinfo
        # on round-trip while naive-column storage (old sqlmodel) drops it;
        # attaching UTC to a naive read-back is exact either way.
        assert key_b.revoked_at.replace(tzinfo=timezone.utc) == fixed_now
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
    batch = [_match(raw_bad), _match(raw_good)]
    with pytest.raises(revocation_module.LeakBatchIncomplete):
        revocation_module.revoke_leaked_keys(batch, session_factory=session_factory)

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


def _traceback_frames_blob(exc):
    """Render every frame's locals across the full exception chain.

    Only frames from THIS sink module are checked: the endpoint and
    delivery frames upstream legitimately hold the raw batch (pre-existing
    #374 surface, covered by deployment-level scrubbing), while every
    frame in this module must be token-free. Returns (blob, frame_count).
    """
    parts = []
    count = 0
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        tb = current.__traceback__
        while tb is not None:
            # Production sink frames only: the filename must be the module
            # itself (api/secret_revocation.py), not the test module
            # (test_secret_revocation.py) whose locals legitimately hold
            # the raw token to drive the test.
            filename = str(tb.tb_frame.f_code.co_filename).replace("\\", "/")
            if filename.endswith("api/secret_revocation.py"):
                parts.append(str(tb.tb_frame.f_locals))
                count += 1
            tb = tb.tb_next
        current = current.__cause__ or current.__context__
    return "\n".join(parts), count


def test_traceback_frames_carry_no_plaintext_on_digest_failure(session_factory, monkeypatch):
    """CodeRabbit CWE-532 on #380: a traceback keeps every frame it passes
    through, so cleaning caller frames is insufficient — the helper frame
    scrubs itself before re-raising (see _stage_batch)."""
    _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET")
    batch = [_match(raw)]
    try:
        revocation_module.revoke_leaked_keys(batch, session_factory=session_factory)
        raised = None
    except RuntimeError as exc:
        raised = exc
    assert raised is not None
    blob, frame_count = _traceback_frames_blob(raised)
    # Non-vacuous: sink frames were actually walked (outcome dict renders).
    assert frame_count >= 1
    assert "'revoked'" in blob
    assert raw not in blob


def test_digest_failure_scrubs_callee_frames(session_factory, monkeypatch):
    """Greptile T-Rex on #380: hash_api_key's own frame binds the token as
    ``api_key`` — scrubbed before logging so capture sees nothing."""
    _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET")
    batch = [_match(raw)]
    try:
        revocation_module.revoke_leaked_keys(batch, session_factory=session_factory)
        raised = None
    except RuntimeError as exc:
        raised = exc
    assert raised is not None
    callee_frames = []
    seen = set()
    current = raised
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        tb = current.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_name == "hash_api_key":
                callee_frames.append(tb.tb_frame.f_locals)
            tb = tb.tb_next
        current = current.__cause__ or current.__context__
    assert callee_frames, "expected the hasher frame in the chain"
    for locals_map in callee_frames:
        assert locals_map.get("api_key", "") != raw


def test_traceback_frames_carry_no_plaintext_on_row_failure(session_factory, monkeypatch):
    """Same guarantee for the main-loop failure path (DB error mid-batch)."""
    _mails(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _key = _seed_key(session, org, user)

    real_try_revoke = revocation_module._try_revoke

    def _flaky_once(session, api_key, match, **kwargs):
        if not _flaky_once.fired:
            _flaky_once.fired = True
            raise RuntimeError("db down")
        return real_try_revoke(session, api_key, match)

    _flaky_once.fired = False
    monkeypatch.setattr(revocation_module, "_try_revoke", _flaky_once)
    try:
        revocation_module.revoke_leaked_keys([_match(raw)], session_factory=session_factory)
        raised = None
    except revocation_module.LeakBatchIncomplete as exc:
        raised = exc
    assert raised is not None
    blob, frame_count = _traceback_frames_blob(raised)
    assert frame_count >= 1
    assert raw not in blob
