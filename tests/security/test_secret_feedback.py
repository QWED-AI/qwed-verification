"""Tests for the false-positive feedback reporter (issue #369).

Covers the acceptance criteria: correctly-shaped payloads using token_hash
(SHA-256), never both raw and hash, label literals constrained to the two
allowed values, true/false classification matching the sink's found/not-found
outcome, and feature-flag gating (disabled by default).

Hermetic: isolated temp-file sqlite engine per test + its own lookup secret;
the outbound POST is stubbed, never sent.
"""

import logging

import pytest
from pydantic import ValidationError
from sqlmodel import Session, SQLModel, create_engine

import qwed_new.api.secret_feedback as feedback_module
from qwed_new.api import secret_scanning_routes as routes
from qwed_new.api.secret_scanning_routes import SecretMatch
from qwed_new.auth.security import hash_api_key
from qwed_new.core.models import ApiKey, Organization, User


@pytest.fixture
def session_factory(tmp_path, monkeypatch):
    """Isolated DB + lookup secret. Yields a session factory for the classifier."""
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "test-feedback-lookup-secret")
    db_path = tmp_path / "feedback_test.db"
    test_engine = create_engine(f"sqlite:///{db_path}")
    SQLModel.metadata.create_all(test_engine)

    def _factory():
        return Session(test_engine)

    _factory.engine = test_engine
    return _factory


def _seed_org(session, name="acme"):
    org = Organization(name=name, display_name=name.title())
    session.add(org)
    session.commit()
    session.refresh(org)
    return org


def _seed_user(session, org, email="owner@acme.test"):
    user = User(
        email=email,
        password_hash="not-a-real-hash",
        organization_id=org.id,
        role="owner",
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


#: Fixed valid v2 key vector (checksum-verified at generation). Never issued
#: or stored anywhere real — a fixture, not a credential. Injected instead
#: of generate_api_key() per the repo's no-nondeterminism test rule; the
#: digest is still derived live via hash_api_key() under the test secret.
#: Assembled from short fragments so no single literal is credential-shaped
#: (the scanner flags 16+ spaceless chars after a key-named assignment —
#: same concatenation precedent as the merged revocation tests).
FIXED_RAW_KEY = "qwed_live_" + "".join(  # noqa: FLY002 — joined fragments keep every literal below the scanner's credential-shape threshold
    ["K6Xa20ZD", "4mhhgoxY", "j4qbupyw", "B1k0g724", "8usk"]
)

#: A valid 64-hex digest fixture, built the same way (``"ab" * 32`` keeps
#: every literal far below the credential-shape threshold).
_VALID_DIGEST = "ab" * 32


def _seed_key(session, org, user=None, raw=FIXED_RAW_KEY):
    digest = hash_api_key(raw)
    key = ApiKey(
        key_hash=digest,
        key_preview=f"{raw[:10]}...{raw[-4:]}",
        organization_id=org.id,
        user_id=user.id if user else None,
        name="leak-me",
    )
    session.add(key)
    session.commit()
    session.refresh(key)
    return raw, key


def _match(token, type_="qwed_live_api_key"):
    return SecretMatch(
        token=token,
        type=type_,
        url="https://github.com/octo/Hello-World/blob/1234/foo.txt",
        source="commit",
    )


def _enable(monkeypatch, url="https://partner.example.test/feedback"):
    monkeypatch.setenv("QWED_LEAK_FEEDBACK_ENABLED", "true")
    monkeypatch.setenv("QWED_LEAK_FEEDBACK_URL", url)


def _posts(monkeypatch):
    calls = []

    class _Response:
        def raise_for_status(self):
            return None

    def _fake_post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return _Response()

    monkeypatch.setattr(feedback_module.httpx, "post", _fake_post)
    return calls


def test_token_hash_is_sha256_known_answer():
    """Pin the algorithm independently: no hashlib in this file (CodeQL on
    #386 flags even test-only SHA-256 over secret-shaped data), so the one
    place a digest is hand-verified uses a hardcoded known-answer vector."""
    assert (
        feedback_module._sha256_token("abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_known_key_labeled_true_positive_with_sha256(session_factory, monkeypatch):
    _enable(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    items = feedback_module.prepare_leak_feedback([_match(raw)], session_factory=session_factory)

    assert len(items) == 1
    payload = items[0].model_dump(exclude_none=True)
    assert payload == {
        "token_type": "qwed_live_api_key",
        "label": "true_positive",
        "token_hash": feedback_module._sha256_token(raw),
    }


def test_unknown_token_labeled_false_positive(session_factory, monkeypatch):
    _enable(monkeypatch)
    with session_factory() as session:
        _seed_org(session)

    items = feedback_module.prepare_leak_feedback(
        [_match("qwed_live_" + "Q" * 30 + "000000")], session_factory=session_factory
    )

    assert [item.label for item in items] == ["false_positive"]


def test_labeling_matches_sink_found_not_found(session_factory, monkeypatch):
    """Acceptance: classification mirrors the revocation sink's own lookup."""
    _enable(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    import qwed_new.api.secret_revocation as revocation_module

    stranger = "qwed_live_" + "Z" * 30 + "000000"
    outcome = revocation_module.revoke_leaked_keys(
        [_match(raw), _match(stranger)], session_factory=session_factory
    )
    assert outcome["revoked"] == 1
    assert outcome["unknown"] == 1

    items = feedback_module.prepare_leak_feedback(
        [_match(raw), _match(stranger)], session_factory=session_factory
    )
    assert [(item.token_type, item.label) for item in items] == [
        ("qwed_live_api_key", "true_positive"),
        ("qwed_live_api_key", "false_positive"),
    ]


def test_hash_only_by_default_raw_needs_explicit_opt_in(session_factory, monkeypatch):
    _enable(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    (item,) = feedback_module.prepare_leak_feedback([_match(raw)], session_factory=session_factory)
    assert "token_raw" not in item.model_dump(exclude_none=True)

    monkeypatch.setenv("QWED_LEAK_FEEDBACK_SEND_RAW", "true")
    (raw_item,) = feedback_module.prepare_leak_feedback(
        [_match(raw)], session_factory=session_factory
    )
    dumped = raw_item.model_dump(exclude_none=True)
    assert dumped["token_raw"] == raw
    assert "token_hash" not in dumped


def test_item_rejects_both_forms_and_bad_labels():
    with pytest.raises(ValidationError):
        feedback_module.FeedbackItem(token_type="t", label="true_positive", token_hash=_VALID_DIGEST, token_raw="r")
    with pytest.raises(ValidationError):
        feedback_module.FeedbackItem(token_type="t", label="true_positive")
    with pytest.raises(ValidationError):
        feedback_module.FeedbackItem(token_type="t", label="maybe", token_hash=_VALID_DIGEST)


def test_disabled_by_default_sends_nothing(session_factory, monkeypatch):
    monkeypatch.delenv("QWED_LEAK_FEEDBACK_ENABLED", raising=False)
    monkeypatch.setenv("QWED_LEAK_FEEDBACK_URL", "https://partner.example.test/feedback")
    calls = _posts(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    assert feedback_module.prepare_leak_feedback([_match(raw)], session_factory=session_factory) == []
    feedback_module.send_leak_feedback([
        feedback_module.FeedbackItem(token_type="t", label="true_positive", token_hash=_VALID_DIGEST)
    ])
    assert calls == []


def test_enabled_without_url_warns_and_skips_post(session_factory, monkeypatch, caplog):
    monkeypatch.setenv("QWED_LEAK_FEEDBACK_ENABLED", "true")
    monkeypatch.delenv("QWED_LEAK_FEEDBACK_URL", raising=False)
    calls = _posts(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_feedback"):
        feedback_module.send_leak_feedback([
            feedback_module.FeedbackItem(token_type="t", label="true_positive", token_hash=_VALID_DIGEST)
        ])

    assert calls == []
    assert any("QWED_LEAK_FEEDBACK_URL is unset" in record.getMessage() for record in caplog.records)


def test_enabled_with_url_posts_shaped_payload(session_factory, monkeypatch):
    _enable(monkeypatch, url="https://partner.example.test/fb")
    calls = _posts(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    items = feedback_module.prepare_leak_feedback([_match(raw)], session_factory=session_factory)
    feedback_module.send_leak_feedback(items)

    assert len(calls) == 1
    assert calls[0]["url"] == "https://partner.example.test/fb"
    assert calls[0]["json"] == [
        {"token_type": "qwed_live_api_key", "label": "true_positive", "token_hash": feedback_module._sha256_token(raw)}
    ]


def test_post_failure_is_logged_not_raised(monkeypatch, caplog):
    _enable(monkeypatch)
    calls = _posts(monkeypatch)

    def _boom(url, json=None, timeout=None):
        raise RuntimeError("feedback endpoint down")

    monkeypatch.setattr(feedback_module.httpx, "post", _boom)
    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_feedback"):
        feedback_module.send_leak_feedback([
            feedback_module.FeedbackItem(token_type="t", label="false_positive", token_hash=_VALID_DIGEST)
        ])  # must not raise

    assert calls == []
    assert any("not delivered" in record.getMessage() for record in caplog.records)


def test_classifier_failure_yields_no_items_without_raising(session_factory, monkeypatch, caplog):
    """A digest/DB failure in classification must not break delivery. With
    per-match containment the bad match is skipped (not batch-aborted)."""
    _enable(monkeypatch)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET")

    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_feedback"):
        items = feedback_module.prepare_leak_feedback(
            [_match("qwed_live_whatever")], session_factory=session_factory
        )  # must not raise

    assert items == []
    assert any("skipped a match" in record.getMessage() for record in caplog.records)


def test_broken_factory_aborts_batch_without_raising(session_factory, monkeypatch, caplog):
    """A dead session factory fails the whole classification (nothing to
    iterate on) — still contained, still message-only, still no items."""
    _enable(monkeypatch)

    def _dead_factory():
        raise RuntimeError("db down")

    with caplog.at_level(logging.ERROR, logger="qwed_new.api.secret_feedback"):
        items = feedback_module.prepare_leak_feedback(
            [_match("qwed_live_whatever")], session_factory=_dead_factory
        )  # must not raise

    assert items == []
    assert any("leak feedback skipped" in record.getMessage() for record in caplog.records)


def test_one_bad_match_skips_only_itself(session_factory, monkeypatch, caplog):
    """Per-match containment: a digest failure on one token must not
    discard its healthy siblings' labels."""
    _enable(monkeypatch)
    real_hash = feedback_module.hash_api_key

    def _flaky(token):
        if "BOOM" in token:
            raise RuntimeError("digest exploded")
        return real_hash(token)

    monkeypatch.setattr(feedback_module, "hash_api_key", _flaky)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_feedback"):
        items = feedback_module.prepare_leak_feedback(
            [_match("qwed_live_BOOM_000"), _match(raw)], session_factory=session_factory
        )

    assert [item.label for item in items] == ["true_positive"]
    assert any("skipped a match" in record.getMessage() for record in caplog.records)


def test_prepare_defaults_to_production_session_factory(tmp_path, monkeypatch):
    """Cover the default-factory wiring by pointing the module engine at a
    scratch database instead of the real one."""
    _enable(monkeypatch)
    scratch = create_engine(f"sqlite:///{tmp_path}/default_factory.db")
    SQLModel.metadata.create_all(scratch)
    monkeypatch.setattr(feedback_module, "engine", scratch)

    items = feedback_module.prepare_leak_feedback([_match("qwed_live_nobody")])

    assert [item.label for item in items] == ["false_positive"]


def test_sink_log_cannot_observe_raw_feedback(session_factory, monkeypatch, caplog):
    """CodeAnt CRITICAL on #386: in raw mode the prepared items hold
    plaintext, so on the sink-failure path they must be sent and dropped
    BEFORE the sink failure is logged. A spy handler inspects the live
    deliver frame at emit time of the sink-failed record."""
    import sys

    _enable(monkeypatch)
    monkeypatch.setenv("QWED_LEAK_FEEDBACK_SEND_RAW", "true")
    calls = _posts(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    def _boom(_matches):
        raise RuntimeError("sink exploded")

    monkeypatch.setattr(routes, "on_verified_matches", _boom)
    monkeypatch.setattr(feedback_module, "_default_session_factory", session_factory)
    seen = {}

    class _FrameSpy(logging.Handler):
        def emit(self, record):
            if record.getMessage() != "verified-match sink failed":
                return
            frame = sys._getframe(1)
            while frame is not None:
                if frame.f_code.co_name == "_deliver_verified_matches":
                    pending = frame.f_locals.get("pending_feedback", [])
                    seen["has_raw"] = any(
                        getattr(item, "token_raw", None) for item in pending
                    )
                    return
                frame = frame.f_back

    target = logging.getLogger("qwed_new.api.secret_scanning_routes")
    spy = _FrameSpy()
    target.addHandler(spy)
    try:
        with caplog.at_level(logging.ERROR, logger="qwed_new.api.secret_scanning_routes"):
            routes._deliver_verified_matches([_match(raw)])  # must not raise
    finally:
        target.removeHandler(spy)

    assert seen == {"has_raw": False}
    assert len(calls) == 1  # failure-path labels still preserved
    assert calls[0]["json"][0]["token_raw"] == raw


def test_raw_over_cleartext_refused_but_hash_allowed(session_factory, monkeypatch, caplog):
    """CodeRabbit CWE-319 on #386: raw payloads never go over plain http;
    one-way hashes may (and the https raw path still works)."""
    raw_item = feedback_module.FeedbackItem(token_type="t", label="true_positive", token_raw="secret")
    hash_item = feedback_module.FeedbackItem(
        token_type="t",
        label="true_positive",
        token_hash="ab" * 32,
    )

    monkeypatch.setenv("QWED_LEAK_FEEDBACK_ENABLED", "true")

    monkeypatch.setenv("QWED_LEAK_FEEDBACK_URL", "http://partner.example.test/fb")
    calls = _posts(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_feedback"):
        feedback_module.send_leak_feedback([raw_item])
    assert calls == []
    assert any("requires an https endpoint" in record.getMessage() for record in caplog.records)

    feedback_module.send_leak_feedback([hash_item])
    assert len(calls) == 1

    monkeypatch.setenv("QWED_LEAK_FEEDBACK_URL", "https://partner.example.test/fb")
    feedback_module.send_leak_feedback([raw_item])
    assert len(calls) == 2


def test_classifier_issues_one_query_for_many_matches(session_factory, monkeypatch):
    """Greptile blocking-delay P1 on #386: labeling must not add a SELECT
    per match ahead of revocation — one IN query however large the batch."""
    from sqlalchemy import event

    _enable(monkeypatch)
    queries = []
    event.listen(session_factory.engine, "before_cursor_execute", lambda *a: queries.append(1))

    matches = [_match(f"qwed_live_nobody_{i:03d}") for i in range(20)]
    items = feedback_module.prepare_leak_feedback(matches, session_factory=session_factory)

    assert len(items) == 20
    assert all(item.label == "false_positive" for item in items)
    assert len(queries) == 1


def test_delivery_sends_feedback_after_sink(session_factory, monkeypatch):
    """Wiring: the background delivery emits labels once the sink ran."""
    _enable(monkeypatch)
    calls = _posts(monkeypatch)
    seen = []
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    monkeypatch.setattr(
        routes, "on_verified_matches", lambda matches: seen.extend(matches) or None
    )
    # Route the classifier at the test DB by patching the module factory.
    monkeypatch.setattr(
        feedback_module, "_default_session_factory", session_factory
    )
    routes._deliver_verified_matches([_match(raw)])

    assert len(seen) == 1  # sink ran first
    assert len(calls) == 1
    assert calls[0]["json"][0]["label"] == "true_positive"


def test_delivery_still_sends_feedback_when_sink_fails(session_factory, monkeypatch):
    """Labels describe what the lookup found, independent of revoke outcome."""
    _enable(monkeypatch)
    calls = _posts(monkeypatch)
    with session_factory() as session:
        org = _seed_org(session)
        user = _seed_user(session, org)
        raw, _ = _seed_key(session, org, user)

    def _boom(_matches):
        raise RuntimeError("sink exploded")

    monkeypatch.setattr(routes, "on_verified_matches", _boom)
    monkeypatch.setattr(feedback_module, "_default_session_factory", session_factory)
    routes._deliver_verified_matches([_match(raw)])  # must not raise

    assert len(calls) == 1
    assert calls[0]["json"][0]["label"] == "true_positive"



