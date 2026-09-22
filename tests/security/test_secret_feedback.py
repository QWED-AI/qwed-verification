"""Tests for the false-positive feedback reporter (issue #369).

Covers the acceptance criteria: correctly-shaped payloads using token_hash
(SHA-256), never both raw and hash, label literals constrained to the two
allowed values, true/false classification matching the sink's found/not-found
outcome, and feature-flag gating (disabled by default).

Hermetic: isolated temp-file sqlite engine per test + its own lookup secret;
the outbound POST is stubbed, never sent.
"""

import hashlib
import logging

import pytest
from pydantic import ValidationError
from sqlmodel import Session, SQLModel, create_engine

import qwed_new.api.secret_feedback as feedback_module
from qwed_new.api import secret_scanning_routes as routes
from qwed_new.api.secret_feedback import FeedbackItem
from qwed_new.api.secret_scanning_routes import SecretMatch
from qwed_new.auth.security import generate_api_key, hash_api_key
from qwed_new.core.models import ApiKey, Organization, User


@pytest.fixture
def session_factory(tmp_path, monkeypatch):
    """Isolated DB + lookup secret. Yields a session factory for the classifier."""
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "test-feedback-lookup-secret")
    db_path = tmp_path / "feedback_test.db"
    test_engine = create_engine(f"sqlite:///{db_path}")
    SQLModel.metadata.create_all(test_engine)
    return lambda: Session(test_engine)


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


def _seed_key(session, org, user=None):
    raw, digest = generate_api_key()
    assert digest == hash_api_key(raw)
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


def _sha256(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
        "token_hash": _sha256(raw),
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
        FeedbackItem(token_type="t", label="true_positive", token_hash="h", token_raw="r")
    with pytest.raises(ValidationError):
        FeedbackItem(token_type="t", label="true_positive")
    with pytest.raises(ValidationError):
        FeedbackItem(token_type="t", label="maybe", token_hash="h")


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
        FeedbackItem(token_type="t", label="true_positive", token_hash="h")
    ])
    assert calls == []


def test_enabled_without_url_warns_and_skips_post(session_factory, monkeypatch, caplog):
    monkeypatch.setenv("QWED_LEAK_FEEDBACK_ENABLED", "true")
    monkeypatch.delenv("QWED_LEAK_FEEDBACK_URL", raising=False)
    calls = _posts(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_feedback"):
        feedback_module.send_leak_feedback([
            FeedbackItem(token_type="t", label="true_positive", token_hash="h")
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
        {"token_type": "qwed_live_api_key", "label": "true_positive", "token_hash": _sha256(raw)}
    ]


def test_post_failure_is_logged_not_raised(monkeypatch, caplog):
    _enable(monkeypatch)
    calls = _posts(monkeypatch)

    def _boom(url, json=None, timeout=None):
        raise RuntimeError("feedback endpoint down")

    monkeypatch.setattr(feedback_module.httpx, "post", _boom)
    with caplog.at_level(logging.WARNING, logger="qwed_new.api.secret_feedback"):
        feedback_module.send_leak_feedback([
            FeedbackItem(token_type="t", label="false_positive", token_hash="h")
        ])  # must not raise

    assert calls == []
    assert any("not delivered" in record.getMessage() for record in caplog.records)


def test_classifier_failure_yields_no_items_without_raising(session_factory, monkeypatch, caplog):
    """A digest/DB failure in classification must not break delivery."""
    _enable(monkeypatch)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET")

    with caplog.at_level(logging.ERROR, logger="qwed_new.api.secret_feedback"):
        items = feedback_module.prepare_leak_feedback(
            [_match("qwed_live_whatever")], session_factory=session_factory
        )  # must not raise

    assert items == []
    assert any("leak feedback skipped" in record.getMessage() for record in caplog.records)


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
