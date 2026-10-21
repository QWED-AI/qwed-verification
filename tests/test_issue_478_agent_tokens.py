"""#478: agent tokens were stored in plaintext and looked up by equality.

A read of the database exposed every agent token. Tokens are now stored as a
keyed digest (``hash_agent_token``, "hmac256:<hex>"), the same way API keys
are, and looked up by digest. A startup migration hashes the plaintext rows
in place, so existing tokens keep working; it leaves hashed rows alone, so
running it again changes nothing. Re-issuing a token is optional.

Agent timestamps are also timezone-aware now: sqlmodel 0.0.28 and later
reject naive datetimes, which made registering an agent fail on a fresh
install.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import (
    AGENT_TOKEN_HASH_PREFIX,
    generate_api_key,
    hash_agent_token,
    hash_api_key,
)
from qwed_new.core import database
from qwed_new.core.agent_models import Agent
from qwed_new.core.agent_registry import AgentRegistry
from qwed_new.core.models import ApiKey, Organization, User

registry = AgentRegistry()


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'agents.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)
    org = Organization(name="acme", display_name="Acme")
    other = Organization(name="globex", display_name="Globex")
    session.add(org)
    session.add(other)
    session.commit()
    session.refresh(org)
    session.refresh(other)
    yield SimpleNamespace(engine=engine, session=session, org=org, other=other)
    session.close()


def _plaintext_agent(db, org, token):
    # A row as written before #478: the token itself in agent_token.
    agent = Agent(organization_id=org.id, name=f"legacy-{token[-4:]}", agent_token=token)
    db.session.add(agent)
    db.session.commit()
    db.session.refresh(agent)
    return agent


# ---------------------------------------------------------------- storage

def test_registering_stores_only_the_digest(db):
    agent, token = registry.register_agent(db.session, db.org.id, "bot")

    db.session.refresh(agent)
    assert token.startswith("agent_")
    assert agent.agent_token == hash_agent_token(token)
    assert agent.agent_token.startswith(AGENT_TOKEN_HASH_PREFIX)
    assert token not in agent.agent_token


def test_the_agent_digest_is_keyed_and_separate_from_api_keys():
    token = "agent_" + "a" * 64

    assert hash_agent_token(token) == hash_agent_token(token)
    assert hash_agent_token(token) != hash_agent_token(token + "b")
    assert hash_agent_token(token).removeprefix(AGENT_TOKEN_HASH_PREFIX) != hash_api_key(token)


# ---------------------------------------------------------------- authentication

def test_the_issued_token_authenticates(db):
    agent, token = registry.register_agent(db.session, db.org.id, "bot")

    assert registry.authenticate_agent(db.session, token).id == agent.id


@pytest.mark.parametrize("presented", ["wrong", "", None, 12345])
def test_wrong_empty_or_non_string_tokens_do_not_authenticate(db, presented):
    registry.register_agent(db.session, db.org.id, "bot")

    assert registry.authenticate_agent(db.session, presented) is None


def test_the_stored_digest_is_not_a_credential(db):
    agent, _ = registry.register_agent(db.session, db.org.id, "bot")
    db.session.refresh(agent)

    assert registry.authenticate_agent(db.session, agent.agent_token) is None


def test_a_suspended_agent_does_not_authenticate(db):
    agent, token = registry.register_agent(db.session, db.org.id, "bot")
    agent.status = "suspended"
    db.session.add(agent)
    db.session.commit()

    assert registry.authenticate_agent(db.session, token) is None


def test_authenticating_records_a_timezone_aware_last_active(db):
    agent, token = registry.register_agent(db.session, db.org.id, "bot")

    registry.authenticate_agent(db.session, token)

    db.session.refresh(agent)
    assert agent.last_active is not None


# ---------------------------------------------------------------- migration

def test_a_plaintext_row_does_not_authenticate_until_it_is_migrated(db):
    token = "agent_" + "1" * 64
    _plaintext_agent(db, db.org, token)

    # Fail closed: the plaintext value is never compared directly.
    assert registry.authenticate_agent(db.session, token) is None

    assert registry.migrate_plaintext_agent_tokens(db.session) == 1

    # Hashing in place keeps the existing token working.
    assert registry.authenticate_agent(db.session, token) is not None


def test_the_migration_is_idempotent(db):
    token = "agent_" + "2" * 64
    agent = _plaintext_agent(db, db.org, token)

    assert registry.migrate_plaintext_agent_tokens(db.session) == 1
    db.session.refresh(agent)
    digest = agent.agent_token

    assert registry.migrate_plaintext_agent_tokens(db.session) == 0
    assert registry.migrate_plaintext_agent_tokens(db.session) == 0
    db.session.refresh(agent)
    assert agent.agent_token == digest == hash_agent_token(token)


def test_the_migration_hashes_only_plaintext_rows(db):
    hashed_agent, hashed_token = registry.register_agent(db.session, db.org.id, "new-bot")
    db.session.refresh(hashed_agent)
    digest_before = hashed_agent.agent_token
    legacy = [_plaintext_agent(db, db.org, "agent_" + c * 64) for c in "345"]

    assert registry.migrate_plaintext_agent_tokens(db.session) == 3

    db.session.refresh(hashed_agent)
    assert hashed_agent.agent_token == digest_before
    assert registry.authenticate_agent(db.session, hashed_token).id == hashed_agent.id
    for agent, c in zip(legacy, "345"):
        db.session.refresh(agent)
        assert agent.agent_token == hash_agent_token("agent_" + c * 64)


def test_startup_runs_the_migration(db, monkeypatch):
    token = "agent_" + "6" * 64
    agent = _plaintext_agent(db, db.org, token)
    monkeypatch.setattr(database, "engine", db.engine)

    main._migrate_agent_tokens()
    main._migrate_agent_tokens()  # a second start changes nothing

    db.session.refresh(agent)
    assert agent.agent_token == hash_agent_token(token)


# ---------------------------------------------------------------- re-issue

def test_reissuing_gives_a_new_token_and_the_old_one_stops_working(db):
    agent, old = registry.register_agent(db.session, db.org.id, "bot")

    new = registry.reissue_agent_token(db.session, agent)

    assert new != old
    assert registry.authenticate_agent(db.session, new).id == agent.id
    assert registry.authenticate_agent(db.session, old) is None


@pytest.fixture
def api(db):
    def user_with_key(org, role):
        user = User(email=f"{role}-{org.id}@test", password_hash="x", organization_id=org.id, role=role)
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        raw, digest = generate_api_key()
        db.session.add(ApiKey(key_hash=digest, key_preview=raw[:8], organization_id=org.id, user_id=user.id))
        db.session.commit()
        return raw

    keys = {role: user_with_key(db.org, role) for role in ("viewer", "member", "admin", "owner")}
    keys["other_owner"] = user_with_key(db.other, "owner")
    agent, token = registry.register_agent(db.session, db.org.id, "bot")

    main.app.dependency_overrides[main.get_session] = lambda: db.session
    client = TestClient(main.app)

    def reissue(who, agent_id=None):
        return client.post(f"/agents/{agent_id or agent.id}/token/reissue", headers={"x-api-key": keys[who]})

    yield SimpleNamespace(reissue=reissue, agent=agent, token=token)
    main.app.dependency_overrides.clear()


@pytest.mark.parametrize("who", ["member", "admin", "owner"])
def test_members_and_above_can_reissue_their_organisations_agent_token(db, api, who):
    response = api.reissue(who)

    assert response.status_code == 200
    new = response.json()["agent_token"]
    assert registry.authenticate_agent(db.session, new).id == api.agent.id
    assert registry.authenticate_agent(db.session, api.token) is None


def test_a_viewer_cannot_reissue(db, api):
    assert api.reissue("viewer").status_code == 403
    assert registry.authenticate_agent(db.session, api.token) is not None


def test_another_organisations_agent_is_404(db, api):
    assert api.reissue("other_owner").status_code == 404
    assert registry.authenticate_agent(db.session, api.token) is not None


def test_an_unknown_agent_is_404(api):
    assert api.reissue("owner", agent_id=999999).status_code == 404


# ---------------------------------------------------------------- timestamps

@pytest.mark.parametrize("expires_at, allowed", [
    (datetime.now(timezone.utc) - timedelta(days=1), False),
    (datetime.now(timezone.utc) + timedelta(days=1), True),
])
def test_permission_expiry_compares_timezone_aware_times(db, expires_at, allowed):
    agent, _ = registry.register_agent(db.session, db.org.id, "bot")
    registry.add_permission(db.session, agent.id, "send_emails", expires_at=expires_at)

    ok, _ = registry.check_permission(db.session, agent.id, "send_emails")

    assert ok is allowed


def test_activity_logging_and_daily_usage_work_with_aware_timestamps(db):
    agent, _ = registry.register_agent(db.session, db.org.id, "bot")
    registry.add_permission(db.session, agent.id, "send_emails", max_uses_per_day=1)

    registry.log_activity(db.session, agent.id, db.org.id, "send_emails", "sent", "success")
    ok, reason = registry.check_permission(db.session, agent.id, "send_emails")

    assert ok is False
    assert "Daily limit" in reason
