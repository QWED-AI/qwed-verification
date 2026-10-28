"""#527: list an organisation's agents, and read an agent's activity as an owner.

There was no route that listed an organisation's agents, and
``GET /agents/{agent_id}/activity`` took only the agent's own token
(``x-agent-token``), so an owner could not read an agent's activity.

``GET /agents`` lists them for an owner or admin, with an API key or a
signed-in session, and never returns a token. The activity route still takes
the agent's token, and now also an owner's or admin's credential for an agent
of their organisation.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import agent_admin_routes, main
from qwed_new.auth.security import (
    create_access_token,
    generate_api_key,
    hash_agent_token,
)
from qwed_new.core.agent_models import Agent, AgentActivity
from qwed_new.core.models import ApiKey, Organization, User

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
ROLES = ("owner", "admin", "member", "viewer")


@pytest.fixture
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'agents527.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    def key_for(u):
        raw, digest = generate_api_key()
        add(ApiKey(key_hash=digest, key_preview=raw[:8], organization_id=u.organization_id, user_id=u.id))
        return raw

    def agent(org, name, hours=0, status="active"):
        token = f"agent_{name}_token"
        row = add(Agent(organization_id=org.id, name=name, agent_token=hash_agent_token(token),
                        status=status, created_at=T0 + timedelta(hours=hours)))
        return row, token

    def activity(row, hours, status="success"):
        return add(AgentActivity(agent_id=row.id, organization_id=row.organization_id,
                                 activity_type="verification_request", description=f"at {hours}h",
                                 status=status, timestamp=T0 + timedelta(hours=hours)))

    acme = add(Organization(name="acme", display_name="Acme"))
    globex = add(Organization(name="globex", display_name="Globex"))
    users = {role: add(User(email=f"{role}@acme.example.com", password_hash="x",
                            organization_id=acme.id, role=role)) for role in ROLES}
    outsider = add(User(email="owner@globex.example.com", password_hash="x", organization_id=globex.id, role="owner"))

    # Created out of id order, so the list order is by creation time.
    bot, bot_token = agent(acme, "support-bot", hours=2)
    old, _ = agent(acme, "old-bot", hours=0, status="suspended")
    foreign, foreign_token = agent(globex, "globex-bot", hours=1)

    main.app.dependency_overrides[main.get_session] = lambda: session
    yield SimpleNamespace(
        session=session, acme=acme, globex=globex, users=users, outsider=outsider,
        bot=bot, bot_token=bot_token, old=old, foreign=foreign, foreign_token=foreign_token,
        key_for=key_for, activity=activity, client=TestClient(main.app),
    )
    main.app.dependency_overrides.clear()
    session.close()


def _bearer(u):
    return {"Authorization": f"Bearer {create_access_token({'sub': str(u.id)})}"}


def _activity(env, agent_id, headers, query=""):
    return env.client.get(f"/agents/{agent_id}/activity{query}", headers=headers)


# ---------------------------------------------------------------- GET /agents

@pytest.mark.parametrize("who", ["owner", "admin"])
def test_an_owner_or_admin_session_lists_the_organisations_agents(env, who):
    response = env.client.get("/agents", headers=_bearer(env.users[who]))

    assert response.status_code == 200
    assert response.json() == [
        {"id": env.old.id, "name": "old-bot", "type": "autonomous", "status": "suspended",
         "created_at": "2026-01-01T00:00:00Z", "last_active": None},
        {"id": env.bot.id, "name": "support-bot", "type": "autonomous", "status": "active",
         "created_at": "2026-01-01T02:00:00Z", "last_active": None},
    ]


def test_no_token_or_token_digest_is_ever_listed(env):
    text = env.client.get("/agents", headers=_bearer(env.users["owner"])).text

    assert "token" not in text
    assert hash_agent_token(env.bot_token) not in text


def test_an_owner_api_key_lists_them_too(env):
    response = env.client.get("/agents", headers={"x-api-key": env.key_for(env.users["owner"])})

    assert [a["name"] for a in response.json()] == ["old-bot", "support-bot"]


def test_another_organisations_owner_sees_only_their_agents(env):
    response = env.client.get("/agents", headers=_bearer(env.outsider))

    assert [a["name"] for a in response.json()] == ["globex-bot"]


@pytest.mark.parametrize("who", ["member", "viewer"])
def test_a_member_or_viewer_cannot_list_agents(env, who):
    assert env.client.get("/agents", headers=_bearer(env.users[who])).status_code == 403


def test_listing_without_a_credential_is_401(env):
    assert env.client.get("/agents").status_code == 401


# ---------------------------------------------------------------- activity, as an owner

@pytest.mark.parametrize("who", ["owner", "admin"])
def test_an_owner_or_admin_session_reads_an_agents_activity(env, who):
    env.activity(env.bot, 3)
    env.activity(env.bot, 5, status="blocked")
    env.activity(env.old, 4)

    response = _activity(env, env.bot.id, _bearer(env.users[who]))

    assert response.status_code == 200
    body = response.json()
    assert body["agent_id"] == env.bot.id
    assert body["agent_name"] == "support-bot"
    # Newest first, this agent's only, with the UTC offset.
    assert [(a["status"], a["timestamp"]) for a in body["activities"]] == [
        ("blocked", "2026-01-01T05:00:00+00:00"),
        ("success", "2026-01-01T03:00:00+00:00"),
    ]


def test_an_owner_api_key_reads_activity_too(env):
    env.activity(env.bot, 3)

    response = _activity(env, env.bot.id, {"x-api-key": env.key_for(env.users["owner"])})

    assert response.status_code == 200
    assert body_len(response) == 1


def body_len(response):
    return len(response.json()["activities"])


@pytest.mark.parametrize("agent", ["foreign", "missing"])
def test_another_organisations_agent_or_a_missing_one_is_404(env, agent):
    agent_id = env.foreign.id if agent == "foreign" else 999_999

    assert _activity(env, agent_id, _bearer(env.users["owner"])).status_code == 404


@pytest.mark.parametrize("who", ["member", "viewer"])
def test_a_member_or_viewer_cannot_read_activity(env, who):
    assert _activity(env, env.bot.id, _bearer(env.users[who])).status_code == 403


def test_reading_activity_without_a_credential_is_401(env):
    assert _activity(env, env.bot.id, {}).status_code == 401


def test_an_inactive_owner_is_refused(env):
    owner = env.users["owner"]
    owner.is_active = False
    env.session.add(owner)
    env.session.commit()

    assert _activity(env, env.bot.id, _bearer(owner)).status_code == 403


# ---------------------------------------------------------------- activity, as the agent

def test_the_agent_still_reads_its_own_activity_with_its_token(env):
    env.activity(env.bot, 3)

    response = _activity(env, env.bot.id, {"x-agent-token": env.bot_token})

    assert response.status_code == 200
    assert body_len(response) == 1


def test_a_sent_agent_token_alone_decides_access(env):
    # Another agent's token is refused even beside an owner's session: the
    # agent path does not fall through to the owner path.
    both = {"x-agent-token": env.foreign_token, **_bearer(env.users["owner"])}

    assert _activity(env, env.bot.id, both).status_code == 401
    assert _activity(env, env.bot.id, {"x-agent-token": "agent_nope"}).status_code == 401


def test_a_suspended_agents_token_is_refused(env):
    assert _activity(env, env.old.id, {"x-agent-token": "agent_old-bot_token"}).status_code == 401


# ---------------------------------------------------------------- limit and OpenAPI

def test_the_limit_is_bounded_and_applied(env):
    for hours in range(3, 8):
        env.activity(env.bot, hours)
    owner = _bearer(env.users["owner"])

    assert body_len(_activity(env, env.bot.id, owner, "?limit=2")) == 2
    assert _activity(env, env.bot.id, owner, "?limit=0").status_code == 422
    assert _activity(env, env.bot.id, owner, "?limit=201").status_code == 422


def test_openapi_lists_both_credentials_for_both_routes(env):
    spec = env.client.get("/openapi.json").json()

    for path in ("/agents", "/agents/{agent_id}/activity"):
        security = spec["paths"][path]["get"].get("security", [])
        assert {"APIKeyHeader": []} in security, path
        assert {"SessionBearer": []} in security, path
    params = {p["name"] for p in spec["paths"]["/agents/{agent_id}/activity"]["get"]["parameters"]}
    assert "x-agent-token" in params


def test_the_activity_route_moved_out_of_main():
    routes = {(r.path, tuple(sorted(r.methods))) for r in main.app.routes if hasattr(r, "methods")}
    assert ("/agents/{agent_id}/activity", ("GET",)) in routes
    assert agent_admin_routes.get_agent_activity.__module__ == "qwed_new.api.agent_admin_routes"
