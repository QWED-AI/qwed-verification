"""List an organisation's agents, and read an agent's activity (#527).

There was no route that listed the agents of an organisation, and
``GET /agents/{agent_id}/activity`` took only the agent's own token, so an
owner could read neither and qwed-dashboard could show an agent only if its
id was already known.

``GET /agents`` lists them for an owner or admin (API key or signed-in
session, as the compliance routes since #485), never with a token.
``GET /agents/{agent_id}/activity`` still takes the agent's token, and now
also an owner's or admin's credential for an agent of their organisation.
Kept out of api/main.py, which is at the size limit of the deterministic
security scan; the activity route moves here from it.
"""

import asyncio
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Security
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlmodel import Session, select

from qwed_new.api.admin_auth import AdminContext, bearer_scheme, require_admin_role
from qwed_new.auth.middleware import api_key_header
from qwed_new.core.agent_models import Agent, AgentActivity
from qwed_new.core.agent_registry import agent_registry
from qwed_new.core.audit_export import as_utc
from qwed_new.core.database import get_session

router = APIRouter(prefix="/agents", tags=["Agents"])

# Owners and admins, with an API key or a signed-in session. The activity
# route calls the check itself, only when no agent token is sent.
_admin_or_session = require_admin_role(["owner", "admin"], allow_session=True)
_REQUIRE_ADMIN_OR_SESSION = Depends(_admin_or_session)
_SESSION = Depends(get_session)
_AGENT_TOKEN = Header(None, description="The agent's own token. When sent, it alone decides access.")
_API_KEY = Security(api_key_header)
_BEARER = Security(bearer_scheme)
_LIMIT = Query(20, ge=1, le=200)
# Largest id an SQL BIGINT holds, as for API key ids in auth/routes.py: a
# larger id would overflow the lookup and fail with a server error, not 404.
_MAX_AGENT_ID = 2**63 - 1


class AgentSummary(BaseModel):
    id: int
    name: str
    type: str
    status: str  # active, suspended or deactivated
    created_at: datetime
    last_active: datetime | None


@router.get(
    "",
    response_model=list[AgentSummary],
    responses={
        401: {"description": "No API key or bearer token"},
        403: {"description": "Not an owner or admin, or an inactive user, organisation or key"},
    },
)
def list_agents(
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
    session: Session = _SESSION,
) -> list[dict[str, Any]]:
    """The agents of the caller's organisation, oldest first. Own organisation only.

    Every status is listed, so a suspended or deactivated agent shows as
    such. The agent token is never returned: only its digest is stored, and
    it is shown once, at registration or reissue.
    """
    agents = session.exec(
        select(Agent)
        .where(Agent.organization_id == ctx.organization_id)
        .order_by(Agent.created_at, Agent.id)
    ).all()
    return [
        {
            "id": agent.id,
            "name": agent.name,
            "type": agent.agent_type,
            "status": agent.status,
            "created_at": as_utc(agent.created_at),
            "last_active": as_utc(agent.last_active),
        }
        for agent in agents
    ]


def _org_agent(session: Session, agent_id: int, organization_id: int) -> Agent | None:
    """The agent with this id in this organisation, or None for any other id."""
    if not 1 <= agent_id <= _MAX_AGENT_ID:
        return None
    agent = session.get(Agent, agent_id)
    return agent if agent is not None and agent.organization_id == organization_id else None


def _activities(session: Session, agent_id: int, limit: int) -> list[AgentActivity]:
    """The agent's newest activities, newest first by time and then id."""
    return list(session.exec(
        select(AgentActivity)
        .where(AgentActivity.agent_id == agent_id)
        .order_by(AgentActivity.timestamp.desc(), AgentActivity.id.desc())
        .limit(limit)
    ).all())


@router.get(
    "/{agent_id}/activity",
    responses={
        401: {"description": "An invalid agent token, or no credential at all"},
        403: {"description": "Not an owner or admin, or an inactive user, organisation or key"},
        404: {"description": "No such agent in the caller's organisation"},
    },
)
async def get_agent_activity(
    agent_id: int,
    limit: int = _LIMIT,
    x_agent_token: str | None = _AGENT_TOKEN,
    x_api_key: str | None = _API_KEY,
    bearer: HTTPAuthorizationCredentials | None = _BEARER,
    session: Session = _SESSION,
) -> dict[str, Any]:
    """An agent's activity, newest first.

    With ``x-agent-token`` the agent reads its own activity, as before: the
    token must be the active agent's own, or the request is 401, whatever
    else is sent. Without it, an owner or admin (API key or signed-in
    session) reads the activity of an agent of their organisation; another
    organisation's agent, one that does not exist, or an id out of range,
    is 404. The database work runs in a worker thread, one step at a time on
    the request's session, so it does not block the event loop.
    """
    if x_agent_token is not None:
        agent = await asyncio.to_thread(agent_registry.authenticate_agent, session, x_agent_token)
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
    else:
        ctx = await _admin_or_session(x_api_key=x_api_key, bearer=bearer, session=session)
        agent = await asyncio.to_thread(_org_agent, session, agent_id, ctx.organization_id)
        if agent is None:
            # 404, not 403: do not confirm that an agent id in another
            # organisation exists.
            raise HTTPException(status_code=404, detail="Agent not found")

    activities = await asyncio.to_thread(_activities, session, agent_id, limit)

    return {
        "agent_id": agent_id,
        "agent_name": agent.name,
        "total_activities": len(activities),
        "current_cost_today": agent.current_cost_today,
        "max_cost_per_day": agent.max_cost_per_day,
        "activities": [
            {
                "type": act.activity_type,
                "description": act.description,
                "status": act.status,
                "cost": act.cost,
                "timestamp": as_utc(act.timestamp).isoformat(),
            }
            for act in activities
        ],
    }
