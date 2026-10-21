"""
Agent Registry: Registration and management service for AI agents.

This module handles:
- Agent registration
- Authentication
- Permission management
- Activity logging
"""

import secrets
from typing import List, Optional, Tuple
from sqlalchemy import update
from sqlmodel import Session, col, select
from datetime import datetime, timezone

from qwed_new.auth.security import AGENT_TOKEN_HASH_PREFIX, hash_agent_token

from qwed_new.core.agent_models import (
    Agent, AgentPermission, AgentActivity,
    AgentType, AgentStatus
)

def _as_utc(value: datetime) -> datetime:
    """Treat a naive stored datetime as UTC so it compares with aware ones."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class AgentRegistry:
    """
    Central registry for managing AI agents.
    Similar to how an OS manages processes.
    """
    
    def __init__(self):
        pass
    
    def register_agent(
        self,
        session: Session,
        organization_id: int,
        name: str,
        agent_type: str = AgentType.AUTONOMOUS,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        max_cost_per_day: float = 100.0,
        created_by_user_id: Optional[int] = None
    ) -> Tuple[Agent, str]:
        """
        Register a new AI agent with QWED.
        
        Returns:
            (Agent object, agent_token). The token is returned once; only its
            digest is stored (#478).
        """
        # Generate secure token
        agent_token = self._generate_agent_token()

        # Create agent
        agent = Agent(
            organization_id=organization_id,
            name=name,
            agent_type=agent_type,
            description=description,
            agent_token=hash_agent_token(agent_token),
            max_cost_per_day=max_cost_per_day,
            created_by_user_id=created_by_user_id
        )
        
        session.add(agent)
        session.commit()
        session.refresh(agent)
        
        # Add default permissions
        if permissions:
            for perm in permissions:
                self.add_permission(session, agent.id, perm)
        
        return agent, agent_token
    
    def authenticate_agent(
        self,
        session: Session,
        agent_token: str
    ) -> Optional[Agent]:
        """
        Verify agent token and return agent if valid.

        The token is looked up by its digest, so a row that still holds a
        plaintext token (not yet migrated) never matches: fail closed.
        """
        if not isinstance(agent_token, str) or not agent_token:
            return None
        statement = select(Agent).where(
            Agent.agent_token == hash_agent_token(agent_token),
            Agent.status == AgentStatus.ACTIVE
        )
        agent = session.exec(statement).first()

        if agent:
            # Update last active timestamp
            agent.last_active = datetime.now(timezone.utc)
            session.add(agent)
            session.commit()
        
        return agent
    
    def add_permission(
        self,
        session: Session,
        agent_id: int,
        permission_type: str,
        resource: Optional[str] = None,
        max_uses_per_day: Optional[int] = None,
        expires_at: Optional[datetime] = None
    ) -> AgentPermission:
        """
        Grant a permission to an agent.
        """
        permission = AgentPermission(
            agent_id=agent_id,
            permission_type=permission_type,
            resource=resource,
            max_uses_per_day=max_uses_per_day,
            expires_at=expires_at
        )
        
        session.add(permission)
        session.commit()
        session.refresh(permission)
        
        return permission
    
    def check_permission(
        self,
        session: Session,
        agent_id: int,
        permission_type: str,
        resource: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if agent has a specific permission.
        
        Returns:
            (allowed: bool, reason: Optional[str])
        """
        # Get all permissions for this agent
        statement = select(AgentPermission).where(
            AgentPermission.agent_id == agent_id,
            AgentPermission.permission_type == permission_type
        )
        
        if resource:
            statement = statement.where(AgentPermission.resource == resource)
        
        permissions = session.exec(statement).all()
        
        if not permissions:
            return False, f"Agent does not have '{permission_type}' permission"
        
        # Check if any permission is valid
        for perm in permissions:
            # Check expiration
            if perm.expires_at and _as_utc(perm.expires_at) < datetime.now(timezone.utc):
                continue
            
            # Check daily usage limit
            if perm.max_uses_per_day:
                today_usage = self._count_permission_usage_today(
                    session, agent_id, permission_type
                )
                if today_usage >= perm.max_uses_per_day:
                    return False, f"Daily limit ({perm.max_uses_per_day}) exceeded for '{permission_type}'"
            
            # Permission is valid
            return True, None
        
        return False, f"All permissions for '{permission_type}' are expired or exhausted"
    
    def log_activity(
        self,
        session: Session,
        agent_id: int,
        organization_id: int,
        activity_type: str,
        description: str,
        status: str,
        input_data: Optional[str] = None,
        output_data: Optional[str] = None,
        cost: float = 0.0,
        latency_ms: Optional[float] = None,
        ip_address: Optional[str] = None
    ) -> AgentActivity:
        """
        Log an agent activity (audit trail).
        """
        activity = AgentActivity(
            agent_id=agent_id,
            organization_id=organization_id,
            activity_type=activity_type,
            description=description,
            status=status,
            input_data=input_data,
            output_data=output_data,
            cost=cost,
            latency_ms=latency_ms,
            ip_address=ip_address
        )
        
        session.add(activity)
        
        # Update agent's daily cost
        agent = session.get(Agent, agent_id)
        if agent:
            agent.current_cost_today += cost
            session.add(agent)
        
        session.commit()
        session.refresh(activity)
        
        return activity
    
    def check_budget(
        self,
        session: Session,
        agent_id: int
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if agent has budget remaining for today.
        """
        agent = session.get(Agent, agent_id)
        
        if not agent:
            return False, "Agent not found"
        
        if agent.current_cost_today >= agent.max_cost_per_day:
            return False, f"Daily budget ({agent.max_cost_per_day}) exceeded"
        
        return True, None
    
    def reset_daily_costs(self, session: Session):
        """
        Reset all agents' daily costs (should be run daily via cron).
        """
        statement = select(Agent).where(Agent.current_cost_today > 0)
        agents = session.exec(statement).all()
        
        for agent in agents:
            agent.current_cost_today = 0.0
            session.add(agent)
        
        session.commit()
    
    def suspend_agent(
        self,
        session: Session,
        agent_id: int,
        reason: str
    ):
        """
        Suspend an agent (stops it from operating).
        """
        agent = session.get(Agent, agent_id)
        if agent:
            agent.status = AgentStatus.SUSPENDED
            session.add(agent)
            session.commit()
            
            # Log suspension
            self.log_activity(
                session,
                agent_id,
                agent.organization_id,
                "suspension",
                f"Agent suspended: {reason}",
                "suspended"
            )
    
    def reissue_agent_token(self, session: Session, agent: Agent) -> str:
        """Give an agent a new token, returned once; the old one stops working.

        Optional after the #478 migration: hashing in place keeps existing
        tokens valid, but a token that sat in plaintext may also sit in a
        database backup, so its owner may want a new one.
        """
        agent_token = self._generate_agent_token()
        agent.agent_token = hash_agent_token(agent_token)
        session.add(agent)
        session.commit()
        session.refresh(agent)
        return agent_token

    def migrate_plaintext_agent_tokens(self, session: Session) -> int:
        """Hash every agent token still stored in plaintext (#478).

        Idempotent: a hashed row carries AGENT_TOKEN_HASH_PREFIX and is left
        alone, so running this again changes nothing. Existing tokens keep
        working. Returns how many rows were hashed.

        Each row is updated only if it still holds the plaintext that was
        read, so a token re-issued (or hashed by another worker) in between
        is never overwritten with the old token's digest.
        """
        statement = select(Agent.id, Agent.agent_token).where(
            ~col(Agent.agent_token).startswith(AGENT_TOKEN_HASH_PREFIX)
        )
        migrated = 0
        for agent_id, plaintext in session.exec(statement).all():
            result = session.exec(
                update(Agent)
                .where(col(Agent.id) == agent_id, col(Agent.agent_token) == plaintext)
                .values(agent_token=hash_agent_token(plaintext))
            )
            migrated += result.rowcount
        session.commit()
        return migrated

    def _generate_agent_token(self) -> str:
        """
        Generate a secure agent authentication token.
        Format: agent_<64 random hex chars>
        """
        return f"agent_{secrets.token_hex(32)}"
    
    def _count_permission_usage_today(
        self,
        session: Session,
        agent_id: int,
        permission_type: str
    ) -> int:
        """
        Count how many times agent used a permission today.
        """
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        statement = select(AgentActivity).where(
            AgentActivity.agent_id == agent_id,
            AgentActivity.activity_type.contains(permission_type),
            AgentActivity.timestamp >= today_start
        )
        
        activities = session.exec(statement).all()
        return len(activities)

# Global singleton
agent_registry = AgentRegistry()
