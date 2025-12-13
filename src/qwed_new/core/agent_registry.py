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
from sqlmodel import Session, select
from datetime import datetime, timedelta

from qwed_new.core.agent_models import (
    Agent, AgentPermission, AgentActivity, ToolCall,
    AgentType, AgentStatus
)

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
            (Agent object, agent_token)
        """
        # Generate secure token
        agent_token = self._generate_agent_token()
        
        # Create agent
        agent = Agent(
            organization_id=organization_id,
            name=name,
            agent_type=agent_type,
            description=description,
            agent_token=agent_token,
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
        """
        statement = select(Agent).where(
            Agent.agent_token == agent_token,
            Agent.status == AgentStatus.ACTIVE
        )
        agent = session.exec(statement).first()
        
        if agent:
            # Update last active timestamp
            agent.last_active = datetime.utcnow()
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
            if perm.expires_at and perm.expires_at < datetime.utcnow():
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
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        statement = select(AgentActivity).where(
            AgentActivity.agent_id == agent_id,
            AgentActivity.activity_type.contains(permission_type),
            AgentActivity.timestamp >= today_start
        )
        
        activities = session.exec(statement).all()
        return len(activities)

# Global singleton
agent_registry = AgentRegistry()
