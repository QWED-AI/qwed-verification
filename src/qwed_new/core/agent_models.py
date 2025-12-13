"""
Agent Models: Database schema for AI Agent governance.

This module defines models for:
- Agent registration
- Permission management
- Activity logging
- Tool call tracking
"""

from typing import Optional, List
from sqlmodel import Field, SQLModel, JSON, Column
from datetime import datetime
from enum import Enum

class AgentType(str, Enum):
    """Types of AI agents."""
    AUTONOMOUS = "autonomous"  # Fully autonomous (AutoGPT-style)
    SEMI_AUTONOMOUS = "semi_autonomous"  # Requires approval for critical actions
    ASSISTANT = "assistant"  # Human-in-the-loop

class AgentStatus(str, Enum):
    """Agent lifecycle status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"

class Agent(SQLModel, table=True):
    """
    Represents an AI agent registered with QWED.
    Each agent belongs to an organization and has specific permissions.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id", index=True)
    
    # Agent Identity
    name: str = Field(index=True)  # E.g., "CustomerSupportBot"
    agent_type: str = Field(default=AgentType.AUTONOMOUS)
    description: Optional[str] = None
    
    # Authentication
    agent_token: str = Field(unique=True, index=True)  # Like API key but for agents
    
    # Status & Limits
    status: str = Field(default=AgentStatus.ACTIVE)
    max_cost_per_day: float = Field(default=100.0)  # Budget limit
    current_cost_today: float = Field(default=0.0)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_active: Optional[datetime] = None
    created_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")

class AgentPermission(SQLModel, table=True):
    """
    Defines what an agent is allowed to do.
    Permissions are scoped to specific actions/resources.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    agent_id: int = Field(foreign_key="agent.id", index=True)
    
    # Permission Details
    permission_type: str = Field(index=True)  # E.g., "read_database", "send_emails"
    resource: Optional[str] = None  # Specific resource (e.g., "customer_table")
    
    # Constraints
    max_uses_per_day: Optional[int] = None  # Rate limit per permission
    expires_at: Optional[datetime] = None  # Temporary permissions
    
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AgentActivity(SQLModel, table=True):
    """
    Audit log of all agent actions.
    Every request, tool call, or decision is logged here.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    agent_id: int = Field(foreign_key="agent.id", index=True)
    organization_id: int = Field(foreign_key="organization.id", index=True)
    
    # Activity Details
    activity_type: str = Field(index=True)  # "verification_request", "tool_call", "decision"
    description: str  # What the agent did
    
    # Request Context
    input_data: Optional[str] = None  # JSON string of input
    output_data: Optional[str] = None  # JSON string of output
    
    # Status & Cost
    status: str  # "success", "blocked", "failed"
    cost: float = Field(default=0.0)  # Cost of this action
    latency_ms: Optional[float] = None
    
    # Audit Trail
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    ip_address: Optional[str] = None

class ToolCall(SQLModel, table=True):
    """
    Specific tracking for tool/API calls made by agents.
    More detailed than AgentActivity for tool usage.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    agent_id: int = Field(foreign_key="agent.id", index=True)
    activity_id: Optional[int] = Field(foreign_key="agentactivity.id")
    
    # Tool Details
    tool_name: str = Field(index=True)  # E.g., "send_email", "database_query"
    tool_params: str = Field(sa_column=Column(JSON))  # JSON params
    
    # Approval & Execution
    approved: bool = Field(default=False)
    approved_by: Optional[str] = None  # "automatic", "user:{user_id}", "policy"
    executed: bool = Field(default=False)
    result: Optional[str] = None
    
    # Risk Assessment
    risk_score: float = Field(default=0.0)  # 0.0 = safe, 1.0 = dangerous
    blocked_reason: Optional[str] = None
    
    timestamp: datetime = Field(default_factory=datetime.utcnow)
