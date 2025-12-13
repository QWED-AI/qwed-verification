from typing import Optional
from sqlmodel import Field, SQLModel
from datetime import datetime

class Organization(SQLModel, table=True):
    """
    Represents a tenant (company, team, or organization).
    Each organization has isolated resources and API keys.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    display_name: str
    tier: str = Field(default="free")  # free, pro, enterprise
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class User(SQLModel, table=True):
    """
    Users belong to an organization.
    Enhanced with RBAC (Role-Based Access Control).
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    organization_id: int = Field(foreign_key="organization.id")
    role: str = Field(default="member")  # admin, member, viewer
    permissions: Optional[str] = None  # JSON string of permissions
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ApiKey(SQLModel, table=True):
    """
    API keys are scoped to organizations.
    We store only the hash of the key for security.
    Enhanced with expiration and rotation policies.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    key_hash: str = Field(index=True, unique=True)
    key_preview: str  # e.g. "qwed_live_...1234"
    organization_id: int = Field(foreign_key="organization.id")
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    name: Optional[str] = Field(default=None)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None  # Key expiration
    rotation_required: bool = Field(default=False)  # Flag for mandatory rotation


class ResourceQuota(SQLModel, table=True):
    """
    Per-tenant resource limits.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id", unique=True)
    max_requests_per_day: int = Field(default=1000)
    max_requests_per_minute: int = Field(default=60)
    max_concurrent_requests: int = Field(default=10)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class VerificationLog(SQLModel, table=True):
    """
    Logs are scoped to organizations for data isolation.
    Enhanced with cryptographic audit trail for SOC 2 / GDPR compliance.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id", index=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    query: str
    result: str  # JSON string of the result
    is_verified: bool
    domain: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Cryptographic audit fields
    entry_hash: Optional[str] = None  # SHA-256 hash of this entry
    hmac_signature: Optional[str] = None  # HMAC signature
    previous_hash: Optional[str] = None  # Hash of previous entry (chain)
    raw_llm_output: Optional[str] = None  # Preserve raw LLM response

class SecurityEvent(SQLModel, table=True):
    """
    Security audit log for tracking blocked/sanitized requests.
    OWASP LLM compliance - full audit trail of security events.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id", index=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    event_type: str  # BLOCKED, SANITIZED, INJECTION_DETECTED, etc.
    query: str  # Redacted or truncated query
    reason: str  # Why it was blocked/flagged
    security_layer: Optional[str] = None  # Which layer caught it (e.g., "Base64 Detection")
    severity: str = Field(default="medium")  # low, medium, high, critical
    timestamp: datetime = Field(default_factory=datetime.utcnow)
