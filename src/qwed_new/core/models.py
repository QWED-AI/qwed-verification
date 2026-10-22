from typing import Optional
from sqlmodel import Field, SQLModel
from datetime import datetime, timezone


def _utcnow() -> datetime:
    """Timezone-aware UTC now for column defaults.

    sqlmodel>=0.0.28 maps datetime columns to UTCDateTime, which rejects
    naive values (CI installs latest unpinned, currently 0.0.45). The old
    datetime.utcnow defaults broke every DB-writing test there.
    """
    return datetime.now(timezone.utc)

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
    created_at: datetime = Field(default_factory=_utcnow)

class User(SQLModel, table=True):
    """
    Users belong to an organization.
    Enhanced with RBAC (Role-Based Access Control).
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    organization_id: int = Field(foreign_key="organization.id")
    role: str = Field(default="member")  # owner, admin, member, viewer
    permissions: Optional[str] = None  # JSON string of permissions
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=_utcnow)


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
    created_at: datetime = Field(default_factory=_utcnow)
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
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

class VerificationLog(SQLModel, table=True):
    """
    Logs are scoped to organizations for data isolation.
    Each entry is HMAC-signed and hash-chained, so changes can be detected.
    The trail is a record to support audits; it does not make a system compliant.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id", index=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    query: str
    result: str  # JSON string of the result
    is_verified: bool
    domain: str
    timestamp: datetime = Field(default_factory=_utcnow)
    
    # Cryptographic audit fields
    entry_hash: Optional[str] = None  # SHA-256 hash of this entry
    hmac_signature: Optional[str] = None  # HMAC signature
    previous_hash: Optional[str] = None  # Hash of previous entry (chain)
    raw_llm_output: Optional[str] = None  # Preserve raw LLM response

    # Who wrote the row and with what (#484). Null on rows written before
    # these columns existed, and api_key_id is null when no API key made the
    # request (a user session, the audit seed). core/schema_migrations.py
    # adds both columns to an existing table at startup.
    api_key_id: int | None = None  # ApiKey.id of the key that made the request
    verifier_version: str | None = None  # qwed_new.__version__ when the row was written
    # The admission decision the route made (#307): "ADMIT" or "BLOCKED", or
    # "ADMIT" or "DENY" on /verification-context/from-diagnostic:
    # the one it returned, except on the agent route, which decides one
    # without returning it. Null when the route decides none, and on rows written
    # before the column existed. Not the verdict: a VERIFIED row can be BLOCKED.
    admission: str | None = None

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
    timestamp: datetime = Field(default_factory=_utcnow)
