"""
Authentication models for QWED Enterprise Portal.
Includes User, Organization, and APIKey models for multi-tenant auth.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr
from enum import Enum

class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"

class SubscriptionTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

# Database Models (for SQLite/PostgreSQL)
class Organization(BaseModel):
    id: str
    name: str
    subscription_tier: SubscriptionTier = SubscriptionTier.FREE
    created_at: datetime
    
class User(BaseModel):
    id: str
    email: EmailStr
    password_hash: str
    org_id: str
    role: UserRole = UserRole.MEMBER
    created_at: datetime
    is_active: bool = True

class APIKey(BaseModel):
    id: str
    key_hash: str  # Never store plaintext keys
    user_id: str
    org_id: str
    name: str  # User-friendly name like "Production Key"
    created_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

# Request/Response Schemas
class SignUpRequest(BaseModel):
    email: EmailStr
    password: str
    organization_name: str

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class APIKeyCreateRequest(BaseModel):
    name: str

class APIKeyResponse(BaseModel):
    id: str
    name: str
    key: str  # Only shown once on creation
    created_at: datetime

class APIKeyListItem(BaseModel):
    id: str
    name: str
    key_preview: str  # e.g., "qwed_live_****1234"
    created_at: datetime
    last_used_at: Optional[datetime]
    is_revoked: bool
