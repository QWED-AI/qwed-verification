"""
Tenant Context: Authentication & Authorization Middleware.

This module handles API key validation and tenant identification.
It's the "authentication layer" of the QWED OS.
"""

import hashlib
from typing import Optional
from fastapi import Header, HTTPException, Depends
from sqlmodel import Session, select
from qwed_new.core.database import get_session
from qwed_new.core.models import ApiKey, Organization

class TenantContext:
    """
    Represents the authenticated tenant (organization) for the current request.
    """
    def __init__(self, organization_id: int, organization_name: str, tier: str, api_key: str = None):
        self.organization_id = organization_id
        self.organization_name = organization_name
        self.tier = tier
        self.api_key = api_key  # Store for rate limiting

async def get_current_tenant(
    x_api_key: str = Header(..., description="API Key for authentication"),
    session: Session = Depends(get_session)
) -> TenantContext:
    """
    Dependency function to extract and validate the API key.
    Returns the authenticated tenant context.
    """
from qwed_new.auth.security import hash_api_key

# ...

    # 1. Hash the provided key
    hashed_key = hash_api_key(x_api_key)
    
    # 2. Look up API key
    statement = select(ApiKey).where(ApiKey.key_hash == hashed_key, ApiKey.is_active == True)
    api_key = session.exec(statement).first()
    
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or inactive API key"
        )
    
    # 3. Get organization
    org_statement = select(Organization).where(
        Organization.id == api_key.organization_id,
        Organization.is_active == True
    )
    organization = session.exec(org_statement).first()
    
    if not organization:
        raise HTTPException(
            status_code=403,
            detail="Organization is inactive or does not exist"
        )
    
    # Update last used timestamp (optional, maybe async in prod)
    # api_key.last_used_at = datetime.utcnow()
    # session.add(api_key)
    # session.commit()
    
    return TenantContext(
        organization_id=organization.id,
        organization_name=organization.name,
        tier=organization.tier,
        api_key=x_api_key
    )
