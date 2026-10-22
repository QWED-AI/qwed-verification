"""
Tenant Context: Authentication & Authorization Middleware.

This module handles API key validation and tenant identification.
It's the "authentication layer" of the QWED OS.
"""

from fastapi import Depends, Header, HTTPException
from sqlmodel import Session, select

from qwed_new.auth.security import hash_api_key, is_api_key_live, validate_api_key_format
from qwed_new.core.database import get_session
from qwed_new.core.api_key_usage import record_api_key_use
from qwed_new.core.models import ApiKey, Organization
from qwed_new.core.request_caller import set_request_api_key_id


class TenantContext:
    """
    Represents the authenticated tenant (organization) for the current request.
    """
    def __init__(
        self,
        organization_id: int,
        organization_name: str,
        tier: str,
        api_key: str = None,
        api_key_id: int | None = None,
    ):
        self.organization_id = organization_id
        self.organization_name = organization_name
        self.tier = tier
        self.api_key = api_key  # Store for rate limiting
        self.api_key_id = api_key_id  # ApiKey.id, recorded on audit rows (#484)

async def get_current_tenant(
    x_api_key: str = Header(..., description="API Key for authentication"),
    session: Session = Depends(get_session)
) -> TenantContext:
    """
    Dependency function to extract and validate the API key.
    Returns the authenticated tenant context.
    """
    # Offline format pre-filter (issue #366): reject keys that can never be
    # valid before they cost an HMAC + DB lookup on this unauthenticated
    # path. Both v1 and v2 shapes pass; anything else fails closed.
    if validate_api_key_format(x_api_key) == "invalid":
        raise HTTPException(
            status_code=401,
            detail="Invalid or inactive API key"
        )

    # 1. Hash the provided key
    hashed_key = hash_api_key(x_api_key)
    
    # 2. Look up API key. is_active is a cheap indexed pre-filter; is_api_key_live
    # is the authoritative gate — an expired or revoked key is NOT a usable
    # credential even though is_active stays True after expiry (#389, CWE-613).
    statement = select(ApiKey).where(ApiKey.key_hash == hashed_key, ApiKey.is_active.is_(True))
    api_key = session.exec(statement).first()

    if not api_key or not is_api_key_live(api_key):
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
    
    # Only after every check: a key that was refused is never recorded (#484).
    set_request_api_key_id(api_key.id)

    tenant = TenantContext(
        organization_id=organization.id,
        organization_name=organization.name,
        tier=organization.tier,
        api_key=x_api_key,
        api_key_id=api_key.id,
    )
    # Last, so a refused key is never marked as used (#486).
    record_api_key_use(session, api_key)
    return tenant
