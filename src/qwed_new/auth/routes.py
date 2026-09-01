"""
Authentication routes for QWED Enterprise Portal.
"""
import asyncio
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from typing import Optional, List
from datetime import datetime
from sqlmodel import Session, select

from qwed_new.core.database import get_session
from qwed_new.core.models import User, Organization, ApiKey
from qwed_new.core.rate_limiter import check_auth_rate_limit
from .models import (
    SignUpRequest, SignInRequest, TokenResponse,
    APIKeyCreateRequest, APIKeyResponse, APIKeyListItem
)
from .security import (
    hash_password, verify_password, create_access_token,
    generate_api_key, mask_api_key, decode_access_token
)

router = APIRouter(prefix="/auth", tags=["authentication"])

# bcrypt cost-12 verify burns ~270 ms on an unknown email and returns in the
# same time for a known one, equalizing the email-enumeration timing oracle
# (issue #334). Initialized lazily so module import stays cheap. The lazy
# memo is not lock-guarded: a concurrent first wave re-hashes a few dummies —
# bounded by the per-IP throttle and strictly one-time — which is cheaper
# than serializing every unknown-email signin on a lock.
_dummy_password_hash: Optional[str] = None


async def _burn_one_bcrypt(password: str) -> None:
    """Run one bcrypt verify against a throwaway hash (timing equalizer)."""
    global _dummy_password_hash
    if _dummy_password_hash is None:
        _dummy_password_hash = await asyncio.to_thread(
            hash_password, "qwed-timing-equalizer"
        )
    await asyncio.to_thread(verify_password, password, _dummy_password_hash)

@router.post(
    "/signup",
    response_model=TokenResponse,
    responses={
        400: {"description": "Email already registered or organization name taken"},
        429: {"description": "Per-IP authentication rate limit exceeded"},
        500: {"description": "User creation failed"},
    },
)
async def signup(
    request: SignUpRequest,
    req: Request,
    session: Session = Depends(get_session)
):
    """
    Sign up a new user and create their organization.
    Returns JWT token for immediate login.
    """
    # Anonymous route: per-IP throttle before any DB or bcrypt work
    # (bcrypt is ~269 ms of CPU; issues #226/#334).
    check_auth_rate_limit(req)

    # Check if email already exists
    statement = select(User).where(User.email == request.email)
    existing_user = session.exec(statement).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create organization
    # Check if org name exists
    org_statement = select(Organization).where(Organization.name == request.organization_name)
    if session.exec(org_statement).first():
        # Auto-append random suffix if name taken, or just fail?
        # For now, let's fail
        raise HTTPException(status_code=400, detail="Organization name already taken")

    # Hash in the threadpool — bcrypt must never run on the event loop
    # (issue #334). Also BEFORE any row is written so a hash failure
    # cannot strand an orphaned Organization row.
    password_hash = await asyncio.to_thread(hash_password, request.password)

    # Create organization + user in ONE transaction (Sentry on PR #345):
    # flush() assigns the org PK without committing, so a user-creation
    # failure rolls the org back instead of stranding an orphaned row.
    org = Organization(
        name=request.organization_name,
        display_name=request.organization_name,
        tier="free"
    )
    session.add(org)
    session.flush()

    # Create user (first user is owner)
    try:
        print(f"DEBUG: Creating user with email={request.email}, org_id={org.id}")
        user = User(
            email=request.email,
            password_hash=password_hash,
            organization_id=org.id,
            role="owner"
        )
        print(f"DEBUG: User object created: {user}")
        session.add(user)
        session.commit()
        session.refresh(org)
        session.refresh(user)
        print("DEBUG: User committed successfully")
    except Exception as e:
        session.rollback()
        print(f"DEBUG: Error creating user: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="User creation failed")
    
    # Generate JWT token
    access_token = create_access_token(data={"sub": str(user.id), "org_id": str(org.id)})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "org_id": str(user.organization_id),
            "role": user.role
        }
    }

@router.post(
    "/signin",
    response_model=TokenResponse,
    responses={
        401: {"description": "Invalid email or password"},
        403: {"description": "Account is deactivated"},
        429: {"description": "Per-IP authentication rate limit exceeded"},
    },
)
async def signin(
    request: SignInRequest,
    req: Request,
    session: Session = Depends(get_session)
):
    """Sign in an existing user."""
    # Anonymous route: per-IP throttle — unthrottled signin is a password-
    # guessing oracle and a ~4 req/s whole-service DoS (issues #226/#334).
    check_auth_rate_limit(req)

    statement = select(User).where(User.email == request.email)
    user = session.exec(statement).first()

    # bcrypt in the threadpool (issue #334); when the email is unknown,
    # burn one bcrypt anyway so response timing does not enumerate emails.
    if user is None:
        await _burn_one_bcrypt(request.password)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not await asyncio.to_thread(verify_password, request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    
    # Generate JWT token
    access_token = create_access_token(data={"sub": str(user.id), "org_id": str(user.organization_id)})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "org_id": str(user.organization_id),
            "role": user.role
        }
    }

def get_current_user_token(authorization: Optional[str] = Header(None)) -> dict:
    """Dependency to get the decoded token payload."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_access_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
        
    return payload

async def get_current_user(
    payload: dict = Depends(get_current_user_token),
    session: Session = Depends(get_session)
) -> User:
    """Dependency to get the current user object."""
    user_id = payload.get("sub")
    user = session.get(User, int(user_id))
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "org_id": str(current_user.organization_id),
        "role": current_user.role
    }

@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key_endpoint(
    request: APIKeyCreateRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Generate a new API key."""
    # Generate key
    plaintext_key, key_hash = generate_api_key()
    
    # Store in database
    api_key = ApiKey(
        key_hash=key_hash,
        key_preview=mask_api_key(plaintext_key),
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        name=request.name
    )
    session.add(api_key)
    session.commit()
    session.refresh(api_key)
    
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "key": plaintext_key,  # Only shown once
        "created_at": api_key.created_at
    }

@router.get("/api-keys", response_model=List[APIKeyListItem])
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """List all API keys for the current user's organization."""
    # Show all keys for the organization
    statement = select(ApiKey).where(
        ApiKey.organization_id == current_user.organization_id,
        ApiKey.is_active == True
    ).order_by(ApiKey.created_at.desc())
    
    keys = session.exec(statement).all()
    
    return [
        {
            "id": str(key.id),
            "name": key.name,
            "key_preview": key.key_preview,
            "created_at": key.created_at,
            "last_used_at": key.last_used_at,
            "is_revoked": key.revoked_at is not None
        }
        for key in keys
    ]

@router.delete("/api-keys/{key_id}")
async def revoke_api_key_endpoint(
    key_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Revoke an API key."""
    # Ensure key belongs to user's org
    statement = select(ApiKey).where(
        ApiKey.id == int(key_id),
        ApiKey.organization_id == current_user.organization_id
    )
    key = session.exec(statement).first()
    
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Soft delete / revoke
    key.is_active = False
    key.revoked_at = datetime.utcnow()
    session.add(key)
    session.commit()
    
    return {"message": "API key revoked successfully"}
