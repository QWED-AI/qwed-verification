from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from sqlmodel import Session, select

from qwed_new.auth.security import hash_api_key, is_api_key_live, validate_api_key_format
from qwed_new.core.database import get_session
from qwed_new.core.models import ApiKey

# Define the API Key header scheme
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

async def get_api_key(
    api_key_header: str = Security(api_key_header),
    session: Session = Depends(get_session)
) -> ApiKey:
    """
    Validates the API Key from the x-api-key header.
    Returns the APIKey object if valid, otherwise raises HTTPException.
    """
    if not api_key_header:
        raise HTTPException(
            status_code=401,
            detail="Missing x-api-key header"
        )

    # Offline format pre-filter (issue #366): reject keys that can never be
    # valid before they cost an HMAC + DB lookup on this unauthenticated
    # path. Both v1 and v2 shapes pass; anything else fails closed.
    if validate_api_key_format(api_key_header) == "invalid":
        raise HTTPException(
            status_code=403,
            detail="Invalid or revoked API Key"
        )

    # Hash the provided key to compare with stored hash
    # The key format is qwed_live_<random>
    # We store the hash of the full key string
    hashed_key = hash_api_key(api_key_header)
    
    # Query database for the key. is_active is a cheap indexed pre-filter;
    # is_api_key_live is the authoritative gate — an expired or revoked key is
    # NOT a usable credential even though is_active stays True after expiry
    # (#389, CWE-613).
    statement = select(ApiKey).where(
        ApiKey.key_hash == hashed_key,
        ApiKey.is_active.is_(True)
    )
    api_key = session.exec(statement).first()

    if not api_key or not is_api_key_live(api_key):
        raise HTTPException(
            status_code=403,
            detail="Invalid or revoked API Key"
        )
    
    # last_used_at is recorded by the caller once every check has passed
    # (#486; see admin_auth._admin_from_api_key).
    return api_key
