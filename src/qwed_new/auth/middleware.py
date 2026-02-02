from fastapi import HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from sqlmodel import Session, select
from typing import Optional
import hashlib

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
    
from qwed_new.auth.security import hash_api_key

# ...

    # Hash the provided key to compare with stored hash
    # The key format is qwed_live_<random>
    # We store the hash of the full key string
    hashed_key = hash_api_key(api_key_header)
    
    # Query database for the key
    statement = select(ApiKey).where(
        ApiKey.key_hash == hashed_key,
        ApiKey.is_active == True
    )
    api_key = session.exec(statement).first()
    
    if not api_key:
        raise HTTPException(
            status_code=403,
            detail="Invalid or revoked API Key"
        )
    
    # Update last used timestamp (optional - might impact performance if done every request)
    # For high throughput, this should be done asynchronously or in batches
    # api_key.last_used_at = datetime.utcnow()
    # session.add(api_key)
    # session.commit()
    
    return api_key
