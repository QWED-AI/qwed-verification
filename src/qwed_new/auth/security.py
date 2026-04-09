"""
Security utilities for QWED authentication.
Handles password hashing, JWT token generation, and API key management.
"""
import bcrypt
import jwt
import secrets
import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

# Configuration - MUST be set via environment variables
SECRET_KEY = os.getenv("QWED_JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "QWED_JWT_SECRET_KEY must be set for deterministic API-key hashing/authentication."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_api_key(prefix: str = "qwed_live") -> tuple[str, str]:
    """
    Generate a new API key and its hash.
    Returns: (plaintext_key, key_hash)
    
    Format: qwed_live_<32_random_chars>
    """
    random_part = secrets.token_urlsafe(32)
    plaintext_key = f"{prefix}_{random_part}"
    
    # Hash the key for storage
    key_hash = hash_api_key(plaintext_key)
    
    return plaintext_key, key_hash


def hash_api_key(api_key: str) -> str:
    """
    Derive a hash for an API key using PBKDF2-HMAC-SHA256.

    This is intentionally computationally expensive to make brute-force attacks
    against stored API key hashes more difficult, while remaining deterministic
    for lookup purposes.
    """
    # Derive a salt from SECRET_KEY; fall back to a constant development salt.
    if isinstance(SECRET_KEY, str):
        secret_bytes = SECRET_KEY.encode()
    else:
        secret_bytes = b"default_dev_salt" # Fallback if secret is somehow bytes or None

    # Namespace the salt for API key hashing to avoid cross-protocol reuse.
    salt = secret_bytes + b":qwed_api_key"

    # Use PBKDF2-HMAC-SHA256 with a reasonable iteration count.
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        api_key.encode("utf-8"),
        salt,
        100_000,
    )
    return dk.hex()

def mask_api_key(api_key: str) -> str:
    """
    Mask an API key for display.
    Example: qwed_live_abc123... -> qwed_live_****3...
    """
    if len(api_key) < 16:
        return "****"
    return f"{api_key[:10]}****{api_key[-4:]}"
