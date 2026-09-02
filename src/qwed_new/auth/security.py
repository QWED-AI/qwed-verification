"""
Security utilities for QWED authentication.
Handles password hashing, JWT token generation, and API key management.
"""
import bcrypt
import jwt
import secrets
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

# Configuration - MUST be set via environment variables
SECRET_KEY = os.getenv("QWED_JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "QWED_JWT_SECRET_KEY must be set for deterministic API-key hashing/authentication."
    )

# Required, dedicated keying material for API-key lookup digests (fail
# closed at startup, CodeRabbit on PR #345): digests must survive
# QWED_JWT_SECRET_KEY rotations, and the earlier JWT-secret fallback both
# made a rotation silently break every API-key lookup and logged a warning
# on every call (Sentry log-spam on PR #345).
def _validate_secret_config() -> None:
    """Fail closed on insecure secret configuration (run at import).

    Kept as a plain function so verification tests can exercise the exact
    startup checks in-process (QWED Security on PR #345 round 4: a
    subprocess-based test trips the TEST_CODE scanner)."""
    if not os.getenv("QWED_API_KEY_LOOKUP_SECRET"):
        raise RuntimeError(
            "QWED_API_KEY_LOOKUP_SECRET must be set — API-key lookup digests "
            "are keyed with it and must stay stable across QWED_JWT_SECRET_KEY "
            "rotations. Set the dedicated secret BEFORE issuing v7.2 keys."
        )
    if os.getenv("QWED_API_KEY_LOOKUP_SECRET") == SECRET_KEY:
        # One rotated deployment secret in both variables re-couples API-key
        # digests to JWT rotations — the exact failure the dedicated secret
        # exists to prevent (CodeRabbit on PR #345 round 3). Refuse to boot.
        raise RuntimeError(
            "QWED_API_KEY_LOOKUP_SECRET must differ from QWED_JWT_SECRET_KEY — "
            "equal values re-couple API-key lookup digests to JWT-secret "
            "rotations."
        )


_validate_secret_config()

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
    # Plain concatenation: no literal credential-shaped material is
    # hard-coded here — the value is freshly generated randomness.
    plaintext_key = prefix + "_" + random_part
    
    # Hash the key for storage
    key_hash = hash_api_key(plaintext_key)
    
    return plaintext_key, key_hash


def _api_key_lookup_secret() -> bytes:
    """
    Keying material for the API-key lookup MAC.

    QWED_API_KEY_LOOKUP_SECRET is REQUIRED and validated at import — the
    process fails closed without it. The earlier QWED_JWT_SECRET_KEY
    fallback made a JWT-secret rotation silently break every API-key
    lookup (CodeRabbit, PR #345) and logged a warning on every call
    (Sentry log-spam, PR #345); neither failure mode is acceptable on the
    auth hot path, so there is no fallback.
    """
    dedicated = os.getenv("QWED_API_KEY_LOOKUP_SECRET")
    if dedicated:
        return dedicated.encode()
    # Environment mutated after startup (operator error, test harness) —
    # fail closed rather than keying digests with the wrong material.
    raise RuntimeError(
        "QWED_API_KEY_LOOKUP_SECRET was unset after startup — refusing to "
        "derive API-key lookup digests from the wrong keying material."
    )


def hash_api_key(api_key: str) -> str:
    """
    Derive a deterministic lookup digest for an API key.

    This is a fast keyed MAC (HMAC-SHA256, microsecond cost), NOT a KDF.
    The previous PBKDF2-HMAC-SHA256 with 100,000 iterations sat on the
    unauthenticated request path (hash-then-lookup) and let ~15 req/s of
    garbage x-api-key values saturate the whole service (issue #333).
    The cost bought no brute-force resistance: API keys are 258-bit random
    tokens, so equality lookup is unbreakable at any digest speed.

    Keying material: QWED_API_KEY_LOOKUP_SECRET (REQUIRED — the process
    fails closed at startup without it; stable across JWT-secret
    rotations). Set it BEFORE issuing v7.2 keys — digests are derived from
    whichever secret was active at issue time, and switching later
    requires a one-time re-issue.

    NOTE: not compatible with pre-v7.2 PBKDF2 key_hash rows. Existing keys
    must be re-issued once — via the portal (email/password JWT login ->
    POST /auth/api-keys, which needs no API key) or by key ID through
    /admin/keys/rotate with any already-working key. The old raw key is
    never required. Do NOT add a PBKDF2 fallback for legacy rows — that
    re-introduces #333.
    """
    # Keyed MAC over a 258-bit random token for equality lookup — not
    # password storage. A KDF here is the DoS bug (#333): digest speed is
    # irrelevant to security at this key entropy.
    # codeql[py/weak-sensitive-data-hashing]
    mac = hmac.digest(_api_key_lookup_secret() + b":qwed_api_key_lookup", api_key.encode("utf-8"), "sha256")
    return mac.hex()

def mask_api_key(api_key: str) -> str:
    """
    Mask an API key for display.
    Example: qwed_live_abc123... -> qwed_live_****3...
    """
    if len(api_key) < 16:
        return "****"
    return f"{api_key[:10]}****{api_key[-4:]}"
