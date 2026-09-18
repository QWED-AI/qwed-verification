"""
Security utilities for QWED authentication.
Handles password hashing, JWT token generation, and API key management.
"""
import hmac
import os
import secrets
import zlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt

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

# ---------------------------------------------------------------------------
# API-key formats (issue #366)
#
# v2 (current):  qwed_live_<30 Base62 random><6 Base62 CRC32 checksum>
#   - charset strictly alphanumeric after the prefix, so the token
#     double-click selects cleanly and never breaks on a word separator.
#   - the trailing 6-char checksum lets the format be validated OFFLINE
#     (pure math, no DB) and collapses random false-positive matches to
#     ~2^-32. The checksum authenticates *shape*, never *authorization* —
#     access still requires the HMAC lookup in hash_api_key().
#   - entropy: 30 x log2(62) ~= 178.6 bits.
#
# v1 (legacy):   qwed_live_<43 base64url chars from token_urlsafe(32)>
#   - 32 bytes = 256 bits of entropy (NOT 258 — the 43rd base64 char
#     carries 2 zero padding bits). Accepted for backward compatibility;
#     existing v1 keys keep working and are never force-rotated.
# ---------------------------------------------------------------------------
_V2_RANDOM_LEN = 30
_V2_CHECKSUM_LEN = 6
_V2_BODY_LEN = _V2_RANDOM_LEN + _V2_CHECKSUM_LEN  # 36
_V1_BODY_LEN = 43  # len(secrets.token_urlsafe(32)) — always exactly 43

# Base62 alphabet (0-9A-Za-z ordering makes the checksum fixed-width).
_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62 = frozenset(_BASE62_ALPHABET)
# token_urlsafe alphabet: A-Za-z0-9 plus '-' and '_'.
_V1_BODY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)

_KEY_PREFIXES = ("qwed_live", "qwed_test")


def _split_key(api_key: str) -> tuple[str, str] | None:
    """Split a key into (prefix, body), or None if the shape is wrong.

    The known prefixes (``qwed_live``, ``qwed_test``) themselves contain an
    underscore, so we match the full ``"<prefix>_"`` prefix rather than
    splitting on the first '_'. A v1 base64url body may also contain '_',
    which is why we never re-split the body. Returns None for anything
    without a known prefix.
    """
    if not isinstance(api_key, str):
        return None
    for prefix in _KEY_PREFIXES:
        head = prefix + "_"
        if api_key.startswith(head):
            body = api_key[len(head):]
            return (prefix, body) if body else None
    return None


def _base62_encode(value: int, width: int) -> str:
    """Encode a non-negative int as fixed-width Base62, zero-padded."""
    if value < 0:
        raise ValueError("Base62 checksum input must be non-negative")
    out = []
    for _ in range(width):
        value, rem = divmod(value, 62)
        out.append(_BASE62_ALPHABET[rem])
    if value:  # pragma: no cover - crc32 always fits in 6 Base62 chars
        raise ValueError("value does not fit in the requested Base62 width")
    return "".join(reversed(out))


def _checksum_for(random_body: str) -> str:
    """6-char Base62 CRC32 checksum over the random body."""
    return _base62_encode(zlib.crc32(random_body.encode("ascii")), _V2_CHECKSUM_LEN)


def is_valid_key_checksum(api_key: str) -> bool:
    """Return True iff ``api_key`` is a structurally-valid v2 key.

    Strictly a v2 shape check: exact length, alphanumeric body, and a
    matching checksum. Returns False for v1 keys, test keys, and any
    malformed input. Pure function — no DB, no secrets, constant-work.
    """
    parts = _split_key(api_key)
    if parts is None:
        return False
    prefix, body = parts
    if prefix != "qwed_live" or len(body) != _V2_BODY_LEN:
        return False
    if any(ch not in _BASE62 for ch in body):
        return False
    random_body, checksum = body[:_V2_RANDOM_LEN], body[_V2_RANDOM_LEN:]
    # hmac.compare_digest so a wrong checksum doesn't leak WHERE it diverged.
    return hmac.compare_digest(_checksum_for(random_body), checksum)


def validate_api_key_format(api_key: str) -> str:
    """Classify a key as ``"v2"``, ``"v1"``, or ``"invalid"``.

    ``"v2"`` requires a valid checksum; ``"v1"`` is the legacy 43-char
    base64url shape. Everything else is ``"invalid"``.
    """
    if is_valid_key_checksum(api_key):
        return "v2"
    parts = _split_key(api_key)
    if parts is None:
        return "invalid"
    _, body = parts
    if len(body) == _V1_BODY_LEN and all(ch in _V1_BODY_CHARS for ch in body):
        return "v1"
    return "invalid"


def generate_api_key(prefix: str = "qwed_live") -> tuple[str, str]:
    """
    Generate a new v2 API key and its storage hash.

    Returns: (plaintext_key, key_hash)

    Format: ``<prefix>_<30 Base62 random><6 Base62 CRC32 checksum>``
    (see the format note above). ``prefix`` is ``qwed_live`` for production
    keys and ``qwed_test`` for non-production keys.
    """
    if prefix not in _KEY_PREFIXES:
        raise ValueError(f"unsupported API-key prefix: {prefix!r}")
    random_body = "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(_V2_RANDOM_LEN))
    # Plain concatenation: no credential-shaped material is hard-coded —
    # the value is freshly generated randomness plus its checksum.
    plaintext_key = f"{prefix}_{random_body}{_checksum_for(random_body)}"
    return plaintext_key, hash_api_key(plaintext_key)


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
    The cost bought no brute-force resistance: API keys are >=178-bit
    random tokens (v1 = 256 bits, v2 = ~178.6 bits), so equality lookup is
    unbreakable at any digest speed.

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
    # Keyed MAC over a high-entropy (>=178-bit) random token for equality
    # lookup — not password storage. A KDF here is the DoS bug (#333):
    # digest speed is irrelevant to security at this key entropy.
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
