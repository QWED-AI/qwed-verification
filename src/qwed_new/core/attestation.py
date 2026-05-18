"""
QWED Attestation Service

Implements the QWED-Attestation specification for cryptographic verification proofs.
Uses JWT with ES256 (ECDSA P-256) for signing attestations.

Security contract (Issue #188):
- create_verification_attestation() NEVER returns None; it returns an AttestationResult
  whose .status is one of "ISSUED" | "BLOCKED" | "UNVERIFIABLE".
- Callers MUST check result.is_issued before treating the attestation as valid.
- Key lifecycle events are auditable via structured log entries.
"""

import hashlib
import json
import base64
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum

logger = logging.getLogger(__name__)

# Cryptographic imports - using PyJWT with cryptography backend
try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class AttestationStatus(Enum):
    """Attestation lifecycle states."""
    ISSUED = "issued"
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    # Fail-closed states (Issue #188)
    BLOCKED = "blocked"             # Signing attempted but failed — hard block
    UNVERIFIABLE = "unverifiable"   # Cannot attempt signing (e.g. crypto unavailable)


@dataclass
class AttestationResult:
    """Explicit typed result for attestation creation (Issue #188).

    Replaces the previous Optional[str] return that silently collapsed
    signing failures into None, allowing callers to proceed without a
    valid proof artifact.

    Callers MUST check .is_issued before using .token:

        result = create_verification_attestation(...)
        if not result.is_issued:
            raise RuntimeError(f"Attestation unavailable: {result.error_code}")
        use(result.token)
    """
    status: str                    # "ISSUED" | "BLOCKED" | "UNVERIFIABLE"
    token: Optional[str]           # JWT string, present only when status == "ISSUED"
    error_code: Optional[str]      # "SIGNING_FAILURE" | "CRYPTO_UNAVAILABLE" | None
    error: Optional[str]           # Human-readable error detail

    @property
    def is_issued(self) -> bool:
        """True only when the attestation was successfully signed and issued."""
        return self.status == "ISSUED"


@dataclass
class VerificationResult:
    """The result of a verification to be attested."""
    status: str  # VERIFIED, FAILED, CORRECTED, BLOCKED
    verified: bool
    engine: str
    confidence: float = 1.0
    query_hash: Optional[str] = None
    proof_hash: Optional[str] = None


@dataclass
class AttestationClaims:
    """QWED Attestation JWT Claims."""
    iss: str  # Issuer DID
    sub: str  # Subject hash
    iat: int  # Issued at
    exp: int  # Expiration
    jti: str  # Attestation ID
    qwed: Dict[str, Any]  # QWED-specific claims


@dataclass
class Attestation:
    """A complete QWED Attestation."""
    jwt_token: str
    claims: AttestationClaims
    header: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "jwt": self.jwt_token,
            "jti": self.claims.jti,
            "iss": self.claims.iss,
            "iat": self.claims.iat,
            "exp": self.claims.exp,
            "result": self.claims.qwed.get("result", {}),
        }


class IssuerKeyPair:
    """ECDSA P-256 key pair for attestation signing.

    Key lifecycle policy (Issue #188):
    - Every instance records generated_at and key_continuity_policy.
    - A structured log entry is emitted on every new key generation so
      continuity events are auditable.
    - Default policy is "ephemeral" (in-memory, non-persistent).
      Set key_continuity_policy="persistent" when external KMS binding is
      used and the key material is durably stored outside this process.
    """

    def __init__(
        self,
        issuer_did: str,
        key_id: str,
        key_continuity_policy: str = "ephemeral",
    ):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography package required for attestations")

        self.issuer_did = issuer_did
        self.key_id = key_id
        self.key_continuity_policy = key_continuity_policy
        self.generated_at: int = int(time.time())

        # Generate ECDSA P-256 key pair
        self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._public_key = self._private_key.public_key()

        # Auditable key generation event
        logger.info(
            "attestation.key_generated issuer=%s key_id=%s policy=%s generated_at=%d",
            issuer_did,
            key_id,
            key_continuity_policy,
            self.generated_at,
        )

    @property
    def private_key_pem(self) -> bytes:
        """Get private key in PEM format."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @property
    def public_key_pem(self) -> bytes:
        """Get public key in PEM format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @property
    def jwk(self) -> Dict[str, Any]:
        """Get public key as JWK for verification."""
        numbers = self._public_key.public_numbers()

        def int_to_base64url(n: int, length: int) -> str:
            return base64.urlsafe_b64encode(
                n.to_bytes(length, 'big')
            ).decode().rstrip('=')

        return {
            "kty": "EC",
            "crv": "P-256",
            "x": int_to_base64url(numbers.x, 32),
            "y": int_to_base64url(numbers.y, 32),
            "kid": self.key_id,
        }


class AttestationService:
    """
    Service for creating and verifying QWED attestations.

    Implements the QWED-Attestation v1.0 specification.
    """

    def __init__(
        self,
        issuer_did: str = "did:qwed:node:local",
        validity_days: int = 365,
        key_suffix: Optional[str] = None,
        key_continuity_policy: str = "ephemeral",
    ):
        self.issuer_did = issuer_did
        self.validity_days = validity_days
        self.key_continuity_policy = key_continuity_policy

        # Key management - deterministic if key_suffix provided
        suffix = key_suffix or "v1"
        self.key_id = f"{issuer_did}#signing-key-{suffix}"
        self._key_pair: Optional[IssuerKeyPair] = None

        # Revocation tracking
        self._revoked_attestations: set = set()

        # Attestation registry (in-memory, should use DB in production)
        self._attestations: Dict[str, Attestation] = {}

    def _ensure_key_pair(self) -> IssuerKeyPair:
        """Lazily initialize key pair."""
        if self._key_pair is None:
            self._key_pair = IssuerKeyPair(
                self.issuer_did,
                self.key_id,
                key_continuity_policy=self.key_continuity_policy,
            )
        return self._key_pair

    def _hash_content(self, content: str) -> str:
        """Create SHA-256 hash of content."""
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    def create_attestation(
        self,
        verification_result: VerificationResult,
        original_query: str,
        proof_data: Optional[str] = None,
        chain_id: Optional[str] = None,
        chain_index: Optional[int] = None,
    ) -> Attestation:
        """
        Create a signed attestation for a verification result.

        Args:
            verification_result: The verification result to attest.
            original_query:      The original query that was verified.
            proof_data:          Optional proof data to include.
            chain_id:            Optional chain ID for linked attestations.
            chain_index:         Optional index in the chain.

        Returns:
            Attestation object with signed JWT.

        Raises:
            RuntimeError: if crypto is unavailable or signing fails.
        """
        key_pair = self._ensure_key_pair()

        now = int(time.time())
        expiry = now + (self.validity_days * 24 * 60 * 60)
        attestation_id = f"att_{uuid.uuid4().hex[:12]}"

        # Build QWED-specific claims
        qwed_claims = {
            "version": "1.0",
            "result": {
                "status": verification_result.status,
                "verified": verification_result.verified,
                "engine": verification_result.engine,
                "confidence": verification_result.confidence,
            },
            "query_hash": self._hash_content(original_query),
        }

        if proof_data:
            qwed_claims["proof_hash"] = self._hash_content(proof_data)

        if chain_id:
            qwed_claims["chain_id"] = chain_id
            if chain_index is not None:
                qwed_claims["chain_index"] = chain_index

        # Build full payload
        payload = {
            "iss": self.issuer_did,
            "sub": self._hash_content(original_query),
            "iat": now,
            "exp": expiry,
            "jti": attestation_id,
            "qwed": qwed_claims,
        }

        # Build header
        header = {
            "alg": "ES256",
            "typ": "qwed-attestation+jwt",
            "kid": key_pair.key_id,
        }

        # Sign the JWT
        token = jwt.encode(
            payload,
            key_pair.private_key_pem,
            algorithm="ES256",
            headers=header,
        )

        claims = AttestationClaims(
            iss=payload["iss"],
            sub=payload["sub"],
            iat=payload["iat"],
            exp=payload["exp"],
            jti=attestation_id,
            qwed=qwed_claims,
        )

        attestation = Attestation(
            jwt_token=token,
            claims=claims,
            header=header,
        )

        # Store in registry
        self._attestations[attestation_id] = attestation

        return attestation

    def verify_attestation(
        self,
        jwt_token: str,
        trusted_issuers: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Verify an attestation JWT.

        Args:
            jwt_token:        The JWT to verify.
            trusted_issuers:  List of trusted issuer DIDs (None = trust self).

        Returns:
            Tuple of (is_valid, claims, error_message).
        """
        if trusted_issuers is None:
            trusted_issuers = [self.issuer_did]

        try:
            # Decode without verification first to get issuer.
            # Security: We manually decode the payload to get 'iss' and then
            # perform FULL cryptographic verification with the correct key.
            try:
                _, payload_segment, _ = jwt_token.split('.', 2)
                padding = '=' * (-len(payload_segment) % 4)
                payload_data = base64.urlsafe_b64decode(payload_segment + padding)
                unverified = json.loads(payload_data)
                if not isinstance(unverified, dict):
                    raise ValueError("Payload is not a JSON object")
            except Exception:
                return False, None, "Invalid token format"

            issuer = unverified.get("iss")

            if issuer not in trusted_issuers:
                safe_issuer = str(issuer)[:128].replace('\n', '').replace('\r', '')
                return False, None, f"Untrusted issuer: {safe_issuer}"

            # For self-issued attestations, use our key
            if issuer == self.issuer_did:
                key_pair = self._ensure_key_pair()
                public_key = key_pair.public_key_pem
            else:
                # Would need to resolve DID and get public key
                return False, None, "External issuer key resolution not implemented"

            # Verify signature and claims
            claims = jwt.decode(
                jwt_token,
                public_key,
                algorithms=["ES256"],
                options={"require": ["iss", "sub", "iat", "exp", "jti"]},
            )

            # Check revocation
            jti = claims.get("jti")
            if jti in self._revoked_attestations:
                return False, None, "Attestation has been revoked"

            return True, claims, None

        except jwt.ExpiredSignatureError:
            return False, None, "Attestation has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"

    def revoke_attestation(self, attestation_id: str) -> bool:
        """Revoke an attestation by ID."""
        self._revoked_attestations.add(attestation_id)
        return True

    def get_attestation(self, attestation_id: str) -> Optional[Attestation]:
        """Get an attestation by ID."""
        return self._attestations.get(attestation_id)

    def get_issuer_info(self) -> Dict[str, Any]:
        """Get issuer information for registry, including key lifecycle metadata."""
        key_pair = self._ensure_key_pair()
        return {
            "did": self.issuer_did,
            "name": "QWED Local Node",
            "public_keys": [key_pair.jwk],
            "status": "active",
            "certification_level": "basic",
            # Key lifecycle fields (Issue #188)
            "key_generated_at": key_pair.generated_at,
            "key_continuity_policy": key_pair.key_continuity_policy,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_service: Optional[AttestationService] = None


def get_attestation_service() -> AttestationService:
    """Get the default attestation service."""
    global _default_service
    if _default_service is None:
        _default_service = AttestationService()
    return _default_service


def create_verification_attestation(
    status: str,
    verified: bool,
    engine: str,
    query: str,
    confidence: float = 1.0,
    proof_data: Optional[str] = None,
) -> AttestationResult:
    """Create a signed attestation for a verification result.

    Returns an :class:`AttestationResult` — **never** ``None``.

    The caller MUST check ``result.is_issued`` before using ``result.token``:

        result = create_verification_attestation(...)
        if not result.is_issued:
            # Hard-block: do not proceed as VERIFIED without proof artifact
            raise RuntimeError(f"Attestation unavailable [{result.error_code}]")

    Failure semantics (Issue #188 — fail-closed contract):
    - ``BLOCKED``       — crypto is available but signing failed (key error, JWT error, etc.)
    - ``UNVERIFIABLE``  — crypto package not installed; cannot attempt signing

    Args:
        status:      Verification status string (e.g. "VERIFIED", "FAILED").
        verified:    Whether the result was verified.
        engine:      Verification engine name.
        query:       The original query string.
        confidence:  Confidence score (0.0–1.0).
        proof_data:  Optional proof artifact string.

    Returns:
        AttestationResult with status "ISSUED", "BLOCKED", or "UNVERIFIABLE".
    """
    if not HAS_CRYPTO:
        logger.warning(
            "attestation.unverifiable query_hash=%s reason=CRYPTO_UNAVAILABLE",
            hashlib.sha256(query.encode()).hexdigest()[:16],
        )
        return AttestationResult(
            status="UNVERIFIABLE",
            token=None,
            error_code="CRYPTO_UNAVAILABLE",
            error="cryptography/PyJWT package not installed",
        )

    try:
        service = get_attestation_service()
        result = VerificationResult(
            status=status,
            verified=verified,
            engine=engine,
            confidence=confidence,
        )
        attestation = service.create_attestation(result, query, proof_data)
        return AttestationResult(
            status="ISSUED",
            token=attestation.jwt_token,
            error_code=None,
            error=None,
        )
    except Exception:
        logger.exception(
            "attestation.blocked query_hash=%s reason=SIGNING_FAILURE",
            hashlib.sha256(query.encode()).hexdigest()[:16],
        )
        return AttestationResult(
            status="BLOCKED",
            token=None,
            error_code="SIGNING_FAILURE",
            error="Attestation signing failed — see logs for detail",
        )
