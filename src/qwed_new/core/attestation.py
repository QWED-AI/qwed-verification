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
import os
import re
import json
import base64
import logging
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum

logger = logging.getLogger(__name__)

# Cryptographic imports - using PyJWT with cryptography backend
try:
    import jwt
    from cryptography.exceptions import UnsupportedAlgorithm
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


# Allowlist for key continuity policy values — typos silently degrade auditability.
# "ephemeral": a key generated per process. "configured": a key the operator
# provides, which survives restarts and is shared by replicas (#319).
ALLOWED_KEY_CONTINUITY_POLICIES = {"ephemeral", "configured"}

# The configured attestation signing key, as PEM text or as a path to a PEM
# file (#319).
SIGNING_KEY_ENV = "QWED_SIGNING_KEY"
SIGNING_KEY_FILE_ENV = "QWED_SIGNING_KEY_FILE"

# A P-256 private key in PEM is about 250 bytes; a file far larger is not one.
_MAX_KEY_FILE_BYTES = 16 * 1024

# How long a token the server issues stays valid, in seconds (#319). Tokens
# are delivered to consumers, and revocation is held per process, so a
# token's lifetime is what bounds its use; rotating the key ends them all.
TTL_ENV = "QWED_ATTESTATION_TTL_SECONDS"
DEFAULT_TTL_SECONDS = 24 * 60 * 60
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 30 * 24 * 60 * 60


class AttestationConfigError(RuntimeError):
    """The server's attestation settings cannot be used."""


class SigningKeyError(AttestationConfigError):
    """The configured signing key is missing, unreadable or unusable.

    Its message never includes key material: it can reach a log line and a
    BLOCKED result's developer fields.
    """


def configured_ttl_seconds() -> int:
    """The token lifetime from ``QWED_ATTESTATION_TTL_SECONDS``: 24 hours
    when unset, otherwise a whole number of seconds from 60 to 30 days.

    Anything else raises AttestationConfigError rather than falling back, so
    a typo cannot quietly issue tokens for longer than intended.
    """
    raw = os.environ.get(TTL_ENV, "").strip()
    if not raw:
        return DEFAULT_TTL_SECONDS
    if not raw.isdigit():
        raise AttestationConfigError(f"{TTL_ENV} must be a whole number of seconds")
    ttl = int(raw)
    if not _MIN_TTL_SECONDS <= ttl <= _MAX_TTL_SECONDS:
        raise AttestationConfigError(
            f"{TTL_ENV} must be from {_MIN_TTL_SECONDS} to {_MAX_TTL_SECONDS} seconds"
        )
    return ttl


def _is_p256_private_key(key: Any) -> bool:
    return isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1)


def load_signing_key(pem: bytes) -> "ec.EllipticCurvePrivateKey":
    """An unencrypted EC P-256 private key (ES256) from PEM, or SigningKeyError."""
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise SigningKeyError(
            "attestation signing key is not an unencrypted PEM private key"
        ) from None
    if not _is_p256_private_key(key):
        raise SigningKeyError("attestation signing key must be an EC P-256 key (ES256)")
    return key


def _read_key_file(path: str) -> bytes:
    """The key file's bytes: a regular file, no larger than a key could be.

    The path is the operator's own setting, as trusted as the key, so this
    is not a traversal boundary; it refuses what cannot be a key file (a
    directory, a device, a stream that never ends) before reading it.

    The path is opened once, without blocking, and the open file is the one
    checked, so it cannot be swapped for a FIFO between a check and the open
    (which would block while the service lock is held). Symlinks are
    followed, as mounted secrets often are links.
    """
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise SigningKeyError(f"{SIGNING_KEY_FILE_ENV} could not be read") from None
    # The raw descriptor is checked before it is wrapped: os.fdopen raises on
    # a directory without closing a descriptor it was handed, so it would
    # leak. Until the file object owns it, this function closes it (#510).
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SigningKeyError(f"{SIGNING_KEY_FILE_ENV} is not a regular file")
        handle = os.fdopen(fd, "rb")
        fd = -1  # owned, and closed, by the file object from here
        with handle:
            data = handle.read(_MAX_KEY_FILE_BYTES + 1)
    except OSError:
        raise SigningKeyError(f"{SIGNING_KEY_FILE_ENV} could not be read") from None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > _MAX_KEY_FILE_BYTES:
        raise SigningKeyError(f"{SIGNING_KEY_FILE_ENV} is too large to be a key file")
    return data


def configured_signing_key_pem() -> Optional[bytes]:
    """The configured signing key's PEM, or None when neither setting is set.

    ``QWED_SIGNING_KEY`` holds the PEM itself (``\\n`` escapes are read as
    newlines, for env files); ``QWED_SIGNING_KEY_FILE`` names a file holding
    it, such as a mounted secret. Setting both is an error rather than a
    choice between them.
    """
    pem = os.environ.get(SIGNING_KEY_ENV, "").strip()
    path = os.environ.get(SIGNING_KEY_FILE_ENV, "").strip()
    if pem and path:
        raise SigningKeyError(f"set {SIGNING_KEY_ENV} or {SIGNING_KEY_FILE_ENV}, not both")
    if path:
        return _read_key_file(path)
    if pem:
        return pem.replace("\\n", "\n").encode()
    return None


def _jwk_coordinates(public_key: "ec.EllipticCurvePublicKey") -> Dict[str, str]:
    """The public JWK members of a P-256 key (RFC 7517), without ``kid``."""
    numbers = public_key.public_numbers()

    def int_to_base64url(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).decode().rstrip("=")

    return {"crv": "P-256", "kty": "EC", "x": int_to_base64url(numbers.x), "y": int_to_base64url(numbers.y)}


def jwk_thumbprint(public_key: "ec.EllipticCurvePublicKey") -> str:
    """The RFC 7638 thumbprint of a P-256 public key: the same key gives the
    same value on every restart and every replica, so it names the key."""
    canonical = json.dumps(_jwk_coordinates(public_key), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


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
    status: AttestationStatus      # ISSUED | BLOCKED | UNVERIFIABLE
    token: Optional[str]           # JWT string, present only when status == ISSUED
    error_code: Optional[str]      # "SIGNING_FAILURE" | "CRYPTO_UNAVAILABLE" | None
    error: Optional[str]           # Human-readable error detail

    @property
    def is_issued(self) -> bool:
        """True only when the attestation was successfully signed and issued."""
        return self.status is AttestationStatus.ISSUED


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

    Key lifecycle policy (Issue #188, #319):
    - Every instance records key_continuity_policy, loaded_at, and for a
      generated key generated_at.
    - A structured log entry is emitted whenever a key is generated or
      loaded, so continuity events are auditable.
    - "ephemeral": a key generated in memory. Restarting the process
      generates a new key, and attestations issued before cannot be verified
      after the restart or by another replica.
    - "configured": the operator's key (``private_key``), which survives
      restarts and is shared by replicas.
    """

    def __init__(
        self,
        issuer_did: str,
        key_id: str,
        key_continuity_policy: str = "ephemeral",
        private_key: Optional["ec.EllipticCurvePrivateKey"] = None,
    ):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography package required for attestations")

        if key_continuity_policy not in ALLOWED_KEY_CONTINUITY_POLICIES:
            raise ValueError(
                f"Invalid key_continuity_policy: {key_continuity_policy!r}. "
                f"Must be one of {sorted(ALLOWED_KEY_CONTINUITY_POLICIES)}"
            )
        if (key_continuity_policy == "configured") != (private_key is not None):
            raise ValueError("a configured key needs private_key; an ephemeral one takes none")
        if private_key is not None and not _is_p256_private_key(private_key):
            # Checked here too, for direct callers: another curve would fail
            # later, wherever the JWK is built (#510 review).
            raise ValueError("private_key must be an EC P-256 key (ES256)")

        self.issuer_did = issuer_did
        self.key_id = key_id
        self.key_continuity_policy = key_continuity_policy
        self.loaded_at: int = int(time.time())

        if private_key is None:
            # Generate ECDSA P-256 key pair
            self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.generated_at: Optional[int] = self.loaded_at
            event = "attestation.key_generated"
        else:
            self._private_key = private_key
            self.generated_at = None  # the operator's key: not generated here
            event = "attestation.key_loaded"
        self._public_key = self._private_key.public_key()

        # Auditable key lifecycle event
        logger.info(
            "%s issuer=%s key_id=%s policy=%s at=%d",
            event,
            issuer_did,
            key_id,
            key_continuity_policy,
            self.loaded_at,
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
        return {**_jwk_coordinates(self._public_key), "kid": self.key_id}


# A DiagnosticResult proof_ref, the only proof_hash form that is signed (#320).
_PROOF_HASH = re.compile(r"sha256:[0-9a-f]{64}")

# The admission decisions a token can sign as qwed.admission (#321), the
# values of diagnostics.AdmissionDecision.
ADMISSION_CLAIMS = frozenset({"ADMIT", "BLOCKED"})


def _is_proof_hash(value: Any) -> bool:
    """True for a well-formed proof hash; False for anything else, a
    non-string included, so it is refused rather than raising TypeError."""
    return isinstance(value, str) and _PROOF_HASH.fullmatch(value) is not None


def is_admission_claim(value: Any) -> bool:
    """True for "ADMIT" or "BLOCKED"; False for anything else, an unhashable
    value such as a list included, so it is refused rather than raising
    TypeError (#514 review)."""
    return isinstance(value, str) and value in ADMISSION_CLAIMS


# The header typ of a verdict's token, and of a token that signs a
# Verification Context document (#319).
TOKEN_TYPE = "qwed-attestation+jwt"
CONTEXT_TOKEN_TYPE = "qwed-context+jwt"
_CONTEXT_VERDICTS = frozenset({"VERIFIED", "UNVERIFIABLE", "BLOCKED"})
_CONTEXT_ADMISSIONS = frozenset({"ADMIT", "DENY"})


def _context_refusal(document_hash: Any, verdict: Any, admission: Any, proof_ref: Any) -> str | None:
    """Why a document with these fields cannot be signed, or None if it can
    (#319). The fields are those the Verification Context schema allows: a
    VERIFIED document has a proof_ref, any other has none and is DENY."""
    if not _is_proof_hash(document_hash):
        return "document_hash must be sha256:<64 hex>"
    if not isinstance(verdict, str) or verdict not in _CONTEXT_VERDICTS:
        return "verdict must be VERIFIED, UNVERIFIABLE or BLOCKED"
    if not isinstance(admission, str) or admission not in _CONTEXT_ADMISSIONS:
        return "admission must be ADMIT or DENY"
    if verdict == "VERIFIED":
        if not _is_proof_hash(proof_ref):
            return "a VERIFIED document needs a proof_ref"
    elif proof_ref is not None or admission != "DENY":
        return "a document that is not VERIFIED has no proof_ref and is DENY"
    return None


def _admission_refusal(admission: Any, *, status: Any, verified: Any, proof_bound: bool) -> str | None:
    """Why ``admission`` cannot be signed, or None if it can (#321).

    It must be ADMIT or BLOCKED. ADMIT, a pass at the boundary, is signed
    only for a VERIFIED result that is ``verified`` with a proof bound to the
    token, as admission_decision admits only such a result (#514 review).
    """
    if admission is None:
        return None
    if not is_admission_claim(admission):
        return "admission must be ADMIT or BLOCKED"
    if admission == "ADMIT" and not (status == "VERIFIED" and verified is True and proof_bound):
        return "ADMIT needs a VERIFIED, verified result with a proof bound to it"
    return None

# (#275) Single source of truth for the generic attestation rejection message.
# Every caller-sensitive failure returns this exactly, so attackers cannot
# enumerate trusted issuers, probe expirations, or read implementation state.
_GENERIC_REJECTION_MSG = "Invalid token"


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
        private_key_pem: Optional[bytes] = None,
        validity_seconds: Optional[int] = None,
    ):
        """``validity_seconds``, when given, is a token's lifetime in place of
        ``validity_days``; the server's service sets it (#319).

        ``private_key_pem`` is the configured key (policy "configured"),
        loaded, checked and put in use here, so an unusable key fails at once
        rather than at the first signing, and ``key_loaded_at`` is when it
        was loaded. Its key ID is the key's RFC 7638 thumbprint, the same on
        every restart and replica; ``key_suffix`` names only a generated
        key."""
        self.issuer_did = issuer_did
        self.validity_days = validity_days
        self.validity_seconds = validity_seconds

        if key_continuity_policy not in ALLOWED_KEY_CONTINUITY_POLICIES:
            raise ValueError(
                f"Invalid key_continuity_policy: {key_continuity_policy!r}. "
                f"Must be one of {sorted(ALLOWED_KEY_CONTINUITY_POLICIES)}"
            )
        if (key_continuity_policy == "configured") != (private_key_pem is not None):
            raise ValueError("a configured key needs private_key_pem; an ephemeral one takes none")
        self.key_continuity_policy = key_continuity_policy

        self._key_pair: Optional[IssuerKeyPair] = None
        if private_key_pem is not None:
            if not HAS_CRYPTO:
                raise RuntimeError("cryptography package required for attestations")
            key = load_signing_key(private_key_pem)
            self.key_id = f"{issuer_did}#{jwk_thumbprint(key.public_key())}"
            self._key_pair = IssuerKeyPair(
                issuer_did, self.key_id, key_continuity_policy="configured", private_key=key,
            )
        else:
            # Key management - deterministic if key_suffix provided
            suffix = key_suffix or "v1"
            self.key_id = f"{issuer_did}#signing-key-{suffix}"

        # Revocation tracking
        self._revoked_attestations: set = set()

        # Attestation registry (in-memory, should use DB in production)
        self._attestations: Dict[str, Attestation] = {}

        # Thread safety for lazy key initialization
        self._key_lock: threading.Lock = threading.Lock()

    def _ensure_key_pair(self) -> IssuerKeyPair:
        """Lazily initialize key pair (thread-safe)."""
        if self._key_pair is None:
            with self._key_lock:
                if self._key_pair is None:
                    # A configured key pair is built in __init__; this
                    # generates the ephemeral one on first use.
                    self._key_pair = IssuerKeyPair(
                        self.issuer_did,
                        self.key_id,
                        key_continuity_policy=self.key_continuity_policy,
                    )
        return self._key_pair

    @classmethod
    def from_environment(cls) -> "AttestationService":
        """The service the server signs with: the configured key when one is
        set (``QWED_SIGNING_KEY`` or ``QWED_SIGNING_KEY_FILE``), otherwise a
        generated one.

        A configured key that cannot be read or used raises SigningKeyError:
        it is never replaced by a generated key, because that would issue
        tokens no other replica, and no restart, could verify (#188, #319).
        Its tokens last ``QWED_ATTESTATION_TTL_SECONDS`` (24 hours by
        default); an unusable value raises AttestationConfigError.
        """
        ttl = configured_ttl_seconds()
        pem = configured_signing_key_pem()
        if pem is None:
            logger.warning(
                "attestation.ephemeral_key: no %s or %s is set, so a key is generated "
                "for this process; its tokens cannot be verified after a restart or "
                "by another replica",
                SIGNING_KEY_ENV,
                SIGNING_KEY_FILE_ENV,
            )
            return cls(validity_seconds=ttl)
        return cls(key_continuity_policy="configured", private_key_pem=pem, validity_seconds=ttl)

    def _hash_content(self, content: str) -> str:
        """Create SHA-256 hash of content."""
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    def _binding_claims(
        self,
        verification_result: VerificationResult,
        proof_data: str | None,
        proof_hash: str | None,
        admission: str | None,
    ) -> dict[str, Any]:
        """The claims that bind a token to its answer: ``proof_hash``, and
        ``admission`` where the route decides one (#321). Checked here, at
        the signing boundary, not only by the wrapper; a value that is not
        allowed raises ValueError."""
        if proof_data is not None and proof_hash is not None:
            raise ValueError("give proof_data or proof_hash, not both")
        claims: dict[str, Any] = {}
        if proof_hash is not None:
            if not _is_proof_hash(proof_hash):
                raise ValueError("proof_hash must be sha256:<64 hex>")
            claims["proof_hash"] = proof_hash
        elif proof_data:
            claims["proof_hash"] = self._hash_content(proof_data)
        refusal = _admission_refusal(
            admission,
            status=verification_result.status,
            verified=verification_result.verified,
            proof_bound="proof_hash" in claims,
        )
        if refusal is not None:
            raise ValueError(refusal)
        if admission is not None:
            claims["admission"] = admission
        return claims

    def create_attestation(
        self,
        verification_result: VerificationResult,
        original_query: str,
        proof_data: Optional[str] = None,
        chain_id: Optional[str] = None,
        chain_index: Optional[int] = None,
        issued_at: Optional[int] = None,
        jti: Optional[str] = None,
        proof_hash: Optional[str] = None,
        store: bool = True,
        admission: str | None = None,
    ) -> Attestation:
        """
        Create a signed attestation for a verification result.

        Args:
            verification_result: The verification result to attest.
            original_query:      The original query that was verified.
            proof_data:          Optional proof data to include.
            chain_id:            Optional chain ID for linked attestations.
            chain_index:         Optional index in the chain.
            issued_at:           Optional issuance epoch (injectable for determinism).
            jti:                 Optional attestation ID (injectable for determinism).
            proof_hash:          Optional proof hash to bind as is, in place
                                 of hashing proof_data: a DiagnosticResult's
                                 proof_ref, which is already that hash (#320).
                                 Give one of proof_data and proof_hash; a
                                 proof_hash that is not sha256:<64 hex> is
                                 refused.
            store:               Keep the attestation in this service's
                                 registry (get_attestation). False for a
                                 token checked once in this process and not
                                 returned, so it does not accumulate.
            admission:           The server's admission decision for the
                                 result, "ADMIT" or "BLOCKED", signed as
                                 qwed.admission (#321). None for a route
                                 that decides none; any other value is
                                 refused, and so is ADMIT for a result that
                                 is not VERIFIED, verified and proven.

        Returns:
            Attestation object with signed JWT.

        Raises:
            RuntimeError: if crypto is unavailable or signing fails.
        """
        now, expiry, attestation_id = self._lifetime_claims(issued_at, jti)

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
            **self._binding_claims(verification_result, proof_data, proof_hash, admission),
        }

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

        token, header = self._sign(payload, TOKEN_TYPE)

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

        if store:
            self._attestations[attestation_id] = attestation

        return attestation

    def _lifetime_claims(self, issued_at: Optional[int], jti: Optional[str]) -> Tuple[int, int, str]:
        """A new token's iat, exp and jti."""
        now = issued_at if issued_at is not None else int(time.time())
        lifetime = (
            self.validity_seconds if self.validity_seconds is not None
            else self.validity_days * 24 * 60 * 60
        )
        attestation_id = jti if jti is not None else f"att_{uuid.uuid4().hex[:12]}"
        return now, now + lifetime, attestation_id

    def _sign(self, payload: Dict[str, Any], token_type: str) -> Tuple[str, Dict[str, str]]:
        """``payload`` signed with this service's key as a JWT whose header
        typ is ``token_type``, and that header."""
        # Validate encoded payload fits verify_attestation's 4096-byte limit
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        if len(payload_b64) > 4096:
            raise ValueError(
                f"Attestation payload too large ({len(payload_b64)} bytes) — "
                f"must fit within 4096-byte verify-side limit"
            )

        key_pair = self._ensure_key_pair()

        # Build header
        header = {
            "alg": "ES256",
            "typ": token_type,
            "kid": key_pair.key_id,
        }

        # Sign the JWT
        token = jwt.encode(
            payload,
            key_pair.private_key_pem,
            algorithm="ES256",
            headers=header,
        )
        return token, header

    def create_context_attestation(
        self,
        *,
        document_hash: str,
        verdict: str,
        admission: str,
        proof_ref: Optional[str],
        issued_at: Optional[int] = None,
        jti: Optional[str] = None,
    ) -> str:
        """Sign a Verification Context document and return the token (#319).

        ``document_hash`` is the document's
        ``verification_context.compute_document_hash``, which binds all of
        it; its verdict, admission and ``proof_ref`` are signed beside it, so
        a consumer can check them against the document. The header's typ is
        ``qwed-context+jwt``: the token is not a verdict's attestation, and a
        verdict's check refuses it. It lasts as long as a verdict's token.
        Fields the schema would refuse are refused (ValueError).
        """
        refusal = _context_refusal(document_hash, verdict, admission, proof_ref)
        if refusal is not None:
            raise ValueError(refusal)
        now, expiry, attestation_id = self._lifetime_claims(issued_at, jti)
        payload = {
            "iss": self.issuer_did,
            "sub": document_hash,
            "iat": now,
            "exp": expiry,
            "jti": attestation_id,
            "qwed": {
                "version": "1.1",
                "document_hash": document_hash,
                "verdict": verdict,
                "admission": admission,
                "proof_ref": proof_ref,
            },
        }
        token, _header = self._sign(payload, CONTEXT_TOKEN_TYPE)
        return token

    def verify_attestation(
        self,
        jwt_token: str,
        trusted_issuers: Optional[List[str]] = None,
        token_type: str = TOKEN_TYPE,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Verify an attestation JWT.

        Args:
            jwt_token:        The JWT to verify.
            trusted_issuers:  List of trusted issuer DIDs (None = trust self).
            token_type:       The typ its verified header must have: a
                              verdict's token by default, or
                              CONTEXT_TOKEN_TYPE for a document's (#319).

        Returns:
            Tuple of (is_valid, claims, error_message).
        """
        if trusted_issuers is None:
            trusted_issuers = [self.issuer_did]

        try:
            # Boundary checks before any cryptographic work. Attacker-controlled
            # payload is validated structurally; no claim is trusted until the
            # signature is verified below with the local key.
            try:
                if len(jwt_token) > 8192:
                    return False, None, _GENERIC_REJECTION_MSG
                _, payload_segment, _ = jwt_token.split('.', 2)
                if len(payload_segment) > 4096:
                    return False, None, _GENERIC_REJECTION_MSG
                payload_data = base64.urlsafe_b64decode(payload_segment + '=' * (-len(payload_segment) % 4))
                unverified = json.loads(payload_data)
                if not isinstance(unverified, dict):
                    return False, None, _GENERIC_REJECTION_MSG
            except (IndexError, ValueError, TypeError, RecursionError):
                return False, None, _GENERIC_REJECTION_MSG

            # Always select the local key; issuer authorization is applied only
            # AFTER signature verification (no branch on unverified claims).
            key_pair = self._ensure_key_pair()
            public_key = key_pair.public_key_pem

            # Verify signature and claims. PyJWT exports decode_complete at
            # module level only from 2.10; the PyJWT class has it from 2.0,
            # and the floor is 2.8 (#517 review).
            decoded = jwt.PyJWT().decode_complete(
                jwt_token,
                public_key,
                algorithms=["ES256"],
                options={"verify_signature": True, "verify_exp": True, "require": ["iss", "sub", "iat", "exp", "jti"]},
            )
            claims = decoded["payload"]

            # The verified header says which kind of token this is: a
            # document's token is not a verdict's, nor the reverse (#319).
            if decoded["header"].get("typ") != token_type:
                logger.debug("Attestation of another type rejected (verified)")
                return False, None, _GENERIC_REJECTION_MSG

            # No token this service signs names a critical extension, and
            # PyJWT before 2.12 does not refuse one it does not understand
            # (RFC 7515 section 4.1.11; #517 review).
            if "crit" in decoded["header"]:
                logger.debug("Attestation with a critical header extension rejected (verified)")
                return False, None, _GENERIC_REJECTION_MSG

            # The verified header must name the key that verified it, as
            # spec v1.1 section 4 and the SDKs require (#523 review).
            if decoded["header"].get("kid") != key_pair.key_id:
                logger.debug("Attestation naming another key rejected (verified)")
                return False, None, _GENERIC_REJECTION_MSG

            # Now verified: apply issuer authorization. External issuers have no
            # key resolution implemented (#275) — silent generic, never enumerate.
            if claims.get("iss") != self.issuer_did:
                logger.debug("Attestation issuer not supported (verified)")
                return False, None, _GENERIC_REJECTION_MSG

            if claims.get("iss") not in trusted_issuers:
                logger.debug("Untrusted issuer (verified)")
                return False, None, _GENERIC_REJECTION_MSG

            # Check revocation
            jti = claims.get("jti")
            if jti in self._revoked_attestations:
                logger.debug("Revoked attestation jti=%s rejected", jti)
                return False, None, _GENERIC_REJECTION_MSG

            return True, claims, None

        except jwt.ExpiredSignatureError:
            logger.debug("Attestation expired (silent)")
            return False, None, _GENERIC_REJECTION_MSG
        except jwt.InvalidTokenError as e:
            logger.debug(f"Attestation verification failed (silent): {type(e).__name__}")
            return False, None, _GENERIC_REJECTION_MSG
        except RecursionError:
            # A header nested too deeply for the JSON parser: the caller's
            # malformed token, not the server's failure (#523 review).
            logger.debug("Attestation header too deeply nested (silent)")
            return False, None, _GENERIC_REJECTION_MSG

    def revoke_attestation(self, attestation_id: str) -> bool:
        """Revoke an attestation by ID, in this service only.

        The revoked IDs are held in memory. With a configured key, which
        other replicas and later processes share, they still accept the
        token: revocation is not shared or durable. Nothing in the server
        revokes. Tokens the server delivers are short-lived instead
        (``QWED_ATTESTATION_TTL_SECONDS``, 24 hours by default), and
        rotating the key ends every token issued before (#319).
        """
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
            # Key lifecycle fields (Issue #188). key_generated_at is null
            # for a configured key, which was not generated here (#319).
            "key_generated_at": key_pair.generated_at,
            "key_loaded_at": key_pair.loaded_at,
            "key_continuity_policy": key_pair.key_continuity_policy,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_service: Optional[AttestationService] = None
_default_service_lock = threading.Lock()


def get_attestation_service() -> AttestationService:
    """Get the default attestation service (thread-safe).

    Every VERIFIED result is signed and its token checked against this one
    service's key (#320), some from worker threads. Two first calls racing
    without the lock could each build a service with its own key, and a
    token signed by one would fail the other's check.

    The key is the configured one when set (#319). If it cannot be used,
    this raises SigningKeyError and keeps no service, so every call fails
    the same way. The server calls this at startup and refuses to start;
    elsewhere both callers turn the error into a BLOCKED result.
    """
    global _default_service
    if _default_service is None:
        with _default_service_lock:
            if _default_service is None:
                _default_service = AttestationService.from_environment()
    return _default_service



def create_verification_attestation(
    status: str,
    verified: bool,
    engine: str,
    query: str,
    confidence: float = 1.0,
    proof_data: Optional[str] = None,
    proof_hash: Optional[str] = None,
    admission: str | None = None,
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
        proof_hash:  Optional ``sha256:<hex>`` proof hash to bind as is, in
                     place of hashing ``proof_data``: a DiagnosticResult's
                     ``proof_ref`` (#320). A malformed value is BLOCKED.
        admission:   The route's admission decision, "ADMIT" or "BLOCKED",
                     signed as ``qwed.admission`` (#321); None where the route
                     decides none. Any other value is BLOCKED, and so is ADMIT
                     for a result that is not VERIFIED, verified and proven.

    Returns:
        AttestationResult with status "ISSUED", "BLOCKED", or "UNVERIFIABLE".
    """
    if not HAS_CRYPTO:
        logger.warning(
            "attestation.unverifiable query_hash=%s reason=CRYPTO_UNAVAILABLE",
            hashlib.sha256(query.encode()).hexdigest()[:16],
        )
        return AttestationResult(
            status=AttestationStatus.UNVERIFIABLE,
            token=None,
            error_code="CRYPTO_UNAVAILABLE",
            error="cryptography/PyJWT package not installed",
        )

    if proof_hash is not None and not _is_proof_hash(proof_hash):
        logger.warning(
            "attestation.blocked query_hash=%s reason=INVALID_PROOF_HASH",
            hashlib.sha256(query.encode()).hexdigest()[:16],
        )
        return AttestationResult(
            status=AttestationStatus.BLOCKED,
            token=None,
            error_code="INVALID_PROOF_HASH",
            error="proof_hash must be sha256:<64 hex>",
        )

    refusal = _admission_refusal(
        admission, status=status, verified=verified, proof_bound=bool(proof_data or proof_hash),
    )
    if refusal is not None:
        logger.warning(
            "attestation.blocked query_hash=%s reason=INVALID_ADMISSION",
            hashlib.sha256(query.encode()).hexdigest()[:16],
        )
        return AttestationResult(
            status=AttestationStatus.BLOCKED,
            token=None,
            error_code="INVALID_ADMISSION",
            error=refusal,
        )

    if verified and not (proof_data or proof_hash):
        logger.warning(
            "attestation.blocked query_hash=%s reason=VERIFIED_WITHOUT_PROOF",
            hashlib.sha256(query.encode()).hexdigest()[:16],
        )
        return AttestationResult(
            status=AttestationStatus.BLOCKED,
            token=None,
            error_code="VERIFIED_WITHOUT_PROOF",
            error="VERIFIED status requires proof_data — cannot sign attestation without proof artifact",
        )

    try:
        service = get_attestation_service()
        result = VerificationResult(
            status=status,
            verified=verified,
            engine=engine,
            confidence=confidence,
        )
        # Not stored: the token is checked once by the caller in this process
        # and not returned (#319), so keeping it would only grow memory with
        # every VERIFIED response (#320).
        attestation = service.create_attestation(
            result, query, proof_data, proof_hash=proof_hash, store=False, admission=admission
        )
        return AttestationResult(
            status=AttestationStatus.ISSUED,
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
            status=AttestationStatus.BLOCKED,
            token=None,
            error_code="SIGNING_FAILURE",
            error="Attestation signing failed — see logs for detail",
        )
