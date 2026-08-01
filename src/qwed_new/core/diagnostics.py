"""
QWED Structured Verification Diagnostics.

Implements the 3-layer diagnostic model (Issue #204):

    Layer 1 — Agent-Safe Diagnostics
        agent_message: str
        Agent/model-facing summary. No detection logic, rule IDs, regex
        patterns, or security bypass guidance. Allows agents to correct
        failures without exposing verification internals.

    Layer 2 — Developer Diagnostics
        developer_fields: dict
        Application-developer-facing structured evidence. Includes
        constraint_id, expected/actual values, advisory_checks, methods_used,
        engine-specific evidence. Structured, not free-form strings.

    Layer 3 — Proof Diagnostics
        proof_ref: Optional[str]
        Cryptographic hash of retained proof artifact (sha256:...).
        Present only when status == VERIFIED and proof was established.
        None for UNVERIFIABLE / BLOCKED — this is the authority bit:
        downstream gates reject proof_ref is None for control flow.

Constraints (non-negotiable, per #204):
- Diagnostics are NOT explainability. No confidence scores, no chain-of-thought,
  no model reasoning in diagnostic output.
- All diagnostic fields must originate from verification results, constraints,
  rule evaluation, schema validation, or proof systems.
- Agent-safe diagnostics must never expose detection logic, rule IDs, regex
  patterns, or security bypass guidance.
- VERIFIED requires proof_ref is not None — structurally enforced.
- Existing fail-closed behavior must not be weakened.

This module establishes the contract. Engine conformance (migrating ad-hoc
Dict[str, Any] returns to DiagnosticResult) is tracked in blocked issues:
#129, #130, #131, #133, #134, #162, #163, #164, #190, #205.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Status taxonomy — intentionally small to avoid proliferation.
# Per #190 discussion (Keesan/Rahul): ambiguity IS unverifiability; the
# distinction lives in developer_fields.constraint_id, not in status values.
# ---------------------------------------------------------------------------

class DiagnosticStatus(str, Enum):
    """Verification diagnostic status.

    Three states only — no HEURISTIC, AMBIGUOUS, or CORRECTION_NEEDED.
    Richer distinctions live in developer_fields, not status.

    VERIFIED:
        The claim was deterministically proven. proof_ref MUST be present.
        Downstream gates MAY admit for control flow.

    UNVERIFIABLE:
        The claim could not be proven. proof_ref MUST be None.
        Reasons: insufficient evidence, ambiguous input, model-only support,
        missing provider path, non-convergent computation.
        Downstream gates MUST NOT admit for control flow.

    BLOCKED:
        Verification could not even be attempted. proof_ref MUST be None.
        Reasons: missing declarations, parse error, configuration failure,
        security policy violation, missing dependency.
        Downstream gates MUST NOT admit for control flow.
    """
    VERIFIED = "VERIFIED"
    UNVERIFIABLE = "UNVERIFIABLE"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Advisory check — structured representation of non-proof-bearing analysis.
# Used for: LLM fallback output, NLI entailment labels, VLM interpretation,
# heuristic consistency checks, basic keyword safety scans.
# Advisory checks NEVER set status or proof_ref — they populate
# developer_fields.advisory_checks for audit/developer review only.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AdvisoryCheck:
    """A non-proof-bearing analysis result attached as advisory metadata.

    Advisory checks may carry useful information for developers or auditors,
    but they MUST NOT influence the verification verdict. The constraint:

        advisory_only = True

    is structurally enforced: advisory checks populate
    developer_fields.advisory_checks, never status or proof_ref.
    """
    name: str
    advisory_only: bool = True
    constraint_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.advisory_only is not True:
            raise ValueError(
                "AdvisoryCheck.advisory_only must be True — "
                "advisory checks must never influence the verification verdict."
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "advisory_only": self.advisory_only,
            "constraint_id": self.constraint_id,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdvisoryCheck":
        raw_advisory_only = data.get("advisory_only", True)
        if isinstance(raw_advisory_only, bool):
            advisory_only = raw_advisory_only
        elif isinstance(raw_advisory_only, int) and raw_advisory_only in (0, 1):
            advisory_only = bool(raw_advisory_only)
        else:
            raise ValueError(
                "AdvisoryCheck.advisory_only must be a bool or integer 0/1"
            )

        return cls(
            name=data.get("name", ""),
            advisory_only=advisory_only,
            constraint_id=data.get("constraint_id"),
            details=data.get("details", {}),
        )


# ---------------------------------------------------------------------------
# Proof reference computation — deterministic hash of retained evidence.
# ---------------------------------------------------------------------------

def compute_proof_ref(evidence: Dict[str, Any] | str) -> str:
    """Compute a deterministic proof reference hash from retained evidence.

    The proof_ref binds the verdict (status=VERIFIED) to the specific evidence
    that justified it. If the evidence changes, the hash changes — making
    verdict/evidence drift structurally detectable.

    Args:
        evidence: The proof artifact dict (e.g., convergence trace, frequency
                  counts, eigenvalue comparison, Z3 assertion stack) or a
                  pre-serialized string. When a string is passed, it is hashed
                  directly — this ensures callers can pass the same
                  ``json.dumps(evidence_dict, sort_keys=True)`` that the
                  attestation issuer used as ``proof_data``, guaranteeing the
                  resulting hash matches the attestation token's ``proof_hash``.

    Returns:
        sha256-prefixed hex digest string, e.g. "sha256:abcdef...".

    Note:
        When a dict is passed, it is JSON-serialized with sort_keys=True for
        deterministic hashing. Non-JSON-serializable values must be
        pre-converted to strings by the caller — they will raise
        ValueError (fail-closed), preventing non-deterministic memory-
        address-dependent hashes from entering the proof contract.
    """
    if isinstance(evidence, str):
        payload = evidence
    else:
        try:
            payload = json.dumps(evidence, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Proof evidence must be JSON-serializable for proof_ref hashing: {exc}"
            ) from exc
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# DiagnosticResult — the unified 3-layer diagnostic model.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DiagnosticResult:
    """Unified verification diagnostic result (Issue #204).

    Replaces the 3 incompatible VerificationResult dataclasses and the ad-hoc
    Dict[str, Any] returns across verification engines.

    Three layers:
        1. agent_message   — Layer 1 (agent-safe, no internals)
        2. developer_fields — Layer 2 (structured developer evidence)
        3. proof_ref        — Layer 3 (cryptographic proof artifact hash)

    Authority contract:
        proof_ref is not None  → authoritative, admissible for control flow
        proof_ref is None      → non-authoritative, NOT admissible for control flow

    This is the mechanical rule downstream gates use (per #190 Keesan
    discussion): no separate `authoritative` boolean needed.

    Constraints enforced in __post_init__:
        - status == VERIFIED  requires proof_ref is not None
        - status == UNVERIFIABLE or BLOCKED  requires proof_ref is None
        - agent_message must be non-empty
    """

    status: DiagnosticStatus
    agent_message: str
    developer_fields: Dict[str, Any] = field(default_factory=dict)
    proof_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.agent_message or not self.agent_message.strip():
            raise ValueError(
                "agent_message must be non-empty — Layer 1 diagnostics are mandatory"
            )

        if self.status is DiagnosticStatus.VERIFIED and not self.proof_ref:
            raise ValueError(
                "VERIFIED status requires proof_ref is not None and non-empty — "
                "a claim cannot be marked proven without a proof artifact hash. "
                "Use UNVERIFIABLE if no proof was established."
            )

        if self.status is not DiagnosticStatus.VERIFIED and self.proof_ref is not None:
            raise ValueError(
                f"{self.status.value} status requires proof_ref is None — "
                "non-VERIFIED states are non-authoritative by construction."
            )

    @property
    def is_verified(self) -> bool:
        """True only when status is VERIFIED (which implies proof_ref is not None)."""
        return self.status is DiagnosticStatus.VERIFIED

    @property
    def is_authoritative(self) -> bool:
        """Authority bit — True when proof_ref is present (admissible for control flow).

        This is Keesan's `authoritative=true` from #190, expressed as
        proof_ref presence rather than a separate boolean. Downstream gates:

            if not result.is_authoritative:
                block_decision()  # non-authoritative — reject for control flow
        """
        return self.proof_ref is not None

    @property
    def is_fail_closed(self) -> bool:
        """True when status is UNVERIFIABLE or BLOCKED (non-pass, fail-closed)."""
        return self.status in (DiagnosticStatus.UNVERIFIABLE, DiagnosticStatus.BLOCKED)

    @property
    def constraint_id(self) -> Optional[str]:
        """The primary constraint identifier from developer_fields, if present."""
        return self.developer_fields.get("constraint_id")

    @property
    def advisory_checks(self) -> List[AdvisoryCheck]:
        """Advisory checks from developer_fields, deserialized to AdvisoryCheck.

        Defensive: skips malformed or invalid items rather than raising.
        Only dicts (converted via from_dict) and existing AdvisoryCheck
        instances are included. This ensures the property never raises
        ValueError at access time (Greptile P1) and doesn't propagate
        garbage (CodeRabbit fail-closed suggestion).
        """
        raw = self.developer_fields.get("advisory_checks", [])
        if not isinstance(raw, list):
            return []
        result = []
        for item in raw:
            if isinstance(item, dict):
                try:
                    result.append(AdvisoryCheck.from_dict(item))
                except ValueError:
                    # Invalid advisory metadata is non-authoritative; skip it.
                    continue
            elif isinstance(item, AdvisoryCheck):
                result.append(item)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for API/SDK responses and attestation claims.

        Returns a flat dict with all three layers. AdvisoryCheck instances
        in developer_fields['advisory_checks'] are serialized to dicts.
        """
        # Deep-copy developer_fields and serialize any AdvisoryCheck instances
        fields = dict(self.developer_fields)
        checks = fields.get("advisory_checks")
        if isinstance(checks, list):
            fields["advisory_checks"] = [
                item.to_dict() if isinstance(item, AdvisoryCheck) else item
                for item in checks
            ]
        return {
            "status": self.status.value,
            "agent_message": self.agent_message,
            "developer_fields": fields,
            "proof_ref": self.proof_ref,
            "is_authoritative": self.is_authoritative,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagnosticResult":
        """Deserialize from dict (e.g., API response, attestation claim).

        Tolerates status as str or DiagnosticStatus. Tolerates missing
        developer_fields (defaults to empty dict).

        Raises:
            ValueError: If agent_message is missing or empty — Layer 1
                        diagnostics are mandatory and cannot be defaulted
                        during deserialization.
            ValueError: If status is a string not in DiagnosticStatus —
                        use from_legacy_dict() for pre-#204 engine data.
        """
        status = data.get("status", "UNVERIFIABLE")
        if isinstance(status, str):
            try:
                status = DiagnosticStatus(status)
            except ValueError:
                valid = ", ".join(s.value for s in DiagnosticStatus)
                raise ValueError(
                    f"from_dict: invalid status {status!r} — "
                    f"must be one of: {valid}. "
                    "Use from_legacy_dict() for pre-#204 engine data."
                ) from None

        agent_message = data.get("agent_message")
        if not agent_message or not str(agent_message).strip():
            raise ValueError(
                "from_dict: 'agent_message' is missing or empty — "
                "Layer 1 diagnostics are mandatory for DiagnosticResult deserialization."
            )

        return cls(
            status=status,
            agent_message=agent_message,
            developer_fields=data.get("developer_fields", {}),
            proof_ref=data.get("proof_ref"),
        )

    @classmethod
    def verified(
        cls,
        agent_message: str,
        developer_fields: Dict[str, Any],
        evidence: Dict[str, Any],
        proof_data: Optional[str] = None,
    ) -> "DiagnosticResult":
        """Construct a VERIFIED result with proof_ref computed from evidence.

        Args:
            agent_message: Agent-safe summary (Layer 1).
            developer_fields: Structured developer evidence (Layer 2).
            evidence: Proof artifact dict — hashed to produce proof_ref (Layer 3).
            proof_data: Optional pre-serialized proof string. When provided,
                ``proof_ref`` is computed directly from this string (via
                :func:`compute_proof_ref`) instead of from *evidence*. This
                ensures the hash matches the attestation token's ``proof_hash``
                when the same string is passed as ``proof_data`` to
                :func:`create_verification_attestation`.

        Returns:
            DiagnosticResult with status=VERIFIED and proof_ref=compute_proof_ref(evidence).
        """
        return cls(
            status=DiagnosticStatus.VERIFIED,
            agent_message=agent_message,
            developer_fields=developer_fields,
            proof_ref=compute_proof_ref(proof_data if proof_data is not None else evidence),
        )

    @classmethod
    def unverifiable(
        cls,
        agent_message: str,
        developer_fields: Optional[Dict[str, Any]] = None,
    ) -> "DiagnosticResult":
        """Construct an UNVERIFIABLE result (non-pass, non-authoritative).

        Args:
            agent_message: Agent-safe summary of why verification was inconclusive.
            developer_fields: Structured developer evidence (constraint_id, etc.).

        Returns:
            DiagnosticResult with status=UNVERIFIABLE and proof_ref=None.
        """
        return cls(
            status=DiagnosticStatus.UNVERIFIABLE,
            agent_message=agent_message,
            developer_fields=developer_fields or {},
            proof_ref=None,
        )

    @classmethod
    def blocked(
        cls,
        agent_message: str,
        developer_fields: Optional[Dict[str, Any]] = None,
    ) -> "DiagnosticResult":
        """Construct a BLOCKED result (verification could not be attempted).

        Args:
            agent_message: Agent-safe summary of why verification was blocked.
            developer_fields: Structured developer evidence (constraint_id, etc.).

        Returns:
            DiagnosticResult with status=BLOCKED and proof_ref=None.
        """
        return cls(
            status=DiagnosticStatus.BLOCKED,
            agent_message=agent_message,
            developer_fields=developer_fields or {},
            proof_ref=None,
        )

    @classmethod
    def from_legacy_dict(cls, data: Dict[str, Any], engine: str = "unknown") -> "DiagnosticResult":
        """Migration helper: convert ad-hoc engine dict to DiagnosticResult.

        Interprets the common pre-#204 patterns:
            {"is_correct": True, "status": "VERIFIED", ...}  → VERIFIED
            {"is_correct": False, "status": "CORRECTION_NEEDED", ...}  → UNVERIFIABLE
            {"is_correct": False, "status": "BLOCKED", ...}  → BLOCKED
            {"is_correct": False, "status": "ERROR", "error": ...}  → BLOCKED
            {"is_correct": False, "status": "SYNTAX_ERROR", ...}  → BLOCKED
            {"verified": False, "message": ...}  → UNVERIFIABLE

        Note:
            Legacy VERIFIED results get proof_ref=None because the original
            engine did not retain proof artifacts. This means from_legacy_dict
            CANNOT produce a VERIFIED DiagnosticResult — it will raise
            ValueError for legacy "VERIFIED" inputs, because VERIFIED requires
            proof_ref. Callers must use DiagnosticResult.verified() with
            explicit evidence for true VERIFIED results.

            This is intentional: the migration helper is for fail-closed
            states, not for backfilling proof artifacts that were discarded.

        Args:
            data: The legacy ad-hoc dict from an engine.
            engine: Engine name for constraint_id namespacing.

        Returns:
            DiagnosticResult (UNVERIFIABLE or BLOCKED for non-pass legacy states).

        Raises:
            ValueError: If legacy data indicates VERIFIED — caller must use
                        DiagnosticResult.verified() with explicit evidence.
            ValueError: If legacy data is unrecognized (no known status pattern
                        and is_correct is truthy but not matching any branch) —
                        fail-loudly per QWED_RULES to surface unexpected formats.
        """
        legacy_status = data.get("status", "")
        is_correct = data.get("is_correct", data.get("is_verified", data.get("verified", False)))
        error = data.get("error")
        message = data.get("message", data.get("reasoning", ""))

        # Only explicit "VERIFIED" status is rejected here — truthy is_correct
        # with unknown status falls through to the unrecognized-pattern raise below.
        if legacy_status == "VERIFIED":
            raise ValueError(
                "from_legacy_dict cannot migrate VERIFIED results — "
                "proof artifacts were not retained by legacy engines. "
                "Use DiagnosticResult.verified() with explicit evidence dict."
            )

        if legacy_status == "BLOCKED":
            agent_message = message or "Verification blocked"
            return cls.blocked(
                agent_message=agent_message,
                developer_fields={
                    "constraint_id": f"{engine}.legacy_blocked",
                    "legacy_error": error,
                    "legacy_data": {k: v for k, v in data.items()
                                    if k not in ("status", "is_correct", "error")},
                },
            )

        if legacy_status in ("ERROR", "SYNTAX_ERROR", "PARSE_ERROR"):
            agent_message = "Verification blocked — processing error"
            return cls.blocked(
                agent_message=agent_message,
                developer_fields={
                    "constraint_id": f"{engine}.legacy_error",
                    "legacy_error": error or message,
                    "legacy_status": legacy_status,
                },
            )

        if legacy_status in ("CORRECTION_NEEDED", "NOT_EQUIVALENT", "INCONCLUSIVE",
                             "INSUFFICIENT_EVIDENCE", "NO_PROOF"):
            agent_message = message or "Verification inconclusive"
            return cls.unverifiable(
                agent_message=agent_message,
                developer_fields={
                    "constraint_id": f"{engine}.legacy_inconclusive",
                    "legacy_status": legacy_status,
                    "legacy_data": {k: v for k, v in data.items()
                                    if k not in ("status", "is_correct", "error", "message")},
                },
            )

        if not bool(is_correct):
            if error:
                return cls.blocked(
                    agent_message="Verification blocked",
                    developer_fields={
                        "constraint_id": f"{engine}.legacy_error",
                        "legacy_error": error,
                    },
                )
            return cls.unverifiable(
                agent_message=message or "Verification inconclusive",
                developer_fields={
                    "constraint_id": f"{engine}.legacy_inconclusive",
                },
            )

        # Unrecognized legacy pattern — fail loudly per QWED_RULES
        raise ValueError(
            f"from_legacy_dict cannot interpret unrecognized legacy data from {engine!r}: "
            f"status={legacy_status!r}, is_correct={is_correct!r}. "
            "Review engine output format and add explicit handling."
        )


# ---------------------------------------------------------------------------
# Trust boundary enforcement — consumption-side attestation validation.
# Issue #191: No trust-boundary path can return/consume effective VERIFIED
# without required attestation artifact.
# ---------------------------------------------------------------------------

def _compute_query_hash(query: str) -> str:
    """Compute a query hash in the same format as AttestationService._hash_content."""
    return f"sha256:{hashlib.sha256(query.encode('utf-8')).hexdigest()}"


def _verify_attestation_token(
    attestation_token: str,
    trusted_issuers: Optional[List[str]],
    result: DiagnosticResult,
    policy: str,
) -> Optional[Tuple[bool, Dict[str, Any], Optional[str]]]:
    """Verify the attestation token, returning (is_valid, claims, error) or a blocked result."""
    try:
        from .attestation import get_attestation_service

        service = get_attestation_service()
        is_valid, token_claims, error = service.verify_attestation(
            attestation_token,
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        logger.warning(
            "trust_gate.blocked constraint_id=%s reason=attestation_verification_failed "
            "error=%s policy=%s",
            result.constraint_id or "unknown",
            exc,
            policy,
        )
        return DiagnosticResult.blocked(
            agent_message="Verification blocked — proof artifact verification failed",
            developer_fields={
                "constraint_id": "trust_gate.attestation_verification_error",
                "error": str(exc),
                "policy": policy,
                "verdict_status": result.status.value,
                "verdict_proof_ref": result.proof_ref,
            },
        )

    if not is_valid:
        logger.warning(
            "trust_gate.blocked constraint_id=%s reason=invalid_attestation_token error=%s policy=%s",
            result.constraint_id or "unknown",
            error,
            policy,
        )
        return DiagnosticResult.blocked(
            agent_message="Verification blocked — proof artifact invalid",
            developer_fields={
                "constraint_id": "trust_gate.invalid_attestation_token",
                "validation_error": error,
                "policy": policy,
                "verdict_status": result.status.value,
                "verdict_proof_ref": result.proof_ref,
            },
        )

    return is_valid, token_claims, error


def _validate_attestation_claims(
    result: DiagnosticResult,
    token_claims: Dict[str, Any],
    query: Optional[str],
    policy: str,
) -> Optional[DiagnosticResult]:
    """Validate token claims against result. Returns a blocked result or None."""
    raw_qwed = (token_claims or {}).get("qwed")
    qwed_claims = raw_qwed if isinstance(raw_qwed, dict) else None
    raw_result_claims = qwed_claims.get("result") if qwed_claims else None
    result_claims = raw_result_claims if isinstance(raw_result_claims, dict) else None
    if result_claims is None:
        logger.warning(
            "trust_gate.blocked constraint_id=%s reason=claims_missing_or_malformed policy=%s",
            result.constraint_id or "unknown",
            policy,
        )
        return DiagnosticResult.blocked(
            agent_message="Verification blocked — attestation claims missing or malformed",
            developer_fields={
                "constraint_id": "trust_gate.claims_missing",
                "policy": policy,
                "verdict_status": result.status.value,
                "verdict_proof_ref": result.proof_ref,
            },
        )

    token_status = result_claims.get("status")
    if token_status != result.status.value:
        logger.warning(
            "trust_gate.blocked constraint_id=%s reason=claims_status_mismatch "
            "token_status=%s result_status=%s policy=%s",
            result.constraint_id or "unknown",
            token_status,
            result.status.value,
            policy,
        )
        return DiagnosticResult.blocked(
            agent_message="Verification blocked — attestation claims do not match result status",
            developer_fields={
                "constraint_id": "trust_gate.claims_status_mismatch",
                "token_status": token_status,
                "result_status": result.status.value,
                "policy": policy,
            },
        )

    if query is not None:
        expected_query_hash = _compute_query_hash(query)
        token_query_hash = qwed_claims.get("query_hash")
        if token_query_hash != expected_query_hash:
            logger.warning(
                "trust_gate.blocked constraint_id=%s reason=claims_query_mismatch policy=%s",
                result.constraint_id or "unknown",
                policy,
            )
            return DiagnosticResult.blocked(
                agent_message="Verification blocked — attestation query hash does not match",
                developer_fields={
                    "constraint_id": "trust_gate.claims_query_mismatch",
                    "expected_query_hash": expected_query_hash,
                    "token_query_hash": token_query_hash,
                    "policy": policy,
                },
            )

    token_proof_hash = qwed_claims.get("proof_hash")
    if token_proof_hash != result.proof_ref:
        logger.warning(
            "trust_gate.blocked constraint_id=%s reason=claims_proof_mismatch policy=%s",
            result.constraint_id or "unknown",
            policy,
        )
        return DiagnosticResult.blocked(
            agent_message="Verification blocked — attestation proof hash does not match result",
            developer_fields={
                "constraint_id": "trust_gate.claims_proof_mismatch",
                "token_proof_hash": token_proof_hash,
                "result_proof_ref": result.proof_ref,
                "policy": policy,
            },
        )

    return None


def _snapshot_developer_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild developer_fields as a fully detached, trusted snapshot.

    deepcopy() is NOT sufficient here: a nested object may implement
    __deepcopy__ to return itself, preserving an alias to caller data that
    remains mutable after enforcement (TOCTOU). Instead, containers are
    rebuilt from scratch and only immutable scalars, AdvisoryCheck, and
    JSON-safe containers (dict / list / tuple) are admitted. Any other value
    type is rejected so the caller's objects can never leak into the enforced
    result.

    Raises:
        ValueError: if a value type is not admitted (fail closed by caller).
    """
    if isinstance(fields, dict):
        return {
            str(key): _snapshot_developer_fields(value)
            for key, value in fields.items()
        }
    if isinstance(fields, list):
        return [_snapshot_developer_fields(item) for item in fields]
    if isinstance(fields, tuple):
        return tuple(_snapshot_developer_fields(item) for item in fields)
    if isinstance(fields, AdvisoryCheck):
        return AdvisoryCheck(
            name=fields.name,
            advisory_only=fields.advisory_only,
            constraint_id=fields.constraint_id,
            details=_snapshot_developer_fields(fields.details),
        )
    if fields is None or isinstance(fields, (str, int, float, bool)):
        return fields
    raise ValueError(
        f"developer_fields contains unsupported value type: {type(fields).__name__}"
    )


def enforce_trust_decision(
    result: DiagnosticResult,
    *,
    attestation_token: Optional[str] = None,
    require_attestation: bool = True,
    trusted_issuers: Optional[List[str]] = None,
    query: Optional[str] = None,
) -> DiagnosticResult:
    """Enforce trust-boundary gate: VERIFIED without required attestation → BLOCKED.

    This is the single enforcement point for consumption-side attestation
    validation. Every release gate / trust boundary MUST route verification
    results through this function before making admission decisions.

    Args:
        result: The verification DiagnosticResult from the engine.
        attestation_token: The JWT attestation token (from
            attestation.create_verification_attestation). May be None.
        require_attestation: If True (default), VERIFIED without a valid
            attestation token is blocked. If False, attestation is advisory.
        trusted_issuers: Optional list of trusted issuer DIDs for token
            verification. Defaults to None (uses AttestationService default).
        query: Original query string for query_hash binding validation.
            If provided, the attestation token's qwed.query_hash claim must
            match sha256(query). Without it, query binding is not checked.

    Returns:
        The original DiagnosticResult if all policy checks pass, or a BLOCKED
        DiagnosticResult with fail-closed semantics if attestation is missing,
        invalid, or claims do not match the result.

    Audit event:
        Every block decision is logged at WARNING level with structured
        fields: constraint_id, reason, policy, and error where applicable.
    """
    policy = "mandatory" if require_attestation else "optional"

    # Issue #273 — TOCTOU: detach the caller's mutable developer_fields before
    # any validation reads the result. DiagnosticResult is frozen=True, but
    # developer_fields is a deeply mutable Dict[str, Any]; returning the
    # caller's original reference would let out-of-band mutation after
    # enforcement diverge the returned state from the validated state. The
    # snapshot below is read during validation AND returned, so a concurrent
    # mutation of the caller's object can neither skew the decision nor leak
    # into the returned result. The snapshot rebuilds containers recursively
    # (never deepcopy) so a nested object whose __deepcopy__ returns itself
    # cannot smuggle a mutable alias into the enforced result.
    try:
        result = replace(
            result,
            developer_fields=_snapshot_developer_fields(result.developer_fields),
        )
    except Exception as exc:
        # developer_fields is Dict[str, Any] — a value that rejects snapshoting
        # (or a concurrent mutation mid-snapshot) must fail closed, not escape
        # as an exception. Log only the exception type, never args/message, so
        # no caller data leaks into the audit trail.
        logger.warning(
            "trust_gate.blocked reason=diagnostic_snapshot_failed policy=%s error_type=%s",
            policy,
            type(exc).__name__,
        )
        return DiagnosticResult.blocked(
            agent_message="Verification blocked — diagnostic snapshot failed",
            developer_fields={
                "constraint_id": "trust_gate.diagnostic_snapshot_failed",
                "policy": policy,
            },
        )

    if result.is_fail_closed:
        return result

    if not attestation_token:
        if not require_attestation:
            return result
        logger.warning(
            "trust_gate.blocked constraint_id=%s reason=missing_attestation_token policy=%s",
            result.constraint_id or "unknown",
            policy,
        )
        return DiagnosticResult.blocked(
            agent_message="Verification blocked — proof artifact missing",
            developer_fields={
                "constraint_id": "trust_gate.mandatory_attestation_missing",
                "missing": "attestation_token",
                "policy": policy,
                "verdict_status": result.status.value,
                "verdict_proof_ref": result.proof_ref,
            },
        )

    verification = _verify_attestation_token(attestation_token, trusted_issuers, result, policy)
    if isinstance(verification, DiagnosticResult):
        return verification
    _is_valid, token_claims, _error = verification

    validation = _validate_attestation_claims(result, token_claims, query, policy)
    if validation is not None:
        return validation

    return result


DIAGNOSTIC_RESPONSE_KEYS = frozenset({
    "status", "agent_message", "developer_fields", "proof_ref", "is_authoritative",
})


def merge_diagnostic_result(dr: DiagnosticResult) -> Dict[str, Any]:
    """Merge DiagnosticResult with developer fields, ensuring diagnostic keys win.

    Replaces the duplicated _merge_response helpers in api.main and core.batch.
    """
    serialized = dr.to_dict()
    fields = serialized.get("developer_fields", {})
    safe = {k: v for k, v in fields.items() if k not in DIAGNOSTIC_RESPONSE_KEYS}
    return serialized | safe


__all__ = [
    "DiagnosticStatus",
    "DiagnosticResult",
    "AdvisoryCheck",
    "compute_proof_ref",
    "enforce_trust_decision",
    "merge_diagnostic_result",
]
