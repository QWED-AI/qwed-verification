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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


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

@dataclass
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
        return cls(
            name=data.get("name", ""),
            advisory_only=bool(data.get("advisory_only", True)),
            constraint_id=data.get("constraint_id"),
            details=data.get("details", {}),
        )


# ---------------------------------------------------------------------------
# Proof reference computation — deterministic hash of retained evidence.
# ---------------------------------------------------------------------------

def compute_proof_ref(evidence: Dict[str, Any]) -> str:
    """Compute a deterministic proof reference hash from retained evidence.

    The proof_ref binds the verdict (status=VERIFIED) to the specific evidence
    that justified it. If the evidence changes, the hash changes — making
    verdict/evidence drift structurally detectable.

    Args:
        evidence: The proof artifact dict (e.g., convergence trace, frequency
                  counts, eigenvalue comparison, Z3 assertion stack).

    Returns:
        sha256-prefixed hex digest string, e.g. "sha256:abcdef...".

    Note:
        The evidence dict is JSON-serialized with sort_keys=True for
        deterministic hashing. Non-JSON-serializable values must be
        pre-converted to strings by the caller — they will raise
        ValueError (fail-closed), preventing non-deterministic memory-
        address-dependent hashes from entering the proof contract.
    """
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

@dataclass
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

        if self.status is DiagnosticStatus.VERIFIED and self.proof_ref is None:
            raise ValueError(
                "VERIFIED status requires proof_ref is not None — "
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
                    pass
            elif isinstance(item, AdvisoryCheck):
                result.append(item)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for API/SDK responses and attestation claims.

        Returns a flat dict with all three layers. advisory_checks are
        serialized as dicts inside developer_fields.
        """
        return {
            "status": self.status.value,
            "agent_message": self.agent_message,
            "developer_fields": self.developer_fields,
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
        """
        status = data.get("status", "UNVERIFIABLE")
        if isinstance(status, str):
            status = DiagnosticStatus(status)

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
    ) -> "DiagnosticResult":
        """Construct a VERIFIED result with proof_ref computed from evidence.

        Args:
            agent_message: Agent-safe summary (Layer 1).
            developer_fields: Structured developer evidence (Layer 2).
            evidence: Proof artifact dict — hashed to produce proof_ref (Layer 3).

        Returns:
            DiagnosticResult with status=VERIFIED and proof_ref=compute_proof_ref(evidence).
        """
        return cls(
            status=DiagnosticStatus.VERIFIED,
            agent_message=agent_message,
            developer_fields=developer_fields,
            proof_ref=compute_proof_ref(evidence),
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


__all__ = [
    "DiagnosticStatus",
    "DiagnosticResult",
    "AdvisoryCheck",
    "compute_proof_ref",
]
