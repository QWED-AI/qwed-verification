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

import ast
import hashlib
import json
import keyword
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


class AdmissionDecision(str, Enum):
    """Admission outcome at an enforcement boundary.

    Distinct from :class:`DiagnosticStatus` by design (QWED #13 Separation of
    Responsibilities, #15 Truth Before Policy): a ``DiagnosticResult`` answers
    *"is this claim provably true?"* while an ``AdmissionDecision`` answers
    *"should this be allowed at this boundary?"* A provably-malicious query is
    ``VERIFIED`` (truth) yet ``BLOCKED`` (admission), so generic consumers that
    gate on the admission decision never accept unsafe input even when the
    underlying verification was authoritative.

    Values:
        ADMIT:   The boundary may proceed with the verdict.
        BLOCKED: The boundary must not admit. This is the fail-closed default.
    """
    ADMIT = "ADMIT"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Advisory check — structured representation of non-proof-bearing analysis.
# Used for: LLM fallback output, NLI entailment labels, VLM interpretation,
# heuristic consistency checks, basic keyword safety scans.
# Advisory checks NEVER set status or proof_ref — they populate
# developer_fields.advisory_checks for audit/developer review only.
# ---------------------------------------------------------------------------

_MAX_EQUATION_SIDE_CHARS = 4000


def _is_ident_start(ch: str) -> bool:
    return ch == "_" or "a" <= ch <= "z" or "A" <= ch <= "Z"


def _is_ident_char(ch: str) -> bool:
    return _is_ident_start(ch) or "0" <= ch <= "9"


def _is_word_or_dot(ch: str) -> bool:
    return _is_ident_char(ch) or ch == "."


def _scan_digits(text: str, i: int) -> int:
    """Advance past ASCII digits starting at *i*; single bounded loop."""
    n = len(text)
    while i < n and "0" <= text[i] <= "9":
        i += 1
    return i


def _scan_exponent_tail(text: str, i: int) -> int:
    """Consume an ``e[+-]digits`` exponent at *i*, else return *i* unchanged.

    A bare ``e`` (``2ex``) is not an exponent — the caller treats it as an
    identifier start, matching the old pattern's optional exponent group."""
    n = len(text)
    if i >= n or text[i] not in "eE":
        return i
    j = i + 1
    if j < n and text[j] in "+-":
        j += 1
    k = _scan_digits(text, j)
    if k == j:
        return i
    return k


def _scan_number(text: str, i: int) -> int:
    """End index (exclusive) of the numeric literal starting at *i*.

    Shape mirrors the old implicit-mul number pattern —
    ``digits[.digits][e[+-]digits]`` or ``.digits`` — scanned forward with
    no backtracking. Callers guarantee ``text[i]`` starts a number (an
    ASCII digit, or ``.`` followed by a digit)."""
    i = _scan_digits(text, i)
    if i < len(text) and text[i] == ".":
        i = _scan_digits(text, i + 1)
    return _scan_exponent_tail(text, i)


def _scan_ident(text: str, i: int) -> int:
    """End index (exclusive) of the identifier starting at *i*."""
    n = len(text)
    while i < n and _is_ident_char(text[i]):
        i += 1
    return i


def _skip_ws(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i] in " \t":
        i += 1
    return i


def _starts_number(side: str, i: int) -> bool:
    """True when a numeric literal starts at *i* (digit, or ``.`` + digit)."""
    ch = side[i]
    if "0" <= ch <= "9":
        return True
    return ch == "." and i + 1 < len(side) and "0" <= side[i + 1] <= "9"


def _emit_number_operand(side: str, i: int, out: List[str]) -> int:
    """Emit the number at *i* plus any implicit-mul ``*``; return next index."""
    end = _scan_number(side, i)
    j = _skip_ws(side, end)
    n = len(side)
    if j < n and _is_ident_start(side[j]):
        m = _scan_ident(side, j)
        if keyword.iskeyword(side[j:m]):
            out.append(side[i:end])
            return end
        out.append(side[i:end])
        out.append("*")
        return j
    if j < n and side[j] == "(":
        out.append(side[i:end])
        out.append("*")
        return j
    out.append(side[i:end])
    return end


def _is_implicit_application(side: str, ident: str, end: int, j: int) -> bool:
    """True for ``sin 0.5``: whitespace-separated identifier applied to a number.

    Keywords are excluded (``not 0.5`` must keep parsing), and the number
    must genuinely follow whitespace — ``x0.5`` stays untouched."""
    n = len(side)
    if j <= end or j >= n or keyword.iskeyword(ident):
        return False
    return _starts_number(side, j)


def _emit_ident_operand(side: str, i: int, out: List[str]) -> int:
    """Emit the identifier at *i*, parenthesizing ``f 0.5`` application."""
    end = _scan_ident(side, i)
    ident = side[i:end]
    j = _skip_ws(side, end)
    if not _is_implicit_application(side, ident, end, j):
        out.append(ident)
        return end
    num_end = _scan_number(side, j)
    out.append(ident)
    out.append("(")
    out.append(side[j:num_end])
    out.append(")")
    # A trailing operand (``sin 0.5x``, ``sin 0.5(x+1)``) needs an explicit
    # ``*`` — otherwise ``sin(0.5)x`` is a syntax error and the advisory is
    # lost (Sentry on #348).
    k = _skip_ws(side, num_end)
    if k < len(side) and (_is_ident_start(side[k]) or side[k] == "("):
        out.append("*")
        return k
    return num_end


def _normalize_implicit_mul(side: str) -> str:
    """Insert explicit ``*`` / call parens for implicit multiplication.

    Single left-to-right pass — O(len(side)), no backtracking by
    construction (every iteration advances ``i`` by at least one char).
    Handles ``2x``, ``2 x``, ``2(``, and ``sin 0.5``-style application so
    the advisory parser sees the constants SymPy accepts.

    Python keywords are never treated as operands: ``0.5 in [0.5, 1]``
    and ``2 if x else 3`` parse fine today, and rewriting them would
    break the parse and lose the advisory. Likewise, an identifier
    directly glued to a number (``x0.5``) is left alone — only genuine
    whitespace-separated application is parenthesized.

    Advisory-only: the result feeds float-constant extraction, never a
    verdict."""
    n = len(side)
    out: List[str] = []
    i = 0
    while i < n:
        ch = side[i]
        prev_ok = i == 0 or not _is_word_or_dot(side[i - 1])
        if _starts_number(side, i) and prev_ok:
            i = _emit_number_operand(side, i, out)
        elif _is_ident_start(ch) and prev_ok:
            i = _emit_ident_operand(side, i, out)
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _parse_expression_side(side: str) -> Optional[ast.AST]:
    try:
        return ast.parse(side, mode="eval")
    except (SyntaxError, ValueError, RecursionError):
        pass
    if len(side) > _MAX_EQUATION_SIDE_CHARS:
        # Advisory-only path: oversized sides skip normalization rather
        # than burn CPU — absence of an advisory is always safe.
        return None
    norm = _normalize_implicit_mul(side)
    if norm == side:
        return None
    try:
        return ast.parse(norm, mode="eval")
    except (SyntaxError, ValueError, RecursionError):
        # Normalization failed or unparsable side; skip
        return None


def _parse_equation_trees(source: str) -> List[ast.AST]:
    if "=" not in source:
        return []
    left, _, right = source.partition("=")
    if "=" in left or "=" in right:
        return []
    left_tree = _parse_expression_side(left.strip())
    right_tree = _parse_expression_side(right.strip())
    if left_tree is None or right_tree is None:
        return []
    return [left_tree, right_tree]


def _parse_source_trees(source: str, expression_mode: bool = True) -> List[ast.AST]:
    try:
        return [ast.parse(source, mode="eval" if expression_mode else "exec")]
    except (SyntaxError, ValueError, RecursionError):
        if expression_mode:
            return _parse_equation_trees(source)
        return []


def _extract_float_constants(trees: List[ast.AST]) -> List[str]:
    return sorted(
        {
            repr(node.value)
            for tree in trees
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, (float, complex))
        }
    )


@dataclass(frozen=True)
class AdvisoryCheck:
    """A single non-verdict-affecting advisory check.

    Advisory checks flag operational, precision, or architectural
    concerns (e.g. binary float math, deprecations, performance
    suggestions). They are strictly informational: by contract, they
    MUST NOT influence the verification verdict or proof_ref (Issue #347).
    """

    name: str
    advisory_only: bool = True
    constraint_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
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
    def float_precision(cls, source: str, expression_mode: bool = True) -> Optional["AdvisoryCheck"]:
        """Advisory: *source* contains binary floating-point constants.

        QWED_RULES.md: floating-point math is flagged and decimal.Decimal /
        SymPy exact rationals are suggested. This is a PRECISION advisory,
        never a rejection — execution-safety gates decide what may run,
        not what is exact, and documented inputs like
        `1000 * (1 + 0.05)**2` legitimately contain floats (#347).

        Equality input (`0.1 + 0.2 = 0.3`, `0.0*x = 0.0*x`) is parsed
        side-by-side to preserve lexical float literals even when symbolic
        simplification would eagerly collapse them. Complex constants count
        too: `1.0j` is binary-float-based arithmetic the same way `0.1` is.

        Returns None when the source parses clean of float/complex
        constants or cannot be parsed at all (parse failures are the
        security gates' business, not this advisory's)."""
        trees = _parse_source_trees(source, expression_mode=expression_mode)
        if not trees:
            return None
        constants = _extract_float_constants(trees)
        if not constants:
            return None
        return cls(
            name="floating-point-constants",
            constraint_id="precision.float-constants",
            details={
                "constants": constants,
                "note": (
                    "Binary floating-point values can be inexact; results "
                    "may differ from exact decimal arithmetic."
                ),
                "suggestion": (
                    "Use decimal.Decimal or SymPy exact rationals "
                    "(sympy.Rational) where exact arithmetic matters."
                ),
            },
        )

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
            constraint_id=data.get("constraint_id") or "",
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


def admission_decision(result: DiagnosticResult) -> AdmissionDecision:
    """Map a verification result to an admission decision for a SQL boundary.

    The engine's ``DiagnosticResult`` is the truth and is never modified. This
    deterministic gate turns it into a fail-closed admission outcome:

    - fail-closed status (BLOCKED/UNVERIFIABLE)         -> BLOCKED
    - ``developer_fields.is_valid is not True``          -> BLOCKED (missing/malformed)
    - authoritative (VERIFIED) and valid                 -> ADMIT
    - anything else (non-authoritative)                  -> BLOCKED

    Returning ``BLOCKED`` for a VERIFIED-but-unsafe result is a policy decision
    at the boundary (QWED #7), not a reinterpretation of the verdict (QWED #15):
    the original DiagnosticResult is preserved unchanged alongside it.
    """
    if result.is_fail_closed:
        return AdmissionDecision.BLOCKED
    if result.developer_fields.get("is_valid") is not True:
        return AdmissionDecision.BLOCKED
    if result.is_authoritative:
        return AdmissionDecision.ADMIT
    return AdmissionDecision.BLOCKED


def merge_diagnostic_result(dr: DiagnosticResult) -> Dict[str, Any]:
    """Merge DiagnosticResult with developer fields, ensuring diagnostic keys win.

    Replaces the duplicated _merge_response helpers in api.main and core.batch.
    """
    serialized = dr.to_dict()
    fields = serialized.get("developer_fields", {})
    safe = {k: v for k, v in fields.items() if k not in DIAGNOSTIC_RESPONSE_KEYS}
    return serialized | safe


def aggregate_batch_diagnostic(
    items: List[Dict[str, Any]],
    claims: List[str],
    *,
    engine: str,
    constraints: Dict[str, str],
    messages: Dict[str, str],
    extra_evidence: Optional[Dict[str, Any]] = None,
) -> DiagnosticResult:
    """Aggregate per-item verdicts into a single fail-closed batch DiagnosticResult.

    Shared by the fact/image batch verifiers (and any future batch engine) so the
    security-critical aggregation cannot drift between copies. Per-item verdicts
    live in ``developer_fields.results`` and counts in ``developer_fields.summary``.

    Fail-closed contract:
        - empty batch                      -> BLOCKED (``constraints["empty"]``)
        - any item BLOCKED                 -> BLOCKED (``constraints["blocked"]``)
        - all items VERIFIED               -> VERIFIED + ``proof_ref``
        - otherwise (some UNVERIFIABLE)    -> UNVERIFIABLE

    The batch ``proof_ref`` binds the full claim texts via SHA-256 digests (the
    truncated ``results`` claim field is display-only and not proof-bearing) plus
    any caller-supplied ``extra_evidence`` (e.g. a shared image or context digest).

    Args:
        items: Serialized per-item DiagnosticResults (each carries a ``claim`` key).
        claims: Original claim texts, aligned with ``items`` (for digests/display).
        engine: Engine name recorded in developer_fields/evidence.
        constraints: Mapping with keys ``verified``/``blocked``/``unverifiable``/``empty``.
        messages: Mapping with keys ``empty``/``blocked``/``unverifiable``/``verified``.
        extra_evidence: Optional extra proof-bearing fields merged into evidence.

    Returns:
        A single DiagnosticResult for the whole batch.
    """
    total = len(claims)

    # Fail loudly: verdict counts are taken from ``items`` while the proof binds
    # ``claims``. A length mismatch would bind digests to claims that were not
    # the ones evaluated, so reject it rather than produce a misaligned proof.
    if len(items) != total:
        raise ValueError(
            f"aggregate_batch_diagnostic: items/claims length mismatch for "
            f"{engine!r} — {len(items)} items vs {total} claims. "
            "Per-item verdicts must be aligned with the claim texts they prove."
        )

    # Fail closed: an empty batch proves nothing and must not be admitted.
    if total == 0:
        return DiagnosticResult.blocked(
            agent_message=messages["empty"],
            developer_fields={
                "constraint_id": constraints["empty"],
                "is_valid": False,
                "results": [],
                "summary": {"total": 0, "verified": 0, "unverifiable": 0, "blocked": 0},
                "engine": engine,
            },
        )

    verified = sum(1 for item in items if item["status"] == "VERIFIED")
    blocked = sum(1 for item in items if item["status"] == "BLOCKED")
    unverifiable = total - verified - blocked
    is_verified_all = verified == total

    summary = {
        "total": total,
        "verified": verified,
        "unverifiable": unverifiable,
        "blocked": blocked,
    }

    if is_verified_all:
        constraint_id = constraints["verified"]
    elif blocked:
        constraint_id = constraints["blocked"]
    else:
        constraint_id = constraints["unverifiable"]

    batch_fields: Dict[str, Any] = {
        "constraint_id": constraint_id,
        "is_valid": is_verified_all,
        "results": items,
        "summary": summary,
        "engine": engine,
    }

    if blocked > 0:
        # Fail closed: any refuted/error claim makes the whole batch non-admissible.
        return DiagnosticResult.blocked(
            agent_message=messages["blocked"],
            developer_fields=batch_fields,
        )

    if not is_verified_all:
        return DiagnosticResult.unverifiable(
            agent_message=messages["unverifiable"],
            developer_fields=batch_fields,
        )

    # Fail closed: a batch is authoritative only when every claim has a proof.
    claim_digests = [
        hashlib.sha256(claim.encode("utf-8")).hexdigest() for claim in claims
    ]
    evidence: Dict[str, Any] = {
        "engine": engine,
        "count": total,
        "claims": [
            claim if len(claim) <= 100 else claim[:100] + "..." for claim in claims
        ],
        "claim_digests": claim_digests,
        "verdicts": [
            {"status": item["status"], "is_valid": item["developer_fields"].get("is_valid")}
            for item in items
        ],
    }
    if extra_evidence:
        # Never let caller-supplied evidence overwrite the proof-bearing fields
        # assembled above; a collision would silently weaken the proof binding.
        collisions = set(extra_evidence) & set(evidence)
        if collisions:
            raise ValueError(
                f"aggregate_batch_diagnostic: extra_evidence for {engine!r} would "
                f"overwrite proof-bearing fields {sorted(collisions)}."
            )
        evidence.update(extra_evidence)

    return DiagnosticResult.verified(
        agent_message=messages["verified"],
        developer_fields=batch_fields,
        evidence=evidence,
    )


__all__ = [
    "DiagnosticStatus",
    "DiagnosticResult",
    "AdvisoryCheck",
    "AdmissionDecision",
    "compute_proof_ref",
    "enforce_trust_decision",
    "admission_decision",
    "merge_diagnostic_result",
    "aggregate_batch_diagnostic",
]
