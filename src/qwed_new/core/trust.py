"""Mandatory attestation for VERIFIED results (#320).

A VERIFIED result is a protocol guarantee (QWED_RULES.md section 14): a
consumer applying the admission rule admits it. The control plane's maths path
signs every VERIFIED result and enforces the attestation as mandatory; the
other verify routes used an advisory wrapper, so a VERIFIED result left the
server with no attestation ever issued or checked.

``attest_and_enforce`` gives every route the control plane's treatment: sign
the VERIFIED result, then enforce the attestation as mandatory. A result
that is not VERIFIED (UNVERIFIABLE or BLOCKED) is already fail closed and
passes through unchanged. If signing fails, the result is BLOCKED.

A VERIFIED result that passes carries its token (``attestation``), so the
response delivers it and a consumer can check it against the server's JWKS
(#319). On a route that decides an admission, the token signs that decision
too (``qwed.admission``, #321), so a consumer can check the server's ADMIT or
BLOCKED as well as its verdict.
"""

import logging
import math
from collections.abc import Callable

from qwed_new.core.attestation import AttestationStatus, create_verification_attestation
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    DiagnosticStatus,
    enforce_trust_decision,
)

# How a route decides its admission from the verdict: admission_decision, or
# natural_language_admission for a verdict reached through a translation.
AdmissionRule = Callable[[DiagnosticResult], AdmissionDecision]

logger = logging.getLogger(__name__)


def _attested_statement(dr: DiagnosticResult, query: str) -> str:
    """What the verdict is about, for the attestation's query binding.

    A natural-language verdict covers the expression the LLM translated the
    question into, not the question (the control plane marks it with
    ``verification_scope``), so its attestation binds that expression, as the
    control plane's own attestation does. Any other verdict binds the query.
    """
    fields = dr.developer_fields
    expression = fields.get("translated_expression")
    if fields.get("verification_scope") == "translated_expression_only" and isinstance(expression, str) and expression:
        return expression
    return query


def _confidence(dr: DiagnosticResult) -> float:
    """The engine's own confidence where it reports one in [0, 1] (consensus
    does), otherwise 1.0, as for a deterministic proof."""
    value = dr.developer_fields.get("confidence")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0.0 <= value <= 1.0:
        return float(value)
    return 1.0


def attest_and_enforce(
    dr: DiagnosticResult,
    *,
    engine: str,
    query: str,
    admission: AdmissionRule | None = None,
) -> DiagnosticResult:
    """Sign a VERIFIED result and enforce its attestation as mandatory.

    The attestation binds the result's status and ``proof_ref`` and what the
    verdict is about (``qwed.query_hash``, see ``_attested_statement``);
    ``enforce_trust_decision`` then checks the token's signature and that its
    claims match, and blocks the result otherwise. ``engine`` names the engine
    that produced the verdict, recorded in the token.

    ``admission`` is the rule the route decides its admission with. When
    given, the token also signs ``admission(dr)`` (``qwed.admission``,
    #321): the route returns the same rule applied to the returned result,
    which is ``dr`` itself whenever a token is attached, so the two agree.
    """
    statement = _attested_statement(dr, query)
    if dr.status is not DiagnosticStatus.VERIFIED:
        return enforce_trust_decision(dr, require_attestation=True, query=statement)

    decision = admission(dr).value if admission is not None else None

    attestation = create_verification_attestation(
        status=dr.status.value,
        # The "verified" claim follows is_valid where the engine reports one:
        # code proven unsafe is VERIFIED but not valid.
        verified=dr.developer_fields.get("is_valid") is not False,
        engine=engine,
        query=statement,
        confidence=_confidence(dr),
        # The proof_ref is already the hash of the evidence: bind it as is.
        proof_hash=dr.proof_ref,
        admission=decision,
    )
    if attestation.status is not AttestationStatus.ISSUED:
        logger.warning(
            "trust_boundary.attestation_failed engine=%s status=%s",
            engine,
            attestation.status.value,
        )
        # Fail closed, but keep what the engine concluded beside the block,
        # as enforce_trust_decision does for a missing token, so the audit
        # row records the verdict that was not admitted.
        return DiagnosticResult.blocked(
            "Attestation unavailable — cannot sign VERIFIED result",
            developer_fields={
                "constraint_id": "api.attestation.signing_error",
                "attestation_error": attestation.error_code,
                "engine": engine,
                "verdict_status": dr.status.value,
                "verdict_proof_ref": dr.proof_ref,
            },
        )
    enforced = enforce_trust_decision(
        dr,
        require_attestation=True,
        attestation_token=attestation.token,
        query=statement,
        admission=decision,
    )
    if enforced.status is not DiagnosticStatus.VERIFIED:
        return enforced
    # Delivered with the result, so a consumer can check the verdict against
    # the server's JWKS (#319). Only a token that has just passed the checks
    # above is attached.
    return enforced.with_attestation(attestation.token)
