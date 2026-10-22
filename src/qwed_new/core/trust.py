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
"""

import logging

from qwed_new.core.attestation import AttestationStatus, create_verification_attestation
from qwed_new.core.diagnostics import (
    DiagnosticResult,
    DiagnosticStatus,
    enforce_trust_decision,
)

logger = logging.getLogger(__name__)


def attest_and_enforce(dr: DiagnosticResult, *, engine: str, query: str) -> DiagnosticResult:
    """Sign a VERIFIED result and enforce its attestation as mandatory.

    The attestation binds the result's status and ``proof_ref`` and the
    query (``qwed.query_hash``); ``enforce_trust_decision`` then checks the
    token's signature and that its claims match the result and the query,
    and blocks it otherwise. ``engine`` names the engine that produced the
    verdict, recorded in the token.
    """
    if dr.status is not DiagnosticStatus.VERIFIED:
        return enforce_trust_decision(dr, require_attestation=True, query=query)

    attestation = create_verification_attestation(
        status=dr.status.value,
        # The "verified" claim follows is_valid where the engine reports one:
        # code proven unsafe is VERIFIED but not valid.
        verified=dr.developer_fields.get("is_valid") is not False,
        engine=engine,
        query=query,
        confidence=1.0,
        # The proof_ref is already the hash of the evidence: bind it as is.
        proof_hash=dr.proof_ref,
    )
    if attestation.status is not AttestationStatus.ISSUED:
        logger.warning(
            "trust_boundary.attestation_failed engine=%s status=%s",
            engine,
            attestation.status.value,
        )
        return DiagnosticResult.blocked(
            "Attestation unavailable — cannot sign VERIFIED result",
            developer_fields={
                "constraint_id": "api.attestation.signing_error",
                "attestation_error": attestation.error_code,
            },
        )
    return enforce_trust_decision(
        dr,
        require_attestation=True,
        attestation_token=attestation.token,
        query=query,
    )
