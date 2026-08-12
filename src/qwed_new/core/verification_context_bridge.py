from importlib.metadata import PackageNotFoundError, version
from typing import Optional

from .diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    DiagnosticStatus,
    admission_decision,
    enforce_trust_decision,
)
from .verification_context import (
    Admission,
    Decision,
    Evidence,
    Formalization,
    Interpretation,
    Proof,
    VerificationContext,
    VerificationContextDocument,
    VerificationContextValidationError,
)


def _resolved_verifier_version(verifier_version: Optional[str]) -> str:
    if verifier_version is not None:
        if not verifier_version.strip():
            raise VerificationContextValidationError(
                "verifier_version must be non-empty"
            )
        return verifier_version
    try:
        return version("qwed")
    except PackageNotFoundError:
        from qwed_new import __version__ as qwed_version

        return qwed_version


def verification_context_from_diagnostic_result(
    result: DiagnosticResult,
    *,
    formal_statement: str,
    verifier: str,
    verifier_version: Optional[str] = None,
    attestation_token: Optional[str] = None,
) -> VerificationContextDocument:
    if not isinstance(formal_statement, str) or not formal_statement.strip():
        raise VerificationContextValidationError(
            "formal_statement must be a non-empty string"
        )
    if not isinstance(verifier, str) or not verifier.strip():
        raise VerificationContextValidationError(
            "verifier must be a non-empty string"
        )

    if not isinstance(result.developer_fields, dict):
        result = DiagnosticResult.blocked(
            agent_message="Diagnostic result is malformed",
            developer_fields={
                "constraint_id": "verification_context.malformed_developer_fields",
            },
        )

    if result.status is DiagnosticStatus.VERIFIED:
        result = enforce_trust_decision(
            result,
            attestation_token=attestation_token,
            require_attestation=True,
            query=formal_statement,
        )

    interpretation = Interpretation(theory=f"{verifier} verification")
    proof = Proof(
        verifier=verifier,
        verifier_version=_resolved_verifier_version(verifier_version),
        outcome_treatment="unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
    )
    formalization = Formalization(
        source_query=formal_statement,
        translator=verifier,
    )
    evidence_payload = result.to_dict()

    if result.status is DiagnosticStatus.VERIFIED:
        admission = (
            Admission.ADMIT
            if admission_decision(result) is AdmissionDecision.ADMIT
            else Admission.DENY
        )
        context = VerificationContext(
            interpretation=interpretation,
            proof=proof,
            evidence=Evidence(payload=evidence_payload, proof_ref=None),
            decision=Decision(admission=admission),
        )
        return VerificationContextDocument.verified(
            formal_statement=formal_statement,
            context=context,
            formalization=formalization,
        )

    context = VerificationContext(
        interpretation=interpretation,
        proof=proof,
        evidence=Evidence(payload=evidence_payload, proof_ref=None),
        decision=Decision(admission=Admission.DENY),
    )
    if result.status is DiagnosticStatus.UNVERIFIABLE:
        return VerificationContextDocument.unverifiable(
            formal_statement=formal_statement,
            context=context,
            formalization=formalization,
        )
    if result.status is DiagnosticStatus.BLOCKED:
        return VerificationContextDocument.blocked(
            formal_statement=formal_statement,
            context=context,
            formalization=formalization,
        )
    raise VerificationContextValidationError(
        f"unsupported DiagnosticResult status: {result.status!r}"
    )
