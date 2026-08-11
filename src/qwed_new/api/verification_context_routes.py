from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.rate_limiter import check_rate_limit
from qwed_new.core.tenant_context import TenantContext, get_current_tenant
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    resolve_document_proof_ref,
    validate_document,
)
from qwed_new.core.verification_context_bridge import (
    verification_context_from_diagnostic_result,
)


def _authenticated_verification_context_tenant(
    tenant: TenantContext = Depends(get_current_tenant),
) -> TenantContext:
    check_rate_limit(tenant.api_key)
    return tenant


router = APIRouter(
    prefix="/verification-context",
    tags=["VerificationContext"],
    dependencies=[Depends(_authenticated_verification_context_tenant)],
)


class DiagnosticVerificationContextRequest(BaseModel):
    query: str = Field(min_length=1)
    verifier: str = Field(min_length=1)
    diagnostic: Dict[str, Any]
    verifier_version: Optional[str] = None
    attestation_token: Optional[str] = None


class VerificationContextDocumentRequest(BaseModel):
    document: Dict[str, Any]


def _malformed_diagnostic_result() -> DiagnosticResult:
    return DiagnosticResult.blocked(
        agent_message="Diagnostic result is malformed",
        developer_fields={
            "constraint_id": "verification_context.malformed_diagnostic",
        },
    )


def _diagnostic_result_from_payload(diagnostic: Any) -> DiagnosticResult:
    if not isinstance(diagnostic, dict):
        return _malformed_diagnostic_result()
    developer_fields = diagnostic.get("developer_fields", {})
    if not isinstance(developer_fields, dict):
        return _malformed_diagnostic_result()
    try:
        return DiagnosticResult.from_dict(diagnostic)
    except (ValueError, TypeError, AttributeError):
        return _malformed_diagnostic_result()


@router.post(
    "/from-diagnostic",
    responses={422: {"description": "Verification Context rejected"}},
)
def create_verification_context_from_diagnostic(
    payload: DiagnosticVerificationContextRequest,
) -> Dict[str, Any]:
    result = _diagnostic_result_from_payload(payload.diagnostic)
    try:
        document = verification_context_from_diagnostic_result(
            result,
            formal_statement=payload.query,
            verifier=payload.verifier,
            verifier_version=payload.verifier_version,
            attestation_token=payload.attestation_token,
        )
        document.validate()
        return document.to_dict()
    except VerificationContextValidationError:
        raise HTTPException(
            status_code=422,
            detail="verification context rejected",
        ) from None


@router.post("/validate")
def validate_verification_context(
    payload: VerificationContextDocumentRequest,
) -> Dict[str, Any]:
    try:
        validate_document(payload.document)
        return {"valid": True}
    except VerificationContextValidationError:
        return {"valid": False, "error": "validation_failed"}


@router.post("/resolve")
def resolve_verification_context(
    payload: VerificationContextDocumentRequest,
) -> Dict[str, Any]:
    return {"resolved": resolve_document_proof_ref(payload.document)}
