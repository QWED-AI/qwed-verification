from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    resolve_document_proof_ref,
    validate_document,
)
from qwed_new.core.verification_context_bridge import (
    verification_context_from_diagnostic_result,
)

router = APIRouter(prefix="/verification-context", tags=["VerificationContext"])


class DiagnosticVerificationContextRequest(BaseModel):
    query: str = Field(min_length=1)
    verifier: str = Field(min_length=1)
    diagnostic: Dict[str, Any]
    verifier_version: Optional[str] = None
    attestation_token: Optional[str] = None


class VerificationContextDocumentRequest(BaseModel):
    document: Dict[str, Any]


@router.post("/from-diagnostic")
def create_verification_context_from_diagnostic(
    payload: DiagnosticVerificationContextRequest,
) -> Dict[str, Any]:
    try:
        result = DiagnosticResult.from_dict(payload.diagnostic)
    except ValueError as exc:
        result = DiagnosticResult.blocked(
            agent_message="Diagnostic result is malformed",
            developer_fields={
                "constraint_id": "verification_context.malformed_diagnostic",
                "error": str(exc),
            },
        )
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
    except VerificationContextValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/validate")
def validate_verification_context(
    payload: VerificationContextDocumentRequest,
) -> Dict[str, Any]:
    try:
        validate_document(payload.document)
        return {"valid": True}
    except VerificationContextValidationError as exc:
        return {"valid": False, "error": str(exc)}


@router.post("/resolve")
def resolve_verification_context(
    payload: VerificationContextDocumentRequest,
) -> Dict[str, Any]:
    return {"resolved": resolve_document_proof_ref(payload.document)}
