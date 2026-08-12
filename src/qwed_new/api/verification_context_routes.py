from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import Any, Dict, Optional
import json

from qwed_new.core.database import get_session
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.models import VerificationLog
from qwed_new.core.rate_limiter import check_rate_limit
from qwed_new.core.security import redact_pii
from qwed_new.core.tenant_context import TenantContext, get_current_tenant
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    resolve_document_proof_ref,
    validate_document,
)
from qwed_new.core.verification_context_bridge import (
    verification_context_from_diagnostic_result,
)


def _enforce_tenant_access(
    tenant: TenantContext = Depends(get_current_tenant),
) -> TenantContext:
    check_rate_limit(tenant.api_key)
    return tenant


router = APIRouter(
    prefix="/verification-context",
    tags=["VerificationContext"],
    dependencies=[Depends(_enforce_tenant_access)],
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


def _safe_commit_context_log(
    session: Optional[Session],
    tenant: TenantContext,
    query: str,
    result: Dict[str, Any],
    is_verified: bool,
) -> None:
    if session is None:
        return
    try:
        session.add(
            VerificationLog(
                organization_id=tenant.organization_id,
                user_id=getattr(tenant, "user_id", None),
                query=redact_pii(query),
                result=redact_pii(json.dumps(result)),
                is_verified=is_verified,
                domain="VERIFICATION_CONTEXT",
            )
        )
        session.commit()
    except (TypeError, ValueError, SQLAlchemyError):
        session.rollback()
        raise HTTPException(
            status_code=500,
            detail="audit persistence failed",
        ) from None


@router.post(
    "/from-diagnostic",
    responses={
        422: {"description": "Verification Context rejected"},
        500: {"description": "Audit persistence failed"},
    },
)
def create_verification_context_from_diagnostic(
    payload: DiagnosticVerificationContextRequest,
    tenant: TenantContext = Depends(_enforce_tenant_access),
    session: Optional[Session] = Depends(get_session),
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
        document_dict = document.to_dict()
    except VerificationContextValidationError:
        raise HTTPException(
            status_code=422,
            detail="verification context rejected",
        ) from None
    _safe_commit_context_log(
        session,
        tenant,
        payload.query,
        document_dict,
        document_dict["verdict"] == "VERIFIED"
        and document_dict["context"]["decision"]["admission"] == "ADMIT",
    )
    return document_dict


@router.post(
    "/validate",
    responses={500: {"description": "Audit persistence failed"}},
)
def validate_verification_context(
    payload: VerificationContextDocumentRequest,
    tenant: TenantContext = Depends(_enforce_tenant_access),
    session: Optional[Session] = Depends(get_session),
) -> Dict[str, Any]:
    try:
        validate_document(payload.document)
        response = {"valid": True}
    except VerificationContextValidationError:
        response = {"valid": False, "error": "validation_failed"}
    _safe_commit_context_log(
        session,
        tenant,
        "verification-context:validate",
        response,
        False,
    )
    return response


@router.post(
    "/resolve",
    responses={500: {"description": "Audit persistence failed"}},
)
def resolve_verification_context(
    payload: VerificationContextDocumentRequest,
    tenant: TenantContext = Depends(_enforce_tenant_access),
    session: Optional[Session] = Depends(get_session),
) -> Dict[str, Any]:
    response = {"resolved": resolve_document_proof_ref(payload.document)}
    _safe_commit_context_log(
        session,
        tenant,
        "verification-context:resolve",
        response,
        False,
    )
    return response
