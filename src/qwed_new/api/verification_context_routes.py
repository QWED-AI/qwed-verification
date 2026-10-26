from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session
from sqlalchemy.exc import SQLAlchemyError
from dataclasses import replace
from typing import Any, Dict, Optional
import json

from qwed_new.core.attestation import get_attestation_service
from qwed_new.core.database import get_session
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    DiagnosticStatus,
    enforce_trust_decision,
)
from qwed_new.core.audit_logger import SecurityError, get_audit_logger
from qwed_new.core.rate_limiter import check_rate_limit
from qwed_new.core.security import redact_pii
from qwed_new.core.tenant_context import TenantContext, get_current_tenant
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    resolve_document_proof_ref,
    validate_document,
)
from qwed_new.core.verification_context_attestation import (
    attest_document,
    document_attestation_refusal,
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
    """``require_attestation``: the document must carry an attestation this
    server's key verifies and that signs it (spec v1.1, #319). Pass false
    to check the schema or ``proof_ref`` alone, as for a v1.0 document."""

    document: Dict[str, Any]
    require_attestation: bool = True


def _malformed_diagnostic_result() -> DiagnosticResult:
    return DiagnosticResult.blocked(
        agent_message="Diagnostic result is malformed",
        developer_fields={
            "constraint_id": "verification_context.malformed_diagnostic",
        },
    )


CALLER_SUPPLIED_DIAGNOSTIC = "verification_context.caller_supplied_diagnostic"
_CALLER_SUPPLIED_MESSAGE = (
    "Built from a diagnostic the caller supplied; QWED did not produce its "
    "message or fields"
)


def _diagnostic_result_from_payload(diagnostic: Any) -> DiagnosticResult:
    """The diagnostic the document is built from (#321).

    The caller wrote every field of ``diagnostic``. Only the status and
    ``proof_ref`` are kept as the result's own, because only they are checked:
    a VERIFIED result needs an attestation that binds them and the query.
    The caller's message and developer fields are recorded as given, under
    ``caller_supplied``, and decide nothing; in particular there is no
    ``is_valid``, so the document's admission is DENY unless the attestation
    signs ADMIT (see ``_attested_admission``).
    """
    if not isinstance(diagnostic, dict):
        return _malformed_diagnostic_result()
    developer_fields = diagnostic.get("developer_fields", {})
    if not isinstance(developer_fields, dict):
        return _malformed_diagnostic_result()
    try:
        supplied = DiagnosticResult.from_dict(diagnostic)
        return DiagnosticResult(
            status=supplied.status,
            agent_message=_CALLER_SUPPLIED_MESSAGE,
            developer_fields={
                "constraint_id": CALLER_SUPPLIED_DIAGNOSTIC,
                "caller_supplied": {
                    "agent_message": supplied.agent_message,
                    "developer_fields": supplied.developer_fields,
                },
            },
            proof_ref=supplied.proof_ref,
        )
    except (ValueError, TypeError, AttributeError):
        return _malformed_diagnostic_result()


ATTESTED_ADMIT = "verification_context.attested_admit"
_ATTESTATION_VERIFICATION_FAILED = "attestation verification failed"


def _admitting_engine(token: str | None) -> str | None:
    """The engine that signed ADMIT for this verdict (``qwed.admission`` and
    ``qwed.result.engine``, #321), or None if the token signs no ADMIT.

    Read only after ``enforce_trust_decision`` has checked the token against
    the result's status and ``proof_ref`` and the query, so the admission is
    the server's decision for this verdict, not the caller's. A failure to
    read it again, an error or a token that no longer verifies (expired or
    revoked since), is an enforcement failure: it fails loudly, with a 500,
    not quietly as DENY (QWED_RULES.md section 6). Only a token that still
    verifies and signs no ADMIT is DENY.
    """
    if not token:
        return None
    try:
        is_valid, claims, _error = get_attestation_service().verify_attestation(token)
    # Any failure here is reported as a 500, not suppressed.
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=_ATTESTATION_VERIFICATION_FAILED) from None
    if not is_valid or not isinstance(claims, dict):
        raise HTTPException(status_code=500, detail=_ATTESTATION_VERIFICATION_FAILED)
    qwed = claims.get("qwed")
    if not isinstance(qwed, dict) or qwed.get("admission") != AdmissionDecision.ADMIT.value:
        return None
    signed_result = qwed.get("result")
    engine = signed_result.get("engine") if isinstance(signed_result, dict) else None
    return engine if isinstance(engine, str) and engine else None


def _redact_strings(value: Any) -> Any:
    """Redact PII in every string of a JSON-like value, leaving its structure intact.

    Redacting the serialised text instead would also rewrite bare numbers
    (a ten-digit integer matches the phone pattern) into unquoted tokens and
    leave invalid JSON, which the audit chain refuses to store.
    """
    if isinstance(value, str):
        return redact_pii(value)
    if isinstance(value, dict):
        return {redact_pii(str(k)): _redact_strings(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_strings(v) for v in value]
    return value


def _safe_commit_context_log(
    session: Optional[Session],
    tenant: TenantContext,
    query: str,
    result: Dict[str, Any],
    is_verified: bool,
    admission: Optional[str] = None,
) -> None:
    """``admission`` is the decision the route returned, or None when it
    decides none (#307): from-diagnostic decides "ADMIT" or "DENY", in the
    Verification Context spec's terms; validate and resolve decide none."""
    if session is None:
        return
    # Appended to the organisation's signed audit chain (core.audit_logger),
    # not through the request session. Any failure, including an unset
    # QWED_AUDIT_SECRET_KEY, fails closed with a 500.
    try:
        get_audit_logger().log_verification(
            organization_id=tenant.organization_id,
            user_id=getattr(tenant, "user_id", None),
            query=redact_pii(query),
            result=json.dumps(_redact_strings(result)),
            is_verified=is_verified,
            domain="VERIFICATION_CONTEXT",
            admission=admission,
        )
    except (TypeError, ValueError, SQLAlchemyError, SecurityError):
        raise HTTPException(
            status_code=500,
            detail="audit persistence failed",
        ) from None


@router.post(
    "/from-diagnostic",
    responses={
        422: {"description": "Verification Context rejected"},
        500: {"description": "Audit persistence, or attestation verification or signing, failed"},
    },
)
def create_verification_context_from_diagnostic(
    payload: DiagnosticVerificationContextRequest,
    tenant: TenantContext = Depends(_enforce_tenant_access),
    session: Optional[Session] = Depends(get_session),
) -> Dict[str, Any]:
    """Build a Verification Context document from a caller-supplied diagnostic.

    The document records the diagnostic; it does not vouch for it. Its
    verdict is the diagnostic's status, which for VERIFIED must be backed by
    an attestation token binding the status, ``proof_ref`` and ``query``
    (BLOCKED otherwise). The caller's message and developer fields are kept
    under ``developer_fields.caller_supplied``, a blocked one's included, and
    decide nothing: nothing the caller wrote is taken as a server verdict
    (#321). The admission is DENY unless that token also signs ADMIT, the
    server's own admission of this verdict (``qwed.admission``). An admitted
    document names the engine that signed it, and this server's version, as
    its verifier; the caller's ``verifier`` and ``verifier_version`` are
    kept under ``caller_supplied``.

    Every document returned is v1.1, signed by this server (#319): its
    ``attestation`` authenticates every other field as this server's, so
    a consumer can tell it from one built elsewhere with a ``proof_ref``
    that resolves. A failure to sign is a 500, not an unsigned document.
    """
    result = _diagnostic_result_from_payload(payload.diagnostic)
    verifier, verifier_version = payload.verifier, payload.verifier_version
    if result.status is DiagnosticStatus.VERIFIED:
        # The bridge enforces this too, but its BLOCKED replacement carries
        # the gate's fields only. Enforce here first so a blocked diagnostic
        # keeps the caller's record beside the reason it was blocked.
        enforced = enforce_trust_decision(
            result,
            attestation_token=payload.attestation_token,
            require_attestation=True,
            query=payload.query,
        )
        if enforced.status is not DiagnosticStatus.VERIFIED:
            result = replace(
                enforced,
                developer_fields={
                    **enforced.developer_fields,
                    "caller_supplied": result.developer_fields["caller_supplied"],
                },
            )
        elif (engine := _admitting_engine(payload.attestation_token)) is not None:
            # The server signed ADMIT for this verdict, proof_ref and query,
            # which it does only for a valid result: the document is admitted
            # on the server's word, not the caller's, and so names the engine
            # that verified it, not a verifier the caller chose.
            verifier, verifier_version = engine, None
            caller_supplied = result.developer_fields["caller_supplied"]
            result = replace(
                result,
                developer_fields={
                    **result.developer_fields,
                    "constraint_id": ATTESTED_ADMIT,
                    "is_valid": True,
                    "attested_admission": AdmissionDecision.ADMIT.value,
                    "caller_supplied": {
                        **caller_supplied,
                        "verifier": payload.verifier,
                        "verifier_version": payload.verifier_version,
                    },
                },
            )
    try:
        document = verification_context_from_diagnostic_result(
            result,
            formal_statement=payload.query,
            verifier=verifier,
            verifier_version=verifier_version,
            attestation_token=payload.attestation_token,
        )
        document.validate()
        unsigned = document.to_dict()
    except VerificationContextValidationError:
        raise HTTPException(
            status_code=422,
            detail="verification context rejected",
        ) from None
    try:
        document_dict = attest_document(unsigned)
    except VerificationContextValidationError:
        # The schema takes what the canonical encoding refuses (a lone
        # surrogate in a string), and a document that is not VERIFIED is
        # first encoded here, to be signed. The caller's document is what
        # is wrong, as for a VERIFIED one (#517 review).
        raise HTTPException(
            status_code=422,
            detail="verification context rejected",
        ) from None
    except (RuntimeError, ValueError):
        # The document was valid, so a failure here is the server's own:
        # its key or settings (AttestationConfigError is a RuntimeError).
        raise HTTPException(status_code=500, detail="attestation signing failed") from None
    _safe_commit_context_log(
        session,
        tenant,
        payload.query,
        document_dict,
        document_dict["verdict"] == "VERIFIED"
        and document_dict["context"]["decision"]["admission"] == "ADMIT",
        admission=document_dict["context"]["decision"]["admission"],
    )
    return document_dict


def _attestation_refusal(payload: VerificationContextDocumentRequest) -> Optional[str]:
    """Why the document's attestation is refused, or None if it verifies or
    is not required (#319). A failure to check it, such as a signing key
    that cannot be loaded, is a 500, not a refusal or a pass."""
    if not payload.require_attestation:
        return None
    try:
        return document_attestation_refusal(payload.document)
    except (RuntimeError, ValueError):
        raise HTTPException(status_code=500, detail=_ATTESTATION_VERIFICATION_FAILED) from None


@router.post(
    "/validate",
    responses={500: {"description": "Audit persistence or attestation verification failed"}},
)
def validate_verification_context(
    payload: VerificationContextDocumentRequest,
    tenant: TenantContext = Depends(_enforce_tenant_access),
    session: Optional[Session] = Depends(get_session),
) -> Dict[str, Any]:
    """Validate a document against its version's schema; by default, check
    its attestation first (see VerificationContextDocumentRequest)."""
    if (refusal := _attestation_refusal(payload)) is not None:
        response = {"valid": False, "error": refusal}
    else:
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
    responses={500: {"description": "Audit persistence or attestation verification failed"}},
)
def resolve_verification_context(
    payload: VerificationContextDocumentRequest,
    tenant: TenantContext = Depends(_enforce_tenant_access),
    session: Optional[Session] = Depends(get_session),
) -> Dict[str, Any]:
    """Resolve a document's ``proof_ref``; by default, check its attestation
    first. A ``proof_ref`` is a commitment anyone can compute; the
    attestation is what shows this server issued the document."""
    if (refusal := _attestation_refusal(payload)) is not None:
        response = {"resolved": False, "error": refusal}
    else:
        response = {"resolved": resolve_document_proof_ref(payload.document)}
    _safe_commit_context_log(
        session,
        tenant,
        "verification-context:resolve",
        response,
        False,
    )
    return response
