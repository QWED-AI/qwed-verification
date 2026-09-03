from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import Optional, Annotated
from sqlmodel import Session, select
import os
import logging
from fractions import Fraction

from qwed_new.core.security import redact_pii
from qwed_new.core.diagnostics import (
    AdvisoryCheck,
    DiagnosticResult,
    admission_decision,
    enforce_trust_decision,
    merge_diagnostic_result,
)
from qwed_new.api.verification_context_routes import router as verification_context_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
INTERNAL_VERIFICATION_ERROR = "Internal verification error"
INTERNAL_PROCESSING_ERROR = "Internal processing error"

from qwed_new.core.control_plane import ControlPlane
from qwed_new.core.tenant_context import get_current_tenant, TenantContext
from qwed_new.core.database import create_db_and_tables, get_session
from qwed_new.core.models import VerificationLog, ApiKey, User
from qwed_new.core.rate_limiter import check_rate_limit

# Import auth router
from qwed_new.auth import auth_router
from qwed_new.auth.audit_routes import router as audit_router
from qwed_new.auth.middleware import get_api_key
from qwed_new.auth.routes import get_current_user_token
from qwed_new.auth.security import hash_api_key

TenantDependency = Annotated[TenantContext, Depends(get_current_tenant)]
SessionDependency = Annotated[Session, Depends(get_session)]
AgentTokenHeader = Annotated[str, Header(...)]

APP_VERSION = "7.1.0"

app = FastAPI(
    title="QWED API",
    description="The Deterministic Verification Protocol for AI",
    version=APP_VERSION
)

# CORS - configurable via environment variable
# Default allows all origins for development, restrict in production
raw_cors_origins = os.environ.get("QWED_CORS_ORIGINS", "")
CORS_ORIGINS = [origin.strip() for origin in raw_cors_origins.split(",") if origin.strip()]
if not CORS_ORIGINS:
    logger.critical("QWED_CORS_ORIGINS must be configured")
    raise RuntimeError("QWED_CORS_ORIGINS must be configured")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ORIGINS != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(verification_context_router)

STARTUP_ALLOWED_PTH_FILES = {
    "__editable__.qwed_a2a-0.1.0.pth",
    "__editable__.qwed_finance-2.0.1.pth",
    "__editable__.qwed_mcp-0.2.0.pth",
    "_qwed.pth",
    "_qwed_legal.pth",
    "_qwed_new.pth",
    "_qwed_ucp.pth",
    "a1_coverage.pth",
    "pywin32.pth",
}


def _get_env_allowlisted_pth_files() -> set[str]:
    """Parse deployment-provided exact startup hook allowlist entries."""
    extra = os.environ.get("QWED_ALLOWED_STARTUP_PTH_FILES", "")
    return {name.strip() for name in extra.split(",") if name.strip()}


def _get_startup_hook_allowlist() -> set[str]:
    """Return additional expected startup hook files for this deployment."""
    allowlist = set(STARTUP_ALLOWED_PTH_FILES)
    allowlist.update(_get_env_allowlisted_pth_files())
    return allowlist


def _enforce_environment_integrity() -> None:
    """Fail startup if Python startup hooks cannot be verified as safe."""
    if os.environ.get("QWED_SKIP_ENV_INTEGRITY_CHECK") == "true":
        logger.warning("Bypassing environment integrity check due to QWED_SKIP_ENV_INTEGRITY_CHECK")
        return

    from qwed_sdk.guards.environment_guard import StartupHookGuard

    guard = StartupHookGuard(allowed_pth_files=_get_startup_hook_allowlist())
    result = guard.verify_environment_integrity()
    if not result.get("verified"):
        logger.critical(f"Startup environment integrity check failed: {result}")
        raise RuntimeError(f"Environment integrity verification failed: {result.get('risk')}")


@app.on_event("startup")
def on_startup():
    _enforce_environment_integrity()
    create_db_and_tables()

# Initialize Kernel (Control Plane)
control_plane = ControlPlane()

# Trust boundary enforcement helper (currently advisory until #265)
def _enforce_trust(
    dr: DiagnosticResult, query: str
) -> DiagnosticResult:
    """Route a DiagnosticResult through trust boundary enforcement.

    Currently operates in advisory mode (require_attestation=False) pending
    attestation issuance wiring. Callers must use the returned DiagnosticResult
    for audit logging and response construction.
    """
    return enforce_trust_decision(dr, require_attestation=False, query=query)


_merge_response = merge_diagnostic_result  # shared merge helper (#271)

def _safe_commit_log(session, log):
    """Write a VerificationLog safely, rolling back on failure."""
    try:
        session.add(log)
        session.commit()
    except Exception:
        try:
            session.rollback()
        except Exception:
            logger.exception("Rollback failed while handling commit/log failure")


class VerifyRequest(BaseModel):
    query: str
    provider: Optional[str] = None

@app.get("/")
async def root():
    return {"message": "QWED OS is Running", "version": APP_VERSION}


def get_optional_current_user(
    authorization: Optional[str] = Header(None),
    session: Session = Depends(get_session),
) -> Optional[User]:
    """Resolve a JWT-authenticated user when present."""
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        return None

    payload = get_current_user_token(authorization)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Missing sub claim in token")

    try:
        user = session.get(User, int(user_id))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token subject") from exc

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def get_optional_api_key_record(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
) -> Optional[ApiKey]:
    """Resolve an API key record when the caller provides x-api-key."""
    if not x_api_key:
        return None

    hashed_key = hash_api_key(x_api_key)
    statement = select(ApiKey).where(ApiKey.key_hash == hashed_key, ApiKey.is_active)
    api_key = session.execute(statement).scalars().first()

    if not api_key:
        raise HTTPException(status_code=403, detail="Invalid or revoked API Key")

    return api_key


def _has_metrics_admin_role(user: Optional[User]) -> bool:
    """Return True when the user can access global operational metrics."""
    return user is not None and user.is_active and user.role in {"owner", "admin"}


def require_metrics_access(
    current_user: Annotated[Optional[User], Depends(get_optional_current_user)],
    api_key_record: Annotated[Optional[ApiKey], Depends(get_optional_api_key_record)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    """Restrict operational metrics to admin JWT users or admin-linked API keys."""
    if _has_metrics_admin_role(current_user):
        return

    if api_key_record is not None:
        api_key_user = session.get(User, api_key_record.user_id) if api_key_record.user_id else None
        if _has_metrics_admin_role(api_key_user):
            return
        raise HTTPException(status_code=403, detail="Admin access required")

    if current_user is not None:
        raise HTTPException(status_code=403, detail="Admin access required")

    raise HTTPException(status_code=401, detail="Authentication required")

@app.post("/verify/natural_language")
async def verify_natural_language(
    request: VerifyRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    check_rate_limit(tenant.api_key)

    dr = None
    result = None
    try:
        result = await control_plane.process_natural_language(
            request.query,
            organization_id=tenant.organization_id,
            preferred_provider=request.provider
        )
    except Exception as e:
        logger.error("Natural language verification error: %s", redact_pii(str(e)), exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_VERIFICATION_ERROR,
            {"constraint_id": "api.natural_language.execution_error"},
        )

    if dr is None:
        verification_result = result.get("verification", {}) if isinstance(result, dict) else {}
        try:
            dr = DiagnosticResult.from_legacy_dict(verification_result, engine="math")
        except ValueError:
            dr = DiagnosticResult.unverifiable(
                "Verification result unavailable — legacy engine did not retain proof artifacts",
                {"constraint_id": "api.natural_language.legacy_conversion_failed", "legacy_status": verification_result.get("status")},
            )
    dr = _enforce_trust(dr, query=request.query)

    log = VerificationLog(
        organization_id=tenant.organization_id,
        user_id=tenant.user_id if hasattr(tenant, 'user_id') else None,
        query=request.query,
        result=str(dr.to_dict()),
        is_verified=dr.is_authoritative,
        domain="MATH"
    )
    _safe_commit_log(session, log)

    return _merge_response(dr)

@app.post(
    "/verify/logic",
    responses={403: {"description": "Logic verification blocked by engine"}},
)
async def verify_logic(
    request: VerifyRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    check_rate_limit(tenant.api_key)
    result = None

    try:
        result = await control_plane.process_logic_query(
            request.query,
            organization_id=tenant.organization_id,
            preferred_provider=request.provider
        )

        status = result.get("status", "ERROR")

        if status == "SAT":
            dr = DiagnosticResult.verified(
                "Logic constraints are satisfiable",
                developer_fields=result,
                evidence={"model": str(result.get("model")), "dsl_code": result.get("dsl_code", "")},
            )
        elif status == "UNSAT":
            dr = DiagnosticResult.unverifiable(
                "Logic constraints are unsatisfiable",
                developer_fields=result,
            )
        else:
            dr = DiagnosticResult.blocked(
                result.get("error", "Logic verification failed"),
                developer_fields=result,
            )
        dr = _enforce_trust(dr, query=request.query)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="LOGIC"
        )
        _safe_commit_log(session, log)

        return _merge_response(dr)


    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logic verification error: {redact_pii(str(e))}", exc_info=False)
        provider_used = (
            result.get("provider_used")
            if isinstance(result, dict) and result.get("provider_used")
            else control_plane.router.route(request.query, request.provider)
        )
        dr = DiagnosticResult.blocked(
            INTERNAL_VERIFICATION_ERROR,
            {"constraint_id": "api.logic.execution_error", "provider_used": provider_used},
        )
        dr = _enforce_trust(dr, query=request.query)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=str(dr.to_dict()),
            is_verified=False,
            domain="LOGIC"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)

@app.post(
    "/verify/stats",
    responses={
        403: {"description": "Verification blocked by security policy."},
        503: {"description": "Secure execution runtime unavailable."},
    },
)
async def verify_stats(
    file: UploadFile = File(...),
    query: str = Form(...),
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Verify statistical claims about uploaded data.
    
    Example:
    - Upload: sales.csv
    - Query: "Did sales increase by 15% this quarter?"
    """
    check_rate_limit(tenant.api_key)
    
    try:
        import pandas as pd
        df = pd.read_csv(file.file)
        
        from qwed_new.core.stats_verifier import StatsVerifier
        verifier = StatsVerifier()

        dr = verifier.verify_stats(query, df, provider=None)
        dr = _enforce_trust(dr, query=query)

        # Fail-closed audit semantics (P1 #297): never log a BLOCKED / non-
        # authoritative result as verified. is_authoritative is False for every
        # fail-closed status (BLOCKED/UNVERIFIABLE proof_ref=None), so a result
        # cannot be persisted as verified unless it is a proven claim AND its
        # claim-validity signal is true. developer_fields.is_valid alone is
        # mutable engine metadata and must not drive the audit bit.
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative
            and dr.developer_fields.get("is_valid") is True,
            domain="STATS"
        )
        _safe_commit_log(session, log)

        return _merge_response(dr)
    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Stats verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_PROCESSING_ERROR,
            {"constraint_id": "api.stats.execution_error"},
        )
        dr = _enforce_trust(dr, query=query)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=str(dr.to_dict()),
            is_verified=False,
            domain="STATS"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)


@app.post("/verify/fact")
async def verify_fact(
    request: dict,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Verify a factual claim against a provided context.
    
    Request body:
    {
        "claim": "The policy covers water damage",
        "context": "Policy document text...",
        "provider": "anthropic" (optional)
    }
    """
    check_rate_limit(tenant.api_key)
    claim = request.get("claim")
    context = request.get("context")
    if not claim or not context:
        raise HTTPException(status_code=400, detail="Missing 'claim' or 'context'")

    try:
        from qwed_new.core.fact_verifier import FactVerifier
        verifier = FactVerifier()
        
        provider = request.get("provider")
        
        result = verifier.verify_fact(claim, context, provider=provider)

        if isinstance(result, DiagnosticResult):
            dr = result
        elif hasattr(result, "to_dict") and hasattr(result, "is_verified"):
            verdict = result.verdict if hasattr(result, "verdict") else "UNKNOWN"
            dr = DiagnosticResult.verified(
                "Fact verification complete",
                developer_fields=result.to_dict(),
                evidence={"claim": claim, "verdict": verdict},
            ) if result.is_verified else DiagnosticResult.unverifiable(
                "Fact not supported",
                developer_fields=result.to_dict(),
            )
        else:
            dr = DiagnosticResult.unverifiable(
                "Fact verification inconclusive",
                developer_fields={"result": str(result)},
            )
        dr = _enforce_trust(dr, query=claim)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=claim,
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="FACT"
        )
        _safe_commit_log(session, log)

        return _merge_response(dr)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fact verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_VERIFICATION_ERROR,
            {"constraint_id": "api.fact.execution_error", "verdict": "ERROR"},
        )
        dr = _enforce_trust(dr, query=claim)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=claim,
            result=str(dr.to_dict()),
            is_verified=False,
            domain="FACT"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)


@app.post("/verify/code")
async def verify_code(
    request: dict,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    check_rate_limit(tenant.api_key)
    code = request.get("code")

    try:
        from qwed_new.core.code_verifier import CodeVerifier
        verifier = CodeVerifier()

        language = request.get("language", "python")

        if not code:
            raise HTTPException(status_code=400, detail="Missing 'code'")

        result = verifier.verify_code(code, language=language)

        # Verification truth is preserved unchanged: a proven-unsafe snippet is
        # VERIFIED-as-unsafe (developer_fields.is_valid False, proof_ref bound).
        # Admission is a SEPARATE decision at this boundary (QWED #7, #13, #15):
        # unsafe code must never be admitted, so we expose an explicit
        # AdmissionDecision rather than letting authority-only consumers treat
        # proof_ref as "safe to execute".
        dr = result
        dr = _enforce_trust(dr, query=code)
        admission = admission_decision(dr)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=code[:200],
            result=str(dr.to_dict()),
            is_verified=dr.developer_fields.get("is_valid") is True,
            domain="CODE"
        )
        _safe_commit_log(session, log)

        response = _merge_response(dr)
        response["admission"] = admission.value
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Code verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_VERIFICATION_ERROR,
            {"constraint_id": "api.code.execution_error", "is_safe": False},
        )
        dr = _enforce_trust(dr, query=code)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=(code or "")[:200],
            result=str(dr.to_dict()),
            is_verified=False,
            domain="CODE"
        )
        _safe_commit_log(session, log)
        response = _merge_response(dr)
        response["admission"] = admission_decision(dr).value
        return response


@app.post("/verify/math")
async def verify_math(
    request: dict,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    check_rate_limit(tenant.api_key)
    expression = request.get("expression")
    if not expression:
        raise HTTPException(status_code=400, detail="Missing 'expression'")

    try:
        import sympy
        from qwed_new.core.safe_parser import safe_parse_expr
        from sympy import simplify, symbols, Eq, solve

        context_data = request.get("context", {})

        if "=" in expression:
            left_str, right_str = expression.split("=", 1)
            left = safe_parse_expr(left_str)
            right = safe_parse_expr(right_str)
            difference = simplify(left - right)
            is_valid = difference == 0

            fields = {
                "left_side": str(left),
                "right_side": str(right),
                "simplified_difference": str(difference),
            }
            if is_valid:
                dr = DiagnosticResult.verified(
                    "Identity is true",
                    developer_fields={"is_valid": True, "result": True, **fields},
                    evidence=fields,
                )
            else:
                dr = DiagnosticResult.unverifiable(
                    "Identity is false",
                    developer_fields={"is_valid": False, "result": False, **fields},
                )
        else:
            import re
            expression_normalized = re.sub(r'(\d)(\()', r'\1*\2', expression)
            is_ambiguous = False
            if "/" in expression and "(" in expression:
                if re.search(r'/\d+\(', expression.replace(" ", "")):
                    is_ambiguous = True

            parsed = safe_parse_expr(expression_normalized)
            simplified = simplify(parsed)

            if simplified.has(sympy.zoo) or simplified.has(sympy.nan):
                dr = DiagnosticResult.blocked(
                    "Expression contains division by zero",
                    developer_fields={"is_valid": False, "error": "Division by zero"},
                )
            elif simplified.has(sympy.oo) or simplified.has(-sympy.oo):
                dr = DiagnosticResult.blocked(
                    "Expression is undefined",
                    developer_fields={"is_valid": False, "error": "undefined"},
                )
            elif simplified.is_real is False and context_data.get("domain") == "real":
                dr = DiagnosticResult.blocked(
                    "Expression is not real-valued in the requested real domain",
                    developer_fields={"is_valid": False, "error": "domain error"},
                )
            elif is_ambiguous:
                dr = DiagnosticResult.blocked(
                    "Expression may be ambiguous due to implicit multiplication after division",
                    developer_fields={"is_valid": False, "result": False, "status": "BLOCKED", "warning": "ambiguous", "simplified": str(simplified), "note": "Interpreted using standard order of operations", "original": str(parsed)},
                )
            else:
                is_numeric = simplified.free_symbols == set()
                if not is_numeric:
                    dr = DiagnosticResult.verified(
                        "Expression simplified",
                        developer_fields={"is_valid": True, "simplified": str(simplified), "original": str(parsed), "is_symbolic": True},
                        evidence={"simplified": str(simplified)},
                    )
                else:
                    try:
                        exact = sympy.nsimplify(simplified)
                        value = float(simplified)
                        dr = DiagnosticResult.verified(
                            "Expression evaluated",
                            developer_fields={"is_valid": True, "value": value, "exact_value": str(exact), "simplified": str(simplified), "original": str(parsed)},
                            evidence={"exact_value": str(exact), "simplified": str(simplified)},
                        )
                    except (TypeError, ValueError, OverflowError):
                        dr = DiagnosticResult.unverifiable(
                            "Expression is not numeric",
                            developer_fields={"is_valid": False, "simplified": str(simplified), "original": str(parsed)},
                        )

        # Precision advisory (issue #347): flag binary floating-point
        # constants WITHOUT affecting the verdict — advisory_checks are
        # structurally non-proof-bearing. QWED_RULES.md: flag float math,
        # suggest decimal.Decimal / sympy. Parse submitted text directly
        # so equations (including 0.0*x = 0.0*x, 0.5**0 = 1) retain lexical
        # float literals before symbolic simplification.
        float_advisory = AdvisoryCheck.float_precision(expression)
        if float_advisory is not None:
            dr.developer_fields.setdefault("advisory_checks", []).append(float_advisory)

        dr = _enforce_trust(dr, query=expression)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=expression,
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="MATH"
        )
        _safe_commit_log(session, log)

        return _merge_response(dr)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Math verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_VERIFICATION_ERROR,
            {"constraint_id": "api.math.execution_error"},
        )
        dr = _enforce_trust(dr, query=expression)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=expression,
            result=str(dr.to_dict()),
            is_verified=False,
            domain="MATH"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)


@app.post(
    "/verify/sql",
    responses={400: {"description": "Missing required field: 'query' or 'schema_ddl'"}},
)
async def verify_sql(
    request: dict,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    check_rate_limit(tenant.api_key)
    query = request.get("query")
    if not query:
        raise HTTPException(status_code=400, detail="Missing 'query'")
    schema_ddl = request.get("schema_ddl")
    if not schema_ddl:
        raise HTTPException(status_code=400, detail="Missing 'schema_ddl'")

    try:
        from qwed_new.core.sql_verifier import SQLVerifier
        verifier = SQLVerifier()

        dialect = request.get("dialect", "sqlite")

        result = verifier.verify_sql(query, schema_ddl, dialect=dialect)

        # Verification truth is preserved unchanged: a proven-malicious query is
        # VERIFIED-as-malicious (developer_fields.is_valid False, proof_ref bound).
        # Admission is a SEPARATE decision at this boundary (QWED #7, #13, #15): unsafe
        # SQL must never be admitted, so we expose an explicit AdmissionDecision rather
        # than letting authority-only consumers treat proof_ref as "safe to execute".
        dr = result
        dr = _enforce_trust(dr, query=query)
        admission = admission_decision(dr)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="SQL"
        )
        _safe_commit_log(session, log)

        response = _merge_response(dr)
        response["admission"] = admission.value
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SQL verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_VERIFICATION_ERROR,
            {"constraint_id": "api.sql.execution_error", "is_valid": False},
        )
        dr = _enforce_trust(dr, query=query)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=str(dr.to_dict()),
            is_verified=False,
            domain="SQL"
        )
        _safe_commit_log(session, log)
        response = _merge_response(dr)
        response["admission"] = admission_decision(dr).value
        return response


@app.post("/verify/image")
async def verify_image(
    image: UploadFile = File(...),
    claim: str = Form(...),
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Verify a claim against an uploaded image.
    
    Form data:
    - image: Image file (PNG, JPEG, GIF, WebP)
    - claim: The statement to verify (e.g., "The image is 800x600 pixels")
    
    Returns verification result with:
    - verdict: SUPPORTED, REFUTED, INCONCLUSIVE, or VLM_REQUIRED
    - confidence: 0.0 to 1.0
    - reasoning: Explanation of the result
    - methods_used: List of verification methods applied
    """
    check_rate_limit(tenant.api_key)
    
    try:
        from qwed_new.core.image_verifier import ImageVerifier
        
        # Read image bytes
        image_bytes = await image.read()
        
        if len(image_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty image file")
        
        if len(image_bytes) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=400, detail="Image too large (max 10MB)")
        
        # Verify claim against image
        verifier = ImageVerifier(use_vlm_fallback=False)
        result = verifier.verify_image(image_bytes, claim)

        dr = result
        dr = _enforce_trust(dr, query=claim)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Image claim: {claim}",
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="IMAGE"
        )
        _safe_commit_log(session, log)

        return _merge_response(dr)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_PROCESSING_ERROR,
            {"constraint_id": "api.image.execution_error", "verdict": "INCONCLUSIVE", "confidence": 0.0},
        )
        dr = _enforce_trust(dr, query=claim)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Image claim: {claim}",
            result=str(dr.to_dict()),
            is_verified=False,
            domain="IMAGE"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)

class RAGVerifyRequest(BaseModel):
    target_document_id: str
    chunks: list[dict]
    max_drm_rate: str = "0"  # Accepts Fraction-compatible strings: "0", "1/10", etc.

    @field_validator("target_document_id")
    @classmethod
    def validate_target_document_id(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("target_document_id must be a non-empty string.")
        return stripped

    @field_validator("chunks")
    @classmethod
    def validate_chunks(cls, value: list[dict]) -> list[dict]:
        if not value:
            raise ValueError("chunks must be a non-empty list.")
        if any(not isinstance(chunk, dict) or not chunk for chunk in value):
            raise ValueError("Each chunk must be a non-empty object.")
        return value

    @field_validator("max_drm_rate")
    @classmethod
    def validate_max_drm_rate(cls, value: str) -> str:
        try:
            threshold = Fraction(value)
        except (TypeError, ValueError, ZeroDivisionError) as exc:
            raise ValueError("max_drm_rate must be a Fraction-compatible string.") from exc
        if not Fraction(0) <= threshold <= Fraction(1):
            raise ValueError("max_drm_rate must be between 0 and 1.")
        return value

@app.post(
    "/verify/rag",
    responses={
        400: {"description": "Invalid RAG verification request payload."},
    },
)
async def verify_rag(
    request: RAGVerifyRequest,
    tenant: TenantDependency,
    session: SessionDependency
):
    """
    Document-Level Retrieval Mismatch Defender.
    Verifies that context chunks align with the target document.
    """
    check_rate_limit(tenant.api_key)
    
    try:
        from qwed_sdk.guards.rag_guard import RAGGuard

        try:
            guard = RAGGuard(max_drm_rate=request.max_drm_rate)
            result = guard.verify_retrieval_context(
                target_document_id=request.target_document_id,
                retrieved_chunks=request.chunks
            )
        except ValueError as exc:
            logger.warning("RAG config error: %s", redact_pii(str(exc)))
            dr = DiagnosticResult.unverifiable(
                "RAG configuration error",
                developer_fields={"constraint_id": "api.rag.config_error"},
            )
            dr = _enforce_trust(dr, query=request.target_document_id)
            log = VerificationLog(
                organization_id=tenant.organization_id,
                query=f"RAG Document Verify: {request.target_document_id}",
                result=str(dr.to_dict()),
                is_verified=False,
                domain="RAG"
            )
            _safe_commit_log(session, log)
            return _merge_response(dr)
        
        is_verified = result.get("verified", False)
        if is_verified:
            dr = DiagnosticResult.verified(
                "RAG context verified",
                developer_fields=result,
                evidence={"verified": True, "drm_rate": result.get("drm_rate")},
            )
        else:
            dr = DiagnosticResult.unverifiable(
                "RAG context mismatch detected",
                developer_fields=result,
            )
        dr = _enforce_trust(dr, query=request.target_document_id)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"RAG Document Verify: {request.target_document_id}",
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="RAG"
        )
        _safe_commit_log(session, log)
        
        return _merge_response(dr)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"RAG verification error: {redact_pii(str(e))}", exc_info=False)
        doc_id = getattr(request, 'target_document_id', 'unknown')
        dr = DiagnosticResult.blocked(
            INTERNAL_PROCESSING_ERROR,
            {"constraint_id": "api.rag.execution_error", "verified": False},
        )
        dr = _enforce_trust(dr, query=doc_id)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"RAG Document Verify: {doc_id}",
            result=str(dr.to_dict()),
            is_verified=False,
            domain="RAG"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)

class ProcessVerifyRequest(BaseModel):
    trace: str
    mode: str = "irac"
    milestones: Optional[list[str]] = None

@app.post(
    "/verify/process",
    responses={
        400: {"description": "Invalid process mode or missing milestones for milestones mode."},
    },
)
async def verify_process(
    request: ProcessVerifyRequest,
    tenant: TenantDependency,
    session: SessionDependency
):
    """
    Glass-Box Reasoning Process Verifier.
    Checks IRAC structural compliance or milestone process rates.
    """
    check_rate_limit(tenant.api_key)
    
    try:
        from qwed_new.guards.process_guard import ProcessVerifier
        verifier = ProcessVerifier()
        
        if request.mode == "irac":
            result = verifier.verify_irac_structure(request.trace)
        elif request.mode == "milestones":
            if not request.milestones:
                raise HTTPException(
                    status_code=400,
                    detail="'milestones' is required when mode=\"milestones\""
                )
            result = verifier.verify_trace(request.trace, request.milestones)
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid mode. Use 'irac' or 'milestones'."
            )
        
        if result.get("verified"):
            dr = DiagnosticResult.verified(
                "Process verification passed",
                developer_fields=result,
                evidence={"mode": request.mode, "verified": True},
            )
        else:
            dr = DiagnosticResult.unverifiable(
                "Process verification did not pass",
                developer_fields=result,
            )
        dr = _enforce_trust(dr, query=request.trace)
            
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Process Verification ({request.mode})",
            result=str(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="PROCESS"
        )
        _safe_commit_log(session, log)
        
        return _merge_response(dr)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Process verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_PROCESSING_ERROR,
            {"constraint_id": "api.process.execution_error", "verified": False},
        )
        dr = _enforce_trust(dr, query=request.trace)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Process Verification ({request.mode})",
            result=str(dr.to_dict()),
            is_verified=False,
            domain="PROCESS"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)


# ============================================================
# OBSERVABILITY ENDPOINTS
# ============================================================

from qwed_new.core.observability import (
    get_prometheus_content_type,
    get_prometheus_metrics,
    metrics_collector,
)
from datetime import datetime, timezone
from sqlmodel import select

@app.get("/health")
async def health_check():
    """
    System health check.
    Returns basic status information (no auth required).
    """
    return {
        "status": "healthy",
        "service": "QWED Platform",
        "version": APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/metrics")
async def get_global_metrics(
    current_user: Annotated[None, Depends(require_metrics_access)],
):
    """
    Get system-wide metrics.
    """
    del current_user
    global_metrics = metrics_collector.get_global_metrics()
    all_tenant_metrics = metrics_collector.get_all_tenant_metrics()
    
    return {
        "global": global_metrics,
        "tenants": all_tenant_metrics
    }

@app.get("/metrics/prometheus", tags=["Observability"])
async def prometheus_metrics(
    current_user: Annotated[None, Depends(require_metrics_access)],
):
    """
    Prometheus-compatible metrics endpoint.
    
    Returns metrics in Prometheus text format for scraping.
    """
    del current_user
    content = get_prometheus_metrics()
    return Response(
        content=content,
        media_type=get_prometheus_content_type()
    )

@app.get("/metrics/{organization_id}")
async def get_tenant_metrics(
    organization_id: int,
    tenant: TenantContext = Depends(get_current_tenant)
):
    """
    Get metrics for a specific tenant.
    Tenants can only see their own metrics.
    """
    # Authorization: Ensure tenant can only see their own metrics
    if tenant.organization_id != organization_id:
        raise HTTPException(
            status_code=403,
            detail="You can only view metrics for your own organization"
        )
    
    metrics = metrics_collector.get_tenant_metrics(organization_id)
    
    if not metrics:
        return {
            "organization_id": organization_id,
            "message": "No metrics available yet. Make some requests first!"
        }
    
    return metrics

@app.get("/logs")
async def get_tenant_logs(
    limit: int = 10,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Get verification logs for the authenticated tenant.
    Automatically scoped to the organization.
    """
    statement = select(VerificationLog).where(
        VerificationLog.organization_id == tenant.organization_id
    ).order_by(VerificationLog.timestamp.desc()).limit(limit)
    
    logs = session.execute(statement).scalars().all()
    
    return {
        "organization_id": tenant.organization_id,
        "organization_name": tenant.organization_name,
        "total_logs": len(logs),
        "logs": [
            {
                "id": log.id,
                "query": log.query,
                "is_verified": log.is_verified,
                "domain": log.domain,
                "timestamp": log.timestamp.isoformat()
            }
            for log in logs
        ]
    }

# ============================================================
# AGENTIC AI ENDPOINTS (Phase 2)
# ============================================================

from qwed_new.core.agent_registry import agent_registry
from qwed_new.core.agent_models import Agent, AgentActivity
from qwed_new.core.tool_approval import tool_approval
import json

class AgentRegistrationRequest(BaseModel):
    name: str
    agent_type: str = "autonomous"
    description: Optional[str] = None
    permissions: Optional[list] = None
    max_cost_per_day: float = 100.0

class AgentVerifyRequest(BaseModel):
    query: str
    provider: Optional[str] = None
    tool_schema: Optional[dict] = None

class ToolCallRequest(BaseModel):
    tool_params: dict

def _require_authenticated_agent(session: Session, agent_id: int, x_agent_token: str) -> Agent:
    agent = agent_registry.authenticate_agent(session, x_agent_token)
    if not agent or agent.id != agent_id:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return agent

def _enforce_agent_budget(session: Session, agent_id: int, agent: Agent, query: str) -> None:
    budget_ok, budget_reason = agent_registry.check_budget(session, agent_id)
    if budget_ok:
        return

    agent_registry.log_activity(
        session, agent_id, agent.organization_id,
        "verification_request", "Budget exceeded", "blocked",
        input_data=query
    )
    raise HTTPException(status_code=403, detail=budget_reason)

def _run_exfiltration_check(session: Session, agent_id: int, agent: Agent, query: str) -> None:
    from qwed_sdk.guards.exfiltration_guard import ExfiltrationGuard

    guard = ExfiltrationGuard()
    res = guard.scan_payload(query)
    if res.get("verified"):
        return

    agent_registry.log_activity(
        session, agent_id, agent.organization_id,
        "verification_request", "Exfiltration blocked", "blocked",
        input_data=None
    )
    raise HTTPException(status_code=403, detail="Potential exfiltration detected: " + res.get("message", ""))

def _run_mcp_poison_check(session: Session, agent_id: int, agent: Agent, tool_schema: Optional[dict]) -> None:
    if not tool_schema:
        raise HTTPException(
            status_code=400,
            detail="'tool_schema' is required when mcp_poison check is enabled"
        )

    from qwed_sdk.guards.mcp_poison_guard import MCPPoisonGuard

    guard = MCPPoisonGuard()
    res = guard.verify_tool_definition(tool_schema)
    if res.get("verified"):
        return

    agent_registry.log_activity(
        session, agent_id, agent.organization_id,
        "verification_request", "MCP Poisoning blocked", "blocked",
        input_data=None
    )
    raise HTTPException(status_code=403, detail="Potential MCP Model Context Poisoning detected")

def _run_agent_security_checks(
    session: Session,
    agent_id: int,
    agent: Agent,
    request: AgentVerifyRequest,
) -> None:
    _run_exfiltration_check(session, agent_id, agent, request.query)
    if request.tool_schema:
        _run_mcp_poison_check(session, agent_id, agent, request.tool_schema)

async def _process_agent_verification(agent: Agent, request: AgentVerifyRequest) -> dict:
    try:
        return await control_plane.process_natural_language(
            request.query,
            organization_id=agent.organization_id,
            preferred_provider=request.provider
        )
    except Exception as e:
        logger.error(f"Agent verification failed: {redact_pii(str(e))}", exc_info=False)
        raise HTTPException(status_code=500, detail="Internal agent verification error") from e

@app.post(
    "/agents/register",
    responses={500: {"description": "Agent registration failed due to an internal error"}},
)
async def register_agent(
    request: AgentRegistrationRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Register a new AI agent with QWED.
    Returns agent details and authentication token.
    """
    try:
        agent, agent_token = agent_registry.register_agent(
            session=session,
            organization_id=tenant.organization_id,
            name=request.name,
            agent_type=request.agent_type,
            description=request.description,
            permissions=request.permissions or [],
            max_cost_per_day=request.max_cost_per_day
        )
        
        return {
            "agent_id": agent.id,
            "agent_token": agent_token,
            "name": agent.name,
            "type": agent.agent_type,
            "status": agent.status,
            "max_cost_per_day": agent.max_cost_per_day,
            "message": "Agent registered successfully. Store the agent_token securely."
        }
    except Exception as e:
        logger.error(f"Agent registration error: {redact_pii(str(e))}", exc_info=False)
        raise HTTPException(status_code=500, detail="Agent registration failed") from e

@app.post(
    "/agents/{agent_id}/verify",
    responses={
        400: {"description": "Invalid security check configuration or agent verification payload."},
        401: {"description": "Invalid agent token."},
        403: {"description": "Agent budget exceeded or request blocked by security checks."},
        500: {"description": "Internal agent verification error."},
    },
)
async def agent_verify(
    agent_id: int,
    request: AgentVerifyRequest,
    x_agent_token: AgentTokenHeader,
    session: SessionDependency
):
    """
    Agent makes a verification request through QWED.
    Includes full audit trail.
    """
    import time
    start_time = time.time()
    
    agent = _require_authenticated_agent(session, agent_id, x_agent_token)
    _enforce_agent_budget(session, agent_id, agent, request.query)
    _run_agent_security_checks(session, agent_id, agent, request)
    result = await _process_agent_verification(agent, request)
    
    # 4. Log activity
    latency = (time.time() - start_time) * 1000
    agent_registry.log_activity(
        session, agent_id, agent.organization_id,
        "verification_request",
        f"Query: {request.query}",
        result.get("status", "unknown"),
        input_data=request.query,
        output_data=json.dumps(result),
        cost=0.01,  # Placeholder cost
        latency_ms=latency
    )
    
    return result

@app.post("/agents/{agent_id}/tools/{tool_name}")
async def agent_tool_call(
    agent_id: int,
    tool_name: str,
    request: ToolCallRequest,
    x_agent_token: str = Header(...),
    session: Session = Depends(get_session)
):
    """
    Agent requests to use a tool/API.
    QWED evaluates risk and approves/denies.
    """
    # 1. Authenticate agent
    agent = agent_registry.authenticate_agent(session, x_agent_token)
    if not agent or agent.id != agent_id:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    
    # 2. Check permission for this tool
    has_permission, reason = agent_registry.check_permission(
        session, agent_id, f"use_tool_{tool_name}"
    )
    
    if not has_permission:
        # Log blocked attempt
        agent_registry.log_activity(
            session, agent_id, agent.organization_id,
            "tool_call_blocked",
            f"Attempted to use '{tool_name}': {reason}",
            "blocked"
        )
        raise HTTPException(status_code=403, detail=reason)
    
    # 3. Evaluate tool call
    approved, blocked_reason, tool_call = tool_approval.approve_tool_call(
        session, agent_id, tool_name, request.tool_params
    )
    
    if not approved:
        # Log blocked tool call
        agent_registry.log_activity(
            session, agent_id, agent.organization_id,
            "tool_call_blocked",
            f"Tool '{tool_name}' blocked: {blocked_reason}",
            "blocked"
        )
        raise HTTPException(status_code=403, detail=blocked_reason)
    
    # 4. Execute approved tool
    success, error, result = tool_approval.execute_tool_call(session, tool_call.id)
    
    # 5. Log execution
    agent_registry.log_activity(
        session, agent_id, agent.organization_id,
        "tool_call_success" if success else "tool_call_failed",
        f"Tool '{tool_name}' executed",
        "success" if success else "failed",
        input_data=json.dumps(request.tool_params),
        output_data=json.dumps(result) if result else error
    )
    
    if not success:
        logger.error(f"Tool execution failed: {redact_pii(str(error))}", exc_info=False)
        raise HTTPException(status_code=500, detail="Tool execution failed")
    
    return {
        "tool": tool_name,
        "approved": True,
        "executed": True,
        "result": result
    }

@app.get("/agents/{agent_id}/activity")
async def get_agent_activity(
    agent_id: int,
    limit: int = 20,
    x_agent_token: str = Header(...),
    session: Session = Depends(get_session)
):
    """
    Get activity log for an agent.
    Provides full audit trail.
    """
    # Authenticate agent
    agent = agent_registry.authenticate_agent(session, x_agent_token)
    if not agent or agent.id != agent_id:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    
    # Get activity
    statement = select(AgentActivity).where(
        AgentActivity.agent_id == agent_id
    ).order_by(AgentActivity.timestamp.desc()).limit(limit)
    
    activities = session.execute(statement).scalars().all()
    
    return {
        "agent_id": agent_id,
        "agent_name": agent.name,
        "total_activities": len(activities),
        "current_cost_today": agent.current_cost_today,
        "max_cost_per_day": agent.max_cost_per_day,
        "activities": [
            {
                "type": act.activity_type,
                "description": act.description,
                "status": act.status,
                "cost": act.cost,
                "timestamp": act.timestamp.isoformat()
            }
            for act in activities
        ]
    }
# Append to main.py - Consensus Verification Endpoint

# ============================================================
# ENHANCED VERIFICATION ENDPOINTS (Phase 2B)
# ============================================================

from qwed_new.core.consensus_verifier import consensus_verifier, VerificationMode

class ConsensusVerifyRequest(BaseModel):
    query: str
    verification_mode: str = "single"  # "single", "high", "maximum"
    min_confidence: float = 0.95  # 0.0 to 1.0

@app.post(
    "/verify/consensus",
    responses={
        400: {"description": "Invalid verification mode."},
        422: {"description": "Consensus confidence below requested minimum."},
        503: {"description": "Secure execution runtime unavailable for required consensus depth."},
    },
)
async def verify_with_consensus(
    request: ConsensusVerifyRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Multi-engine consensus verification.
    
    Verification modes:
    - "single": Fast, single engine (default)
    - "high": 2 engines for higher confidence
    - "maximum": 3+ engines for critical domains (medical, financial)
    
    Returns detailed verification chain and confidence score.
    """
    check_rate_limit(tenant.api_key)

    try:
        # Parse mode
        mode = VerificationMode(request.verification_mode)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid verification_mode. Must be: single, high, or maximum"
        )
    
    # Perform consensus verification
    result = consensus_verifier.verify_with_consensus(
        query=request.query,
        mode=mode,
        min_confidence=request.min_confidence
    )

    if result.agreement_status == "blocked_secure_execution":
        dr = DiagnosticResult.blocked(
            "Consensus verification: blocked — secure execution",
            developer_fields={"agreement_status": result.agreement_status, "confidence": result.confidence, "engines_used": result.engines_used},
        )
        dr = _enforce_trust(dr, query=request.query)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=f"Consensus: {result.agreement_status}",
            is_verified=dr.is_authoritative,
            domain="CONSENSUS"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)

    # All engines blocked — preserve BLOCKED status (fail-closed)
    if result.agreement_status == "blocked":
        dr = DiagnosticResult.blocked(
            "Consensus verification: all engines blocked",
            developer_fields={"agreement_status": result.agreement_status, "confidence": result.confidence, "engines_used": result.engines_used},
        )
        dr = _enforce_trust(dr, query=request.query)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=f"Consensus: {result.agreement_status}",
            is_verified=dr.is_authoritative,
            domain="CONSENSUS"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)

    if result.confidence < request.min_confidence:
        dr = DiagnosticResult.unverifiable(
            f"Confidence ({result.confidence:.1%}) below required minimum ({request.min_confidence:.1%})",
            developer_fields={"agreement_status": result.agreement_status, "confidence": result.confidence, "engines_used": result.engines_used, "min_confidence": request.min_confidence},
        )
        dr = _enforce_trust(dr, query=request.query)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=f"Consensus: {result.agreement_status}, Confidence: {result.confidence:.1%}",
            is_verified=dr.is_authoritative,
            domain="CONSENSUS"
        )
        _safe_commit_log(session, log)
        return _merge_response(dr)

    # Convert consensus result via its own to_diagnostic_result() method —
    # it handles proof_ref, attestation evidence, and DiagnosticStatus mapping.
    dr = result.to_diagnostic_result()
    dr = _enforce_trust(dr, query=request.query)

    log = VerificationLog(
        organization_id=tenant.organization_id,
        query=request.query,
        result=f"Consensus: {result.agreement_status}, Confidence: {result.confidence:.1%}",
        is_verified=dr.is_authoritative,
        domain="CONSENSUS"
    )
    _safe_commit_log(session, log)

    # Format response
    response = {
        "final_answer": result.final_answer,
        "confidence": round(result.confidence, 4),
        "engines_used": result.engines_used,
        "agreement_status": result.agreement_status,
        "verification_chain": [
            {
                "engine": r.engine_name,
                "method": r.method,
                "result": str(r.result),
                "confidence": round(r.confidence, 4),
                "latency_ms": round(r.latency_ms, 2),
                "success": r.success,
                "status": r.status,
            }
            for r in result.verification_chain
        ],
        "total_latency_ms": round(result.total_latency_ms, 2),
        # TRUE only when consensus is both VERIFIED at the trust boundary AND
        # confidence meets the threshold — never confidence alone (#269).
        "meets_requirement": dr.is_verified and result.confidence >= request.min_confidence,
    }
    return _merge_response(dr) | response
# --- Enterprise Security Endpoints (Week 2) ---

from qwed_new.core.compliance_exporter import ComplianceExporter
from qwed_new.core.threat_detector import threat_detector
from qwed_new.core.key_rotation import key_manager
from qwed_new.core.rbac import require_role

compliance_exporter = ComplianceExporter()

@app.get("/admin/compliance/export/csv", tags=["Compliance"])
@require_role(["admin"])
async def export_audit_csv(
    organization_id: int,
    request: Request,  # Required for RBAC
    api_key: ApiKey = Depends(get_api_key)
):
    """Export audit trail as CSV (Admin only)."""
    csv_data = compliance_exporter.export_audit_trail_csv(organization_id)
    return Response(content=csv_data, media_type="text/csv")

@app.get("/admin/compliance/verify/{log_id}", tags=["Compliance"])
@require_role(["admin"])
async def verify_audit_log_entry(
    log_id: int,
    request: Request,
    api_key: ApiKey = Depends(get_api_key),
    session: Session = Depends(get_session)
):
    """
    Cryptographically verify a specific audit log entry.
    Checks HMAC signature and hash chain integrity.
    """
    from qwed_new.core.audit_logger import AuditLogger
    verifier = AuditLogger()
    return verifier.verify_log_entry(log_id, session)

@app.get("/admin/compliance/report/soc2/{org_id}", tags=["Compliance"])
@require_role(["admin"])
async def generate_soc2_report(
    org_id: int,
    request: Request,
    api_key: ApiKey = Depends(get_api_key)
):
    """Generate SOC 2 Type II compliance report."""
    return compliance_exporter.generate_soc2_report(org_id)

@app.get("/admin/security/threats/{org_id}", tags=["Security"])
@require_role(["admin"])
async def get_threat_summary(
    org_id: int,
    request: Request,
    api_key: ApiKey = Depends(get_api_key)
):
    """Get real-time threat summary."""
    return threat_detector.get_threat_summary(org_id)

@app.post("/admin/keys/rotate", tags=["Security"])
@require_role(["admin", "member"])
async def rotate_api_key(
    key_id: int,
    request: Request,
    api_key: ApiKey = Depends(get_api_key)
):
    """Rotate an API key (invalidate old, create new)."""
    new_key, raw_key = key_manager.rotate_key(key_id)
    if not new_key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return {
        "status": "rotated",
        "old_key_id": key_id,
        "new_key_id": new_key.id,
        "new_key_preview": new_key.key_preview,
        "new_key_secret": raw_key  # Show once
    }

@app.on_event("startup")
async def startup_security_tasks():
    """Run background security tasks on startup."""
    # Check for expiring keys
    try:
        key_manager.check_expiring_keys()
    except Exception as e:
        print(f"Startup security check failed: {e}")

# --- End Enterprise Security Endpoints ---

# ============================================================
# BATCH VERIFICATION ENDPOINTS (Phase 4)
# ============================================================

from qwed_new.core.batch import batch_service
from typing import List

class BatchVerifyRequest(BaseModel):
    """Request model for batch verification."""
    items: List[dict]  # Each item: {query, type?, params?}
    
class BatchVerifyItem(BaseModel):
    """Single item in batch request."""
    query: str
    type: str = "natural_language"
    params: Optional[dict] = None

@app.post("/verify/batch", tags=["Batch"])
async def batch_verify(
    request: BatchVerifyRequest,
    tenant: TenantContext = Depends(get_current_tenant)
):
    """
    Submit a batch of verification requests.
    
    Processes all items concurrently and returns aggregated results.
    
    Request body:
    {
        "items": [
            {"query": "What is 2+2?", "type": "natural_language"},
            {"query": "(AND (GT x 5) (LT y 10))", "type": "logic"},
            {"query": "x**2 + 2*x + 1 = (x+1)**2", "type": "math"}
        ]
    }
    
    Supported types: natural_language, logic, math, code, fact, sql
    """
    check_rate_limit(tenant.api_key)
    
    # Validate item count
    if len(request.items) > 100:
        raise HTTPException(
            status_code=400,
            detail="Maximum 100 items per batch"
        )
    
    if len(request.items) == 0:
        raise HTTPException(
            status_code=400,
            detail="At least one item required"
        )
    
    # Create and process job
    job = batch_service.create_job(
        organization_id=tenant.organization_id,
        items=request.items
    )
    
    # Process synchronously (for simplicity)
    # For very large batches, return job_id and process async
    job = await batch_service.process_job(job)
    
    # Return results
    return batch_service.get_job_results(job.job_id)


@app.get("/verify/batch/{job_id}", tags=["Batch"])
async def get_batch_status(
    job_id: str,
    tenant: TenantContext = Depends(get_current_tenant)
):
    """
    Get the status and results of a batch verification job.
    
    Useful for polling when processing large batches asynchronously.
    """
    job = batch_service.get_job(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Authorization: ensure job belongs to this tenant
    if job.organization_id != tenant.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return batch_service.get_job_results(job_id)


# ============================================================
# PROMETHEUS METRICS ENDPOINT
# ============================================================
