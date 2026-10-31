from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import Optional, Annotated
from sqlmodel import Session, select
from datetime import datetime, timezone
import asyncio
import hashlib
import hmac
import os
import logging
import time
from fractions import Fraction

from qwed_new.core.security import redact_pii
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    AdvisoryCheck,
    DiagnosticResult,
    admission_decision,
    merge_diagnostic_result,
)
from qwed_new.core.math_identity import math_identity_result, math_parse_error_result
from qwed_new.core.safe_parser import SafeParserError
from qwed_new.api.verification_context_routes import router as verification_context_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
INTERNAL_VERIFICATION_ERROR = "Internal verification error"
INTERNAL_PROCESSING_ERROR = "Internal processing error"

from qwed_new.core.control_plane import ControlPlane, natural_language_admission
from qwed_new.core.route_diagnostics import logic_diagnostic, natural_language_diagnostic
from qwed_new.core.trust import AdmissionRule, attest_and_enforce
from qwed_new.core.tenant_context import get_current_tenant, TenantContext
from qwed_new.core.database import create_db_and_tables, get_session
from qwed_new.core.audit_logger import get_audit_logger
from qwed_new.core.attestation import get_attestation_service
from qwed_new.core.models import VerificationLog, ApiKey, User, Organization
from qwed_new.core.rate_limiter import check_rate_limit
from qwed_new.core.json_bounding import bound_json_value

# Import auth router
from qwed_new.auth import auth_router
from qwed_new.auth.audit_routes import router as audit_router
from qwed_new.auth.middleware import get_api_key
from qwed_new.auth.routes import get_current_user_token
from qwed_new.auth.security import hash_api_key, is_api_key_live, validate_api_key_format
from qwed_new.api.secret_scanning_routes import router as secret_scanning_router
from qwed_new.api.compliance_routes import router as compliance_router
from qwed_new.api.security_routes import router as security_router
from qwed_new.api.org_users_routes import router as org_users_router
from qwed_new.api.agent_admin_routes import router as agent_admin_router
from qwed_new.core.request_caller import RequestTimingMiddleware
from qwed_new.api.attestation_routes import router as attestation_router

TenantDependency = Annotated[TenantContext, Depends(get_current_tenant)]
SessionDependency = Annotated[Session, Depends(get_session)]
AgentTokenHeader = Annotated[str, Header(...)]

APP_VERSION = "8.0.0"

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
class _BodySizeLimitMiddleware:
    """#353 (CodeAnt + CodeRabbit on PR #354): the endpoint byte cap runs
    AFTER FastAPI has received and spooled the whole multipart body, so by
    itself it cannot stop disk exhaustion. Buffer the request stream here
    and reply 413 before the app ever sees an oversized body — counting
    received chunks, so Content-Length-less chunked uploads are bounded
    too. The endpoint cap stays as the authoritative backstop.

    Buffering happens BEFORE authentication, so concurrent unauthenticated
    uploads could multiply the per-request memory cost (CodeRabbit on PR
    #354: N x max_bytes against the pod limit). A process-wide in-flight
    cap bounds the worst case to max_concurrent x max_bytes; ingress-level
    connection caps stay an infrastructure concern."""

    _max_concurrent = 8
    _in_flight = 0
    # A separate, larger budget for the JSON routes: their bodies are capped
    # small, but they are still buffered before authentication, so concurrent
    # requests must not multiply memory without bound (CodeAnt on PR #447).
    # Worst case stays ~ _json_max_concurrent x _JSON_BODY_LIMIT_BYTES.
    _json_max_concurrent = 64
    _json_in_flight = 0
    # JSON bodies are small and capped, so they get a much tighter read deadline
    # than the large multipart uploads: a stalled JSON request frees its slot in
    # seconds, which shrinks the window a slow client could hold slots pre-auth
    # (Sentry on PR #447). Connection-level slow-loris remains an ingress concern.
    _json_read_deadline_seconds = 10.0

    def __init__(self, app, max_bytes: int = None, path: str = None,
                 limits: dict = None, concurrency_paths=None,
                 read_deadline_seconds: float = 30.0):
        self.app = app
        # Back-compat single-path mode: one capped, concurrency-gated path.
        # Multi-path mode (#392): a per-path byte cap for every /verify route,
        # with the global concurrency slot reserved only for the large
        # multipart uploads (stats, image), since small JSON bodies cost little
        # to buffer and should not be throttled to the upload slot count.
        if limits is None:
            limits = {path: max_bytes}
            concurrency_paths = {path}
        self.limits = {p.rstrip("/"): b for p, b in limits.items()}
        self.concurrency_paths = {p.rstrip("/") for p in (concurrency_paths or ())}
        # Greptile P1 on PR #354: the capacity slot is reserved before
        # authentication, so slow-loris uploads must not hold it forever —
        # the whole body read is bounded by one wall-clock deadline.
        self.read_deadline_seconds = read_deadline_seconds

    async def __call__(self, scope, receive, send):
        # normalize the trailing slash: FastAPI redirects /verify/stats/
        # but the server still receives and spools the WHOLE body before
        # the redirect, so the guard must match both forms (Sentry on
        # PR #354)
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        norm = scope["path"].rstrip("/")
        max_bytes = self.limits.get(norm)
        if max_bytes is None:
            await self.app(scope, receive, send)
            return
        cls = _BodySizeLimitMiddleware
        if norm not in self.concurrency_paths:
            # JSON route: small body, but the replay closure retains it until the
            # handler reads it, so the slot is held for the whole request to keep
            # _json_max_concurrent x cap a real memory bound (CodeRabbit/Greptile
            # on PR #447). The large JSON budget and the short read deadline keep
            # the saturation risk low; connection-level slow-loris is ingress's
            # concern, as the upload path documents.
            if cls._json_in_flight >= cls._json_max_concurrent:
                await JSONResponse(
                    status_code=503,
                    content={"detail": "Server busy — retry shortly."},
                )(scope, receive, send)
                return
            cls._json_in_flight += 1
            try:
                body = await self._read_body(
                    scope, receive, send, max_bytes,
                    deadline_seconds=self._json_read_deadline_seconds,
                )
                if body is not None:
                    await self.app(scope, self._replay(body), send)
            finally:
                cls._json_in_flight -= 1
            return

        # Multipart upload: the body is large and is retained (by the replay
        # closure) until the handler consumes it, so the slot is held for the
        # whole request to keep max_concurrent x max_bytes a real memory bound
        # (Greptile on PR #447).
        if cls._in_flight >= cls._max_concurrent:
            await JSONResponse(
                status_code=503,
                content={"detail": "Upload capacity reached — retry shortly."},
            )(scope, receive, send)
            return
        cls._in_flight += 1
        try:
            body = await self._read_body(scope, receive, send, max_bytes)
            if body is not None:
                await self.app(scope, self._replay(body), send)
        finally:
            cls._in_flight -= 1

    @staticmethod
    def _replay(body: bytes):
        # ASGI receive contract (Sentry on PR #354): the replayed body is
        # delivered ONCE; later calls report disconnect.
        replayed = False

        async def replay_receive():  # NOSONAR
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        return replay_receive

    async def _read_body(self, scope, receive, send, max_bytes, deadline_seconds=None):
        """Read the whole body under the cap and deadline. Returns the bytes, or
        None after sending a 413/408 or on client disconnect."""
        body = bytearray()
        deadline = time.monotonic() + (self.read_deadline_seconds if deadline_seconds is None else deadline_seconds)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await JSONResponse(
                    status_code=408,
                    content={"detail": "Request body not received in time."},
                )(scope, receive, send)
                return None
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except asyncio.TimeoutError:
                await JSONResponse(
                    status_code=408,
                    content={"detail": "Request body not received in time."},
                )(scope, receive, send)
                return None
            if message["type"] == "http.disconnect":
                return None
            body.extend(message.get("body", b""))
            if len(body) > max_bytes:
                await JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body exceeds the {max_bytes} byte limit for this endpoint."},
                )(scope, receive, send)
                return None
            if not message.get("more_body", False):
                break
        return bytes(body)

        await self.app(scope, replay_receive, send)


# #353: hard byte cap on the /verify/stats upload. read_csv is CPU- and
# memory-bound on input size, so the upload is read under this cap and the
# excess rejected (413) before any parse work starts.
# Wall-clock bound for a single code verification run on the event loop (#445).
_CODE_VERIFY_TIMEOUT_SECONDS = float(os.environ.get("QWED_CODE_VERIFY_TIMEOUT", "10"))
# Wall-clock bound for a blocking provider (LLM) call run off the loop (#390).
_PROVIDER_CALL_TIMEOUT_SECONDS = float(os.environ.get("QWED_PROVIDER_TIMEOUT", "30"))
_MAX_STATS_UPLOAD_BYTES = 10_000_000
# #353 (CodeAnt on PR #354): the byte cap bounds transfer, not the expanded
# in-memory frame — bound rows x columns after the parse as well.
_MAX_STATS_CELL_COUNT = 1_000_000
# #353 (Greptile P1 on PR #354): the body-limit middleware caps the whole
# multipart envelope, so a documented-max 10MB CSV rides in a slightly
# larger body — give the BODY cap envelope headroom; the endpoint's file
# cap stays the authoritative file-size boundary.
_STATS_BODY_LIMIT_BYTES = _MAX_STATS_UPLOAD_BYTES + 65_536

# #392: a transport-level body cap on EVERY /verify route, not only
# /verify/stats. Oversized bodies are rejected (413) before the handler reads
# them, so a large JSON or image payload cannot be spooled into memory first.
# JSON routes get a small cap; the two multipart uploads keep their larger caps
# and the global concurrency slot (buffering a big body is what that slot
# bounds). _JSON_BODY_LIMIT_BYTES is generous for verification requests, whose
# bodies are a query plus a small schema or snippet.
_JSON_BODY_LIMIT_BYTES = 1_000_000
# The image handler accepts files up to 10 MiB (10 * 1024 * 1024); the multipart
# envelope is larger, so the body cap is that file limit plus field headroom,
# or a within-limit upload would be rejected before the handler ran.
_IMAGE_BODY_LIMIT_BYTES = 10 * 1024 * 1024 + 65_536
_VERIFY_JSON_PATHS = (
    "/verify/natural_language", "/verify/logic", "/verify/fact", "/verify/code",
    "/verify/math", "/verify/sql", "/verify/rag", "/verify/process",
    "/verify/consensus", "/verify/batch",
)
_BODY_LIMITS = dict.fromkeys(_VERIFY_JSON_PATHS, _JSON_BODY_LIMIT_BYTES)
_BODY_LIMITS["/verify/stats"] = _STATS_BODY_LIMIT_BYTES
_BODY_LIMITS["/verify/image"] = _IMAGE_BODY_LIMIT_BYTES

# Registered BEFORE CORSMiddleware: add_middleware is LIFO, so CORS must be
# added last to stay outermost and stamp its headers onto the 413s this
# middleware short-circuits with (Sentry + Sonar on PR #354).
app.add_middleware(
    _BodySizeLimitMiddleware,
    limits=_BODY_LIMITS,
    concurrency_paths={"/verify/stats", "/verify/image"},
)

app.add_middleware(RequestTimingMiddleware)  # #528: audit latency_ms

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ORIGINS != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Export-Truncated"],  # #508: a cut CSV export
)





# Include routers
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(verification_context_router)
app.include_router(secret_scanning_router)
app.include_router(compliance_router)
app.include_router(security_router)
app.include_router(org_users_router)
app.include_router(agent_admin_router)
app.include_router(attestation_router)

# Verified leak reports -> auto-revoke + owner notify (#368). Assigned here
# (not import-time in the routes module) so the production wiring is explicit
# and tests can substitute the sink without touching the router.
from qwed_new.api import secret_scanning_routes as _secret_scanning_routes
from qwed_new.api.secret_revocation import revoke_leaked_keys as _revoke_leaked_keys

_secret_scanning_routes.on_verified_matches = _revoke_leaked_keys

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


def _enforce_environment_integrity() -> None:
    """Fail startup if Python startup hooks cannot be verified as safe."""
    if os.environ.get("QWED_SKIP_ENV_INTEGRITY_CHECK") == "true":
        logger.warning("Bypassing environment integrity check due to QWED_SKIP_ENV_INTEGRITY_CHECK")
        return

    from qwed_sdk.guards.environment_guard import (
        StartupHookGuard,
        parse_startup_hook_allowlist,
    )

    # Names, and NAME.pth:sha256:<hex> digest pins (#491); a bad pin raises.
    names, pins = parse_startup_hook_allowlist(os.environ.get("QWED_ALLOWED_STARTUP_PTH_FILES", ""))
    guard = StartupHookGuard(allowed_pth_files=STARTUP_ALLOWED_PTH_FILES | names, pinned_pth_digests=pins)
    result = guard.verify_environment_integrity()
    if not result.get("verified"):
        logger.critical(f"Startup environment integrity check failed: {result}")
        raise RuntimeError(f"Environment integrity verification failed: {result.get('risk')}")


def _migrate_agent_tokens() -> None:
    """Hash agent tokens still stored in plaintext; a no-op once done (#478)."""
    from qwed_new.core.agent_registry import agent_registry as _registry
    from qwed_new.core.database import engine

    with Session(engine) as session:
        migrated = _registry.migrate_plaintext_agent_tokens(session)
    if migrated:
        logger.info("Hashed %d agent token(s) stored in plaintext (#478)", migrated)


@app.on_event("startup")
def on_startup():
    _enforce_environment_integrity()
    create_db_and_tables()
    # Fail closed at boot: every verify endpoint appends to the signed audit
    # chain, so the server does not start without QWED_AUDIT_SECRET_KEY.
    get_audit_logger()
    # Likewise a configured signing key that cannot be used (#319), which
    # would otherwise surface only as BLOCKED results once traffic arrives.
    get_attestation_service()
    # After the fail-closed checks: a server that refuses to start does not
    # touch stored data.
    _migrate_agent_tokens()

# Initialize Kernel (Control Plane)
control_plane = ControlPlane()

def _enforce_trust(
    dr: DiagnosticResult,
    query: str,
    *,
    engine: str,
    admission: AdmissionRule | None = None,
) -> DiagnosticResult:
    """Sign a VERIFIED result and enforce its attestation as mandatory (#320).

    Callers must use the returned DiagnosticResult for audit logging and
    response construction: a VERIFIED result whose attestation cannot be
    issued or does not check out comes back BLOCKED (see core/trust.py).
    A route that decides an admission passes its rule, so the token signs the
    admission the route returns (#321).
    """
    return attest_and_enforce(dr, engine=engine, query=query, admission=admission)


_merge_response = merge_diagnostic_result  # shared merge helper (#271)


class AuditPersistenceError(HTTPException):
    """An audit row could not be appended to its organisation's chain.

    An HTTPException on purpose: every verify endpoint re-raises
    HTTPException ahead of its generic ``except Exception`` handler, so an
    audit failure ends the request as a 500. As a plain exception, the
    generic handler would replace the real result with a BLOCKED one and
    try the append again, and a retry that succeeded would return 200 with
    a record of the replacement instead of the result.
    """

    def __init__(self) -> None:
        super().__init__(status_code=500, detail="audit persistence failed")


def _safe_commit_log(log):
    """Append a VerificationLog row to its organisation's audit chain, or fail closed.

    The row is written by the process-wide AuditLogger (hash-chained and
    HMAC-signed), not through the request session, so /admin/compliance/verify
    and verify_audit_trail can check it. Any failure (QWED_AUDIT_SECRET_KEY
    unset, a persisted chain head that fails verification, a continuity
    mismatch, a database error) raises a 500: a verification result is never
    returned without its audit record.
    """
    try:
        get_audit_logger().log_verification(
            organization_id=log.organization_id,
            user_id=log.user_id,
            query=log.query,
            result=log.result,
            is_verified=log.is_verified,
            domain=log.domain,
            raw_llm_output=log.raw_llm_output,
            admission=log.admission,
        )
    except Exception as exc:
        logger.error("Audit persistence failed: %s", type(exc).__name__)
        raise AuditPersistenceError() from None


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

    # Offline format pre-filter (issue #366): a malformed key resolves to no
    # credential (None) before an HMAC + DB lookup, so a request that also
    # carries a valid operator JWT is not preempted by garbage in the
    # x-api-key header. Both v1 and v2 shapes pass through to the lookup.
    if validate_api_key_format(x_api_key) == "invalid":
        return None

    hashed_key = hash_api_key(x_api_key)
    statement = select(ApiKey).where(ApiKey.key_hash == hashed_key, ApiKey.is_active)
    api_key = session.execute(statement).scalars().first()

    # Any x-api-key that is not a usable credential resolves to None, never a
    # raise, so a request that also carries a valid operator JWT is not
    # preempted at the dependency layer (Sentry on PR #349). That covers an
    # unknown or revoked key (is_active=False, filtered out by the query above
    # — CodeAnt on PR #454) as well as an expired/revoked row that reaches the
    # liveness check: is_active alone is not liveness, since an expired key
    # keeps is_active=True (CodeAnt on PR #349). require_metrics_access
    # re-decides on the remaining credentials and still denies key-only callers.
    if not api_key or not is_api_key_live(api_key):
        return None

    return api_key


# #339: VerificationLog.result snapshots the full DiagnosticResult dict. The
# amplifier path is capped at its source (stats_verifier caps observed_result),
# this is the audit-trail backstop so no endpoint can persist an unbounded
# serialized result row.
_MAX_LOG_RESULT_CHARS = 64_000
_MAX_LOG_RESULT_STRING_CHARS = 1_000
# Aggregate traversal budget (Greptile P1 on PR #351): stop cloning the
# structure once enough bounded content has been retained, so a request
# with very many small values cannot drive unbounded traversal on the
# event loop. The bounding traversal itself lives in
# qwed_new.core.json_bounding, shared with stats_verifier (Sonar: the two
# copies had already diverged).
_LOG_BOUND_BUDGET_CHARS = 2 * _MAX_LOG_RESULT_CHARS




def _cap_log_result(result_dict) -> str:
    """Serialize a DiagnosticResult dict for VerificationLog.result, capped.

    The audit integrity verifier decodes this field with json.loads
    (audit_logger._decode_result_payload — malformed payloads raise
    SecurityError), so both paths must emit VALID JSON, not Python repr.
    Serialization is streamed and aggregate-bounded (see
    qwed_new.core.json_bounding) so an oversized dict never materializes in
    memory, and the fallback stays strictly inside the cap: the envelope
    length is reserved before slicing, the preview is sanitized of
    non-printable and JSON-escapable characters, and ensure_ascii=False keeps
    printable non-ASCII at 1 char each (CodeRabbit on PR #351).
    """
    parts = []
    total = 0
    try:
        bounded = bound_json_value(
            result_dict,
            max_string_chars=_MAX_LOG_RESULT_STRING_CHARS,
            budget_chars=_LOG_BOUND_BUDGET_CHARS,
            string_marker="...[truncated]",
            budget_marker="...audit truncated",
        )
        for chunk in json.JSONEncoder(default=str).iterencode(bounded):
            parts.append(chunk)
            total += len(chunk)
            if total > _MAX_LOG_RESULT_CHARS:
                break
    except (TypeError, ValueError, RecursionError):
        return json.dumps({"truncated": True, "unserializable": True})
    if total <= _MAX_LOG_RESULT_CHARS:
        return "".join(parts)
    envelope = json.dumps({"truncated": True, "preview": ""})
    preview = "".join(parts)[:(_MAX_LOG_RESULT_CHARS - len(envelope))]
    # strip control characters AND JSON-escapable characters: with both gone,
    # ensure_ascii=False encodes the preview exactly 1 char per char, so the
    # stored payload is envelope + preview <= _MAX_LOG_RESULT_CHARS
    preview = "".join(ch if ch.isprintable() else "?" for ch in preview)
    preview = preview.replace("\\", "?").replace('"', "'")
    return json.dumps({"truncated": True, "preview": preview}, ensure_ascii=False)


_METRICS_OPERATOR_ENV_VAR = "QWED_METRICS_OPERATOR_USER_IDS"


def _get_metrics_operator_ids() -> set:
    """Parse the platform-operator allowlist from the environment.

    Read per request (not cached at import) so operators can be granted or
    rotated without a process restart. Entries are user IDs, comma-separated;
    blank entries are ignored.
    """
    raw = os.getenv(_METRICS_OPERATOR_ENV_VAR, "")
    return {entry.strip() for entry in raw.split(",") if entry.strip()}


def _is_metrics_operator(user: Optional[User]) -> bool:
    """Platform-operator check for ALL-tenant metrics (issue #337).

    "owner"/"admin" are per-organization roles: self-service signup mints
    role="owner" for every new account, so a role check here degenerates to
    "possess any account". Only explicitly configured operator user IDs may
    read cross-tenant metrics; an unset allowlist denies everyone (fail-closed).
    """
    if user is None or not user.is_active or user.id is None:
        return False
    return str(user.id) in _get_metrics_operator_ids()


def require_metrics_access(
    current_user: Annotated[Optional[User], Depends(get_optional_current_user)],
    api_key_record: Annotated[Optional[ApiKey], Depends(get_optional_api_key_record)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    """Restrict all-tenant metrics to explicit platform operators.

    DEPLOY NOTE: set QWED_METRICS_OPERATOR_USER_IDS (comma-separated user IDs)
    to grant access — with the variable unset these endpoints deny every
    caller, including org owners and admins (issue #337).
    """
    if _is_metrics_operator(current_user):
        return

    if api_key_record is not None:
        api_key_user = session.get(User, api_key_record.user_id) if api_key_record.user_id else None
        if _is_metrics_operator(api_key_user):
            return
        raise HTTPException(status_code=403, detail="Platform operator access required")

    if current_user is not None:
        raise HTTPException(status_code=403, detail="Platform operator access required")

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
        dr = _natural_language_diagnostic(result)
    dr = _enforce_trust(
        dr, query=request.query, engine="natural_language", admission=natural_language_admission
    )
    # The verdict covers the LLM's translated expression, not the user's
    # question, so it is never admitted for the question while the
    # translation itself is unverified. The verdict stays as produced
    # (QWED #15); only admission is withheld.
    admission = natural_language_admission(dr)

    log = VerificationLog(
        organization_id=tenant.organization_id,
        user_id=tenant.user_id if hasattr(tenant, 'user_id') else None,
        query=request.query,
        result=_cap_log_result(dr.to_dict()),
        # The log row is keyed by the user's question, which is only
        # verified when it is admitted.
        is_verified=admission is AdmissionDecision.ADMIT,
        domain="NATURAL_LANGUAGE",  # #520: its own domain, not MATH
        admission=admission.value,  # #307: as returned
    )
    _safe_commit_log(log)

    response = _merge_response(dr)
    response["admission"] = admission.value
    return response


# Shared with /verify/batch so a batch item gets what its route returns (#494).
_natural_language_diagnostic = natural_language_diagnostic

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

        # Shared with /verify/batch (#494).
        dr = _enforce_trust(logic_diagnostic(result), query=request.query, engine="logic")

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="LOGIC"
        )
        _safe_commit_log(log)

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
        dr = _enforce_trust(dr, query=request.query, engine="logic")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="LOGIC"
        )
        _safe_commit_log(log)
        return _merge_response(dr)

# #353 (CodeAnt + CodeRabbit on PR #354): the byte cap bounds TRANSFER,
# not pandas memory — parse in chunks and abort the moment the accumulated
# rows x columns cell count crosses the budget, so a compact-but-wide CSV
# cannot allocate an oversized frame before the 413.
def _read_bounded_csv(source):
    # CodeRabbit on PR #354: chunksize bounds ROWS, not columns —
    # preflight the column count from the header and derive the
    # rows-per-chunk budget so no single chunk can exceed the cell
    # budget when pandas materializes it.
    import pandas as pd

    if hasattr(source, "seek"):
        source.seek(0)
    # Greptile P2 on PR #354: empty and blank-only uploads raise
    # EmptyDataError BEFORE any column exists — a 400 here, not the broad
    # handler's generic BLOCKED 200, is what tells clients the input was
    # malformed
    try:
        header = pd.read_csv(source, nrows=0)
    except pd.errors.EmptyDataError as exc:
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV contains no data.",
        ) from exc
    n_columns = len(header.columns)
    if n_columns == 0:
        # Sentry LOW on PR #354: a malformed CSV parsed as zero columns
        # would otherwise ZeroDivisionError into a generic 500
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV has no columns to verify.",
        )
    if n_columns > _MAX_STATS_CELL_COUNT:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded dataset expands beyond the {_MAX_STATS_CELL_COUNT} cell limit for statistical verification.",
        )
    if hasattr(source, "seek"):
        source.seek(0)
    rows_per_chunk = max(1, _MAX_STATS_CELL_COUNT // n_columns)
    reader = pd.read_csv(source, chunksize=rows_per_chunk)
    chunks = []
    total_cells = 0
    try:
        for chunk in reader:
            total_cells += int(chunk.size)
            if total_cells > _MAX_STATS_CELL_COUNT:
                raise HTTPException(
                    status_code=413,
                    detail=f"Uploaded dataset expands beyond the {_MAX_STATS_CELL_COUNT} cell limit for statistical verification.",
                )
            chunks.append(chunk)
    finally:
        close = getattr(reader, "close", None)
        if close is not None:
            close()
    if not chunks:
        return pd.DataFrame()
    return pd.concat(chunks, ignore_index=True)



@app.post(
    "/verify/stats",
    responses={
        403: {"description": "Verification blocked by security policy."},
        503: {"description": "Secure execution runtime unavailable."},
        413: {"description": "Upload exceeds the byte or expanded-cell limit for statistical verification."},
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
        import io

        import pandas as pd
        # #353: read_csv on an uncapped upload is an unbounded CPU/memory
        # wait inside the engine call path — read the upload under a hard
        # byte cap and reject the excess before any parse work happens.
        upload = await file.read(_MAX_STATS_UPLOAD_BYTES + 1)
        if len(upload) > _MAX_STATS_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Upload exceeds the {_MAX_STATS_UPLOAD_BYTES} byte limit for statistical verification.",
            )
        # #341: the whole stats chain is synchronous — read_csv (CPU-bound,
        # attacker-sized upload), the blocking LLM codegen round trip, and
        # the Docker daemon calls must not run inline on the event loop.
        # #353 (CodeAnt + CodeRabbit on PR #354): the byte cap bounds
        # TRANSFER, not pandas memory — parse in chunks and abort the
        # moment the accumulated rows x columns cell count crosses the
        # budget, so a compact-but-wide CSV cannot allocate an oversized
        # frame before the 413.
        df = await asyncio.to_thread(_read_bounded_csv, io.BytesIO(upload))

        from qwed_new.core.stats_verifier import StatsVerifier
        verifier = StatsVerifier()

        dr = await asyncio.to_thread(verifier.verify_stats, query, df, None)
        dr = _enforce_trust(dr, query=query, engine="stats")

        # Fail-closed audit semantics (P1 #297): never log a BLOCKED / non-
        # authoritative result as verified. is_authoritative is False for every
        # fail-closed status (BLOCKED/UNVERIFIABLE proof_ref=None), so a result
        # cannot be persisted as verified unless it is a proven claim AND its
        # claim-validity signal is true. developer_fields.is_valid alone is
        # mutable engine metadata and must not drive the audit bit.
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative
            and dr.developer_fields.get("is_valid") is True,
            domain="STATS"
        )
        _safe_commit_log(log)

        return _merge_response(dr)
    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Stats verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_PROCESSING_ERROR,
            {"constraint_id": "api.stats.execution_error"},
        )
        dr = _enforce_trust(dr, query=query, engine="stats")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="STATS"
        )
        _safe_commit_log(log)
        return _merge_response(dr)


@app.post("/verify/fact", responses={503: {"description": "Fact verification timed out"}})
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

        # The fact verifier makes a blocking provider (LLM) call; run it off the
        # event loop under a wall-clock bound so a slow upstream cannot stall the
        # worker for every co-tenant (#390). A timeout fails closed with 503,
        # like /verify/code.
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(verifier.verify_fact, claim, context, provider=provider),
                timeout=_PROVIDER_CALL_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            raise HTTPException(status_code=503, detail="Fact verification timed out.") from None

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
        dr = _enforce_trust(dr, query=claim, engine="fact")

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=claim,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="FACT"
        )
        _safe_commit_log(log)

        return _merge_response(dr)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fact verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_VERIFICATION_ERROR,
            {"constraint_id": "api.fact.execution_error", "verdict": "ERROR"},
        )
        dr = _enforce_trust(dr, query=claim, engine="fact")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=claim,
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="FACT"
        )
        _safe_commit_log(log)
        return _merge_response(dr)


@app.post("/verify/code", responses={503: {"description": "Code verification timed out"}})
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

        # Static analysis is CPU-bound and its cost grows with the snippet, so
        # it runs in a worker thread under a wall-clock bound rather than inline
        # on the shared event loop (#445). A timeout fails closed: a snippet the
        # verifier could not finish is not admitted.
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(verifier.verify_code, code, language=language),
                timeout=_CODE_VERIFY_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            raise HTTPException(status_code=503, detail="Code verification timed out.")

        # Verification truth is preserved unchanged: a proven-unsafe snippet is
        # VERIFIED-as-unsafe (developer_fields.is_valid False, proof_ref bound).
        # Admission is a SEPARATE decision at this boundary (QWED #7, #13, #15):
        # unsafe code must never be admitted, so we expose an explicit
        # AdmissionDecision rather than letting authority-only consumers treat
        # proof_ref as "safe to execute".
        dr = result
        dr = _enforce_trust(dr, query=code, engine="code", admission=admission_decision)
        admission = admission_decision(dr)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=code[:200],
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.developer_fields.get("is_valid") is True,
            domain="CODE",
            admission=admission.value,  # #307: as returned
        )
        _safe_commit_log(log)

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
        dr = _enforce_trust(dr, query=code, engine="code", admission=admission_decision)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=(code or "")[:200],
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="CODE",
            admission=admission_decision(dr).value,  # #307: as returned
        )
        _safe_commit_log(log)
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
            # Shared with batch math items (#530): proven false is VERIFIED
            # with is_valid False (#437), an undecided difference UNVERIFIABLE.
            dr = math_identity_result(expression)
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

        dr = _enforce_trust(dr, query=expression, engine="math", admission=admission_decision)
        # A proven-false identity is VERIFIED too, so the verdict alone is
        # not "safe to use": expose admission separately (QWED #15).
        admission = admission_decision(dr)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=expression,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.developer_fields.get("is_valid") is True,
            domain="MATH",
            admission=admission.value,  # #307: as returned
        )
        _safe_commit_log(log)

        response = _merge_response(dr)
        response["admission"] = admission.value
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Math verification error: {redact_pii(str(e))}", exc_info=False)
        if isinstance(e, SafeParserError):
            # Input the parser refused is the caller's to fix, not an
            # internal error (#522); SQL and schema use the same shape.
            dr = math_parse_error_result(e)
        else:
            dr = DiagnosticResult.blocked(
                INTERNAL_VERIFICATION_ERROR,
                {"constraint_id": "api.math.execution_error"},
            )
        dr = _enforce_trust(dr, query=expression, engine="math", admission=admission_decision)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=expression,
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="MATH",
            admission=admission_decision(dr).value,  # #307: as returned
        )
        _safe_commit_log(log)
        response = _merge_response(dr)
        response["admission"] = admission_decision(dr).value
        return response


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
        dr = _enforce_trust(dr, query=query, engine="sql", admission=admission_decision)
        admission = admission_decision(dr)

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="SQL",
            admission=admission.value,  # #307: as returned
        )
        _safe_commit_log(log)

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
        dr = _enforce_trust(dr, query=query, engine="sql", admission=admission_decision)
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="SQL",
            admission=admission_decision(dr).value,  # #307: as returned
        )
        _safe_commit_log(log)
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
        dr = _enforce_trust(dr, query=claim, engine="image")

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Image claim: {claim}",
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="IMAGE"
        )
        _safe_commit_log(log)

        return _merge_response(dr)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_PROCESSING_ERROR,
            {"constraint_id": "api.image.execution_error", "verdict": "INCONCLUSIVE", "confidence": 0.0},
        )
        dr = _enforce_trust(dr, query=claim, engine="image")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Image claim: {claim}",
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="IMAGE"
        )
        _safe_commit_log(log)
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
            dr = _enforce_trust(dr, query=request.target_document_id, engine="rag")
            log = VerificationLog(
                organization_id=tenant.organization_id,
                query=f"RAG Document Verify: {request.target_document_id}",
                result=_cap_log_result(dr.to_dict()),
                is_verified=False,
                domain="RAG"
            )
            _safe_commit_log(log)
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
        dr = _enforce_trust(dr, query=request.target_document_id, engine="rag")

        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"RAG Document Verify: {request.target_document_id}",
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="RAG"
        )
        _safe_commit_log(log)
        
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
        dr = _enforce_trust(dr, query=doc_id, engine="rag")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"RAG Document Verify: {doc_id}",
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="RAG"
        )
        _safe_commit_log(log)
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
        dr = _enforce_trust(dr, query=request.trace, engine="process")
            
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Process Verification ({request.mode})",
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="PROCESS"
        )
        _safe_commit_log(log)
        
        return _merge_response(dr)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Process verification error: {redact_pii(str(e))}", exc_info=False)
        dr = DiagnosticResult.blocked(
            INTERNAL_PROCESSING_ERROR,
            {"constraint_id": "api.process.execution_error", "verified": False},
        )
        dr = _enforce_trust(dr, query=request.trace, engine="process")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Process Verification ({request.mode})",
            result=_cap_log_result(dr.to_dict()),
            is_verified=False,
            domain="PROCESS"
        )
        _safe_commit_log(log)
        return _merge_response(dr)


# ============================================================
# OBSERVABILITY ENDPOINTS
# ============================================================

from qwed_new.core.observability import (
    get_prometheus_content_type,
    get_prometheus_metrics,
    metrics_collector,
)
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

@app.get(
    "/health/identity",
    responses={
        400: {"description": "Missing nonce or nonce longer than 128 characters"},
        503: {"description": "Server secrets not configured"},
    },
)
async def server_identity(nonce: str = ""):
    """
    Challenge-response proof of the active server secret set (issue #376).

    Lets `qwed init` prove the healthy localhost server it found actually
    holds its secrets before bootstrapping an API key against it — a foreign
    process on the same port (or a stale server on older values) fails the
    comparison and init refuses to continue.

    The caller supplies a fresh ``nonce``; the server returns domain-separated
    HMAC-SHA256 tags over it under each secret. Deterministic fingerprints
    would be replayable by any same-host process that once observed them
    (CodeRabbit CWE-294 + Greptile P1 on #388); binding the response to a
    caller nonce makes a captured response useless for any later handshake.
    Preimages stay server-side in all cases. Unauthenticated like /health
    (init has no credentials yet); loopback-scoped by deployment. Missing
    server secrets fail closed with 503 rather than proving anything.
    """
    if not nonce or len(nonce) > 128:
        raise HTTPException(status_code=400, detail="nonce is required (max 128 characters)")
    jwt_secret = os.getenv("QWED_JWT_SECRET_KEY", "")
    lookup_secret = os.getenv("QWED_API_KEY_LOOKUP_SECRET", "")
    audit_secret = os.getenv("QWED_AUDIT_SECRET_KEY", "")
    if not jwt_secret or not lookup_secret or not audit_secret:
        raise HTTPException(status_code=503, detail="server secrets not configured")

    def _prove(secret: str, domain: str) -> str:
        return hmac.new(
            secret.encode(),
            f"qwed-server-identity-v1:{domain}:{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()

    return {
        "identity": {
            "jwt_hmac": _prove(jwt_secret, "jwt"),
            "lookup_hmac": _prove(lookup_secret, "lookup"),
            "audit_hmac": _prove(audit_secret, "audit"),
        }
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
from qwed_new.core.agent_models import Agent
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

    Appends a chained, signed row to the organisation's audit trail, as
    /verify/natural_language does, and also logs the call to the agent's
    activity. The result is not returned if the audit append fails (#477).
    """
    import time
    start_time = time.time()

    agent = _require_authenticated_agent(session, agent_id, x_agent_token)
    _enforce_agent_budget(session, agent_id, agent, request.query)
    _run_agent_security_checks(session, agent_id, agent, request)
    result = await _process_agent_verification(agent, request)

    # The same row /verify/natural_language writes, plus the agent id.
    # AgentActivity is neither chained nor signed, so it is not the audit
    # record (#477).
    dr = _enforce_trust(
        _natural_language_diagnostic(result),
        query=request.query,
        engine="natural_language",
        admission=natural_language_admission,
    )
    admission = natural_language_admission(dr)
    await asyncio.to_thread(_safe_commit_log, VerificationLog(
        organization_id=agent.organization_id,
        user_id=None,
        query=request.query,
        result=_cap_log_result({**dr.to_dict(), "agent_id": agent_id}),
        is_verified=admission is AdmissionDecision.ADMIT,
        domain="NATURAL_LANGUAGE",  # #520
        admission=admission.value,  # #307
    ))
    # The enforced verdict with its admission, as /verify/natural_language
    # returns: not the control plane's raw dict, which a failed attestation
    # would not have blocked (#320).
    response = _merge_response(dr)
    response["admission"] = admission.value

    # 4. Log activity
    latency = (time.time() - start_time) * 1000
    agent_registry.log_activity(
        session, agent_id, agent.organization_id,
        "verification_request",
        f"Query: {request.query}",
        dr.status.value,
        input_data=request.query,
        output_data=json.dumps(response, default=str),
        cost=0.01,  # Placeholder cost
        latency_ms=latency
    )

    return response

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
    
    # Perform consensus verification.
    # #340: the sync orchestrator runs engines inline on the event loop
    # (a 'single'-mode request blocks the WHOLE service for the full
    # synchronous LLM round trip + sympy evaluation). verify_async submits
    # every engine to the executor and enforces a hard per-engine timeout
    # via asyncio.wait_for; min_confidence is enforced below by this
    # endpoint, as it was before.
    result = await consensus_verifier.verify_async(
        query=request.query,
        mode=mode,
        timeout_seconds=30.0,
    )

    if result.agreement_status == "blocked_secure_execution":
        dr = DiagnosticResult.blocked(
            "Consensus verification: blocked — secure execution",
            developer_fields={"agreement_status": result.agreement_status, "confidence": result.confidence, "engines_used": result.engines_used},
        )
        dr = _enforce_trust(dr, query=request.query, engine="consensus")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="CONSENSUS"
        )
        _safe_commit_log(log)
        return _merge_response(dr)

    # All engines blocked — preserve BLOCKED status (fail-closed)
    if result.agreement_status == "blocked":
        dr = DiagnosticResult.blocked(
            "Consensus verification: all engines blocked",
            developer_fields={"agreement_status": result.agreement_status, "confidence": result.confidence, "engines_used": result.engines_used},
        )
        dr = _enforce_trust(dr, query=request.query, engine="consensus")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="CONSENSUS"
        )
        _safe_commit_log(log)
        return _merge_response(dr)

    if result.confidence < request.min_confidence:
        dr = DiagnosticResult.unverifiable(
            f"Confidence ({result.confidence:.1%}) below required minimum ({request.min_confidence:.1%})",
            developer_fields={"agreement_status": result.agreement_status, "confidence": result.confidence, "engines_used": result.engines_used, "min_confidence": request.min_confidence},
        )
        dr = _enforce_trust(dr, query=request.query, engine="consensus")
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=request.query,
            result=_cap_log_result(dr.to_dict()),
            is_verified=dr.is_authoritative,
            domain="CONSENSUS"
        )
        _safe_commit_log(log)
        return _merge_response(dr)

    # Convert consensus result via its own to_diagnostic_result() method —
    # it handles proof_ref, attestation evidence, and DiagnosticStatus mapping.
    dr = result.to_diagnostic_result()
    dr = _enforce_trust(dr, query=request.query, engine="consensus")

    log = VerificationLog(
        organization_id=tenant.organization_id,
        query=request.query,
        result=_cap_log_result(dr.to_dict()),
        is_verified=dr.is_authoritative,
        domain="CONSENSUS"
    )
    _safe_commit_log(log)

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

from qwed_new.api.compliance_routes import FOREIGN_ORG_DETAIL as _FOREIGN_ORG_DETAIL, compliance_exporter
from qwed_new.core.threat_detector import threat_detector
from qwed_new.core.key_rotation import key_manager
from qwed_new.auth.roles import ROLE_RANK
from qwed_new.api.admin_auth import AdminContext, require_admin_role


# Role hierarchy for admin operations (higher number = more privilege); one
# ranking shared with the user-session routes (#478).
_ROLE_RANK = ROLE_RANK


# AdminContext and require_admin_role live in api/admin_auth.py (#485).


# Module-level dependency singletons (avoids calling require_admin_role in
# argument defaults — Ruff B008 — and builds each dependency once).
_REQUIRE_ADMIN_OR_MEMBER = Depends(require_admin_role(["owner", "admin", "member"]))
# Also a signed-in user: compliance (#485), threat summary (#506), key rotation (#505).
_REQUIRE_ADMIN_OR_SESSION = Depends(require_admin_role(["owner", "admin"], allow_session=True))
_REQUIRE_MEMBER_OR_SESSION = Depends(require_admin_role(["owner", "admin", "member"], allow_session=True))
_FOREIGN_ORG_RESPONSE = {403: {"description": _FOREIGN_ORG_DETAIL}}


@app.get("/admin/compliance/verify/{log_id}", tags=["Compliance"],
         responses={404: {"description": "Audit log entry not found"}})
async def verify_audit_log_entry(
    log_id: int,
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
    session: Session = Depends(get_session)
):
    """
    Cryptographically verify a specific audit log entry (own organization only).
    Checks HMAC signature and hash chain integrity.
    """
    log = session.get(VerificationLog, log_id)
    if log is None or log.organization_id != ctx.organization_id:
        # Do not reveal whether a log in another org exists.
        raise HTTPException(status_code=404, detail="Audit log entry not found")
    from qwed_new.core.audit_logger import AuditLogger
    verifier = AuditLogger()
    return verifier.verify_log_entry(log_id, session)

@app.get(
    "/admin/compliance/report/soc2/{org_id}",
    tags=["Compliance"],
    summary="Security activity summary",
    responses=_FOREIGN_ORG_RESPONSE,
)
async def generate_soc2_report(
    org_id: int,
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
):
    """Security activity summary for the caller's organisation (own organisation only).

    Activity counts and a check of the audit trail over the last 90 days,
    all computed from the server's records (#476). It is not a SOC 2 report;
    the path keeps its old name for compatibility.
    """
    if org_id != ctx.organization_id:
        raise HTTPException(status_code=403, detail=_FOREIGN_ORG_DETAIL)
    # Off the event loop: the audit check verifies every entry in the period,
    # with database queries per entry, so a large trail would stall the worker.
    return await asyncio.to_thread(compliance_exporter.generate_soc2_report, org_id)

@app.get("/admin/security/threats/{org_id}", tags=["Security"], responses=_FOREIGN_ORG_RESPONSE)
async def get_threat_summary(
    org_id: int,
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
):
    """Get real-time threat summary (own organization only)."""
    if org_id != ctx.organization_id:
        raise HTTPException(status_code=403, detail=_FOREIGN_ORG_DETAIL)
    return threat_detector.get_threat_summary(org_id)

@app.post("/admin/keys/rotate", tags=["Security"],
          responses={403: {"description": "Not permitted to rotate this key"},
                     404: {"description": "Key not found"}})
async def rotate_api_key(
    key_id: int,
    ctx: AdminContext = _REQUIRE_MEMBER_OR_SESSION,
    session: Session = Depends(get_session)
):
    """Rotate an API key and return the new secret once.

    Scoped to the caller's own organization, and to a key the caller is allowed
    to rotate: anyone may rotate their own key; otherwise only an admin/owner
    may rotate another user's key, and never a key owned by a higher-privileged
    user — so a member cannot rotate an admin's or owner's key and inherit its
    privileges, and an admin cannot take over an owner's key (Sentry on #450).
    A revoked or inactive key is not rotated (it would mint a fresh live secret
    from a dead credential)."""
    target = session.get(ApiKey, key_id)
    if (target is None or target.organization_id != ctx.organization_id
            or not target.is_active or target.revoked_at is not None):
        # 404, not 403: do not confirm that a key id in another org exists, and
        # treat a revoked/inactive key as absent.
        raise HTTPException(status_code=404, detail="Key not found")

    is_own_key = target.user_id is not None and target.user_id == ctx.user.id
    if not is_own_key:
        if ctx.role not in ("owner", "admin"):
            raise HTTPException(status_code=403, detail="Not permitted to rotate another user's key")
        target_owner = session.get(User, target.user_id) if target.user_id else None
        if target_owner and _ROLE_RANK.get(target_owner.role, 0) > _ROLE_RANK.get(ctx.role, 0):
            raise HTTPException(status_code=403, detail="Cannot rotate a key owned by a higher-privileged user")

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


@app.post(
    "/agents/{agent_id}/token/reissue",
    tags=["Agents"],
    responses={
        403: {"description": "API key not live, or role below member"},
        404: {"description": "No such agent in the caller's organisation"},
    },
)
async def reissue_agent_token(
    agent_id: int,
    ctx: AdminContext = _REQUIRE_ADMIN_OR_MEMBER,
    session: Session = Depends(get_session),
):
    """Give an agent a new token, shown once; the old token stops working (#478).

    Optional: the #478 migration hashes stored tokens in place, so existing
    tokens keep working. Re-issue one whose plaintext may still sit in a
    database backup from before the migration. Members and above, for agents
    in their own organisation only.
    """
    agent = session.get(Agent, agent_id)
    if agent is None or agent.organization_id != ctx.organization_id:
        # 404, not 403: do not confirm that an agent id in another org exists.
        raise HTTPException(status_code=404, detail="Agent not found")
    agent_token = agent_registry.reissue_agent_token(session, agent)
    return {
        "agent_id": agent.id,
        "agent_token": agent_token,  # Show once
        "message": "Agent token re-issued. Store it securely; the previous token no longer works.",
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

from qwed_new.core.batch import batch_service, BatchCapacityError
from qwed_new.api.batch_audit import batch_audit_hook
from typing import List

class BatchVerifyRequest(BaseModel):
    """Request model for batch verification."""
    items: List[dict]  # Each item: {query, type?, params?}
    
class BatchVerifyItem(BaseModel):
    """Single item in batch request."""
    query: str
    type: str = "natural_language"
    params: Optional[dict] = None

@app.post("/verify/batch", tags=["Batch"], responses={503: {"description": "Batch capacity reached"}})
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
    try:
        job = batch_service.create_job(
            organization_id=tenant.organization_id,
            items=request.items
        )
    except BatchCapacityError:
        raise HTTPException(status_code=503, detail="Batch capacity reached — retry shortly.") from None
    
    # Process synchronously (for simplicity)
    # For very large batches, return job_id and process async.
    # Every item appends its audit row; an item whose append fails is
    # returned as failed, without its result (#477).
    job = await batch_service.process_job(job, audit=batch_audit_hook(
        tenant, commit_log=_safe_commit_log, cap_result=_cap_log_result, max_chars=_MAX_LOG_RESULT_CHARS,
    ))
    
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
