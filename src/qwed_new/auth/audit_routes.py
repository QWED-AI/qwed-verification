"""
Audit log routes for QWED Enterprise Portal.
"""
import asyncio
import json
import os

from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Any, Optional
import csv
import io
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, select

from qwed_new.core.database import get_session
from qwed_new.core.audit_logger import SecurityError, get_audit_logger
from qwed_new.core.models import VerificationLog, User
from qwed_new.core.verification_context import Verdict
from .roles import ADMIN_ROLES, READ_ROLES
from .routes import ROLE_REFUSED, require_user_role

router = APIRouter(prefix="/audit", tags=["audit"])

# #478: every role may read its organisation's log; only admins and owners may
# export it in bulk or seed samples. Built once, at import (Ruff B008).
_READER = Depends(require_user_role(READ_ROLES))
_ADMIN = Depends(require_user_role(ADMIN_ROLES))

_VERDICTS = frozenset(v.value for v in Verdict)
# Largest id an SQL BIGINT holds, as for API key ids in routes.py; a larger
# id would overflow the query and fail with a server error instead of a 404.
_MAX_LOG_ID = 2**63 - 1


def _caller(log: VerificationLog) -> dict[str, str | None]:
    """Who wrote the row and with what (#484), as stored; null when not recorded.

    ``api_key_id`` is the ApiKey id as a string, like every other id here.
    It is null on rows written before #484 and on rows no API key made.
    """
    return {
        "api_key_id": None if log.api_key_id is None else str(log.api_key_id),
        "verifier_version": log.verifier_version,
    }


def _org_log(session: Session, log_id: int, organization_id: int) -> VerificationLog | None:
    """The log with this id in this organisation, or None for any other id."""
    if not 1 <= log_id <= _MAX_LOG_ID:
        return None
    log = session.get(VerificationLog, log_id)
    return log if log and log.organization_id == organization_id else None


def stored_verdict(result: str) -> str | None:
    """The verdict the verifier stored in a row's result, or None (#484).

    Reads the three shapes a row can hold: a DiagnosticResult from a
    /verify/* route (``status``), a Verification Context document
    (``verdict``), and a /verify/batch item row (its top-level ``verdict``,
    kept outside the capped details since #494, or ``details.result.status``
    on rows written before that).
    Only VERIFIED, UNVERIFIABLE and BLOCKED count; anything else, including
    a truncated result, is None. Nothing is worked out from ``is_verified``.

    This is the verdict, not an admission. VERIFIED means the check ran to a
    proof, not that the claim holds or may be admitted: a disproven identity
    or code proven unsafe is VERIFIED with a DENY admission (see
    ``AdmissionDecision`` in core/diagnostics.py). Never gate on it alone.
    """
    try:
        value: Any = json.loads(result)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("truncated") is True:
        return None
    if "spec_version" in value:
        candidate = value.get("verdict")
    elif "batch_job_id" in value:
        details = value.get("details")
        inner = details.get("result") if isinstance(details, dict) else None
        candidate = value.get("verdict") or (inner.get("status") if isinstance(inner, dict) else None)
    else:
        candidate = value.get("status")
    return candidate if isinstance(candidate, str) and candidate in _VERDICTS else None

@router.get(
    "/logs",
    responses={**ROLE_REFUSED, 404: {"description": "The before cursor is not a log in the organisation"}},
)
async def get_logs(
    limit: int = Query(50, le=200),
    status: Optional[str] = Query(None),
    before: int | None = Query(None, description="Return logs older than this log id (from next_before)"),
    current_user: User = _READER,
    session: Session = Depends(get_session)
):
    """Get audit logs for the current organization.

    ``verdict`` is the stored verdict (see ``stored_verdict``), or null. It
    is not an admission: a disproven claim is VERIFIED, with a "blocked"
    ``status``. ``status`` is unchanged: "verified" or "blocked" from the
    row's ``is_verified``, which each route sets by its own rule. Neither
    is an admission decision.

    ``admission`` is the admission decision the route made, as stored
    (#307): "ADMIT" or "BLOCKED", or "ADMIT" or "DENY" on
    /verification-context/from-diagnostic (the Verification Context spec's
    terms). It is the one the route returned (/agents/{agent_id}/verify
    returns it too since #320). It is null where the route decides none
    (logic, stats, fact, image, RAG, process, consensus, and batch items
    other than code) and on rows written before it was stored.

    Paging (#484): logs come newest first, by timestamp and then id, so
    the order is stable when two rows share a timestamp. ``next_before`` is
    the last row's id when the page is full; pass it as ``before`` for the
    next page. It is null on a page that is not full. ``total`` is the
    number of rows on this page.

    ``api_key_id`` and ``verifier_version`` say who wrote each row and with
    what server version (see ``_caller``).
    """
    statement = select(VerificationLog).where(
        VerificationLog.organization_id == current_user.organization_id
    ).order_by(VerificationLog.timestamp.desc(), VerificationLog.id.desc()).limit(limit)

    if before is not None:
        cursor = _org_log(session, before, current_user.organization_id)
        if cursor is None:
            raise HTTPException(status_code=404, detail="Log not found")
        statement = statement.where(or_(
            VerificationLog.timestamp < cursor.timestamp,
            and_(VerificationLog.timestamp == cursor.timestamp, VerificationLog.id < cursor.id),
        ))

    if status:
        # Filter by status (verified/blocked/failed)
        if status == "verified":
            statement = statement.where(VerificationLog.is_verified == True)
        elif status == "blocked":
            statement = statement.where(VerificationLog.is_verified == False)
            # Note: "blocked" logic might need refinement based on result content
            # For now, is_verified=False implies failed/blocked
    
    logs = session.exec(statement).all()
    full = bool(logs) and len(logs) == limit

    return {
        "total": len(logs),
        "next_before": str(logs[-1].id) if full else None,
        "logs": [
            {
                "id": str(log.id),
                "request_input": log.query,
                "verification_result": log.result,
                "engine_used": log.domain,
                "verdict": stored_verdict(log.result),
                "status": "verified" if log.is_verified else "blocked",
                "admission": log.admission,
                "latency_ms": 0, # Placeholder, add latency to model if needed
                "created_at": log.timestamp.isoformat(),
                "entry_hash": log.entry_hash,
                **_caller(log),
            }
            for log in logs
        ]
    }

@router.get(
    "/logs/{log_id}",
    responses={**ROLE_REFUSED, 404: {"description": "No such log in the organisation"}},
)
async def get_log_detail(
    log_id: int,
    current_user: User = _READER,
    session: Session = Depends(get_session)
):
    """Get detailed information for a single audit log.

    Adds the row's chain entry: its own hash, the hash it links to, and its
    HMAC signature, as stored. ``verdict``, ``status``, ``admission``,
    ``api_key_id`` and ``verifier_version`` are as on the list; neither of
    the first two is an admission decision.
    """
    log = _org_log(session, log_id, current_user.organization_id)

    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")

    return {
        "id": str(log.id),
        "request_input": log.query,
        "verification_result": log.result,
        "engine_used": log.domain,
        "verdict": stored_verdict(log.result),
        "status": "verified" if log.is_verified else "blocked",
        "admission": log.admission,
        "created_at": log.timestamp.isoformat(),
        "entry_hash": log.entry_hash,
        "previous_hash": log.previous_hash,
        "hmac_signature": log.hmac_signature,
        **_caller(log),
    }

@router.get("/export", responses=ROLE_REFUSED)
async def export_logs(
    current_user: User = _ADMIN,
    session: Session = Depends(get_session)
):
    """Export audit logs as CSV."""
    statement = select(VerificationLog).where(
        VerificationLog.organization_id == current_user.organization_id
    ).order_by(VerificationLog.timestamp.desc()).limit(1000)
    
    logs = session.exec(statement).all()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "Timestamp",
        "Request Input",
        "Verification Result",
        "Engine",
        "Status"
    ])
    
    # Write data
    for log in logs:
        writer.writerow([
            log.timestamp.isoformat(),
            log.query,
            log.result,
            log.domain,
            "verified" if log.is_verified else "blocked"
        ])
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=qwed_audit_logs.csv"}
    )

SEED_ENABLED_ENV_VAR = "QWED_ENABLE_AUDIT_SEED"


@router.post(
    "/seed",
    responses={
        **ROLE_REFUSED,
        404: {"description": "Sample seeding is disabled"},
        500: {"description": "Audit persistence failed"},
    },
)
async def seed_sample_data(
    current_user: User = _ADMIN,
    session: Session = Depends(get_session)
):
    """Seed sample audit logs for testing (development only).

    Disabled unless QWED_ENABLE_AUDIT_SEED is set to 1: a production audit
    trail must hold genuine decisions only, so the route answers 404 by
    default and writes nothing.

    Sample rows go through the signed audit chain like any other row, marked
    ``{"sample": true}`` in their result and timestamped when written. A row
    added outside the chain would become an unverifiable head and stop every
    later append for the organisation.
    """
    if os.getenv(SEED_ENABLED_ENV_VAR, "").strip() != "1":
        raise HTTPException(status_code=404, detail="Not found")

    queries = [
        "Is P=NP?",
        "Verify the Riemann Hypothesis",
        "Check if 1+1=3",
        "Validate secure enclave logic",
        "Analyze quantum coherence state"
    ]
    
    domains = ["MATH", "LOGIC", "PHYSICS"]

    # Sample rows are a fixed, repeatable sequence: no randomness is needed
    # for fixture data, and none reaches a signed audit row.
    def _append_samples() -> None:
        audit_logger = get_audit_logger()
        for i in range(10):
            audit_logger.log_verification(
                organization_id=current_user.organization_id,
                user_id=current_user.id,
                query=queries[i % len(queries)],
                result={"sample": True},
                is_verified=i % 2 == 0,
                domain=domains[i % len(domains)],
            )

    # The appends are blocking database transactions: run them in a worker
    # thread so the event loop keeps serving other requests.
    try:
        await asyncio.to_thread(_append_samples)
    except (SecurityError, SQLAlchemyError):
        raise HTTPException(status_code=500, detail="audit persistence failed") from None
    return {"message": "Sample logs seeded successfully"}
