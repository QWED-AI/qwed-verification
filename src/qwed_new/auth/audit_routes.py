"""
Audit log routes for QWED Enterprise Portal.
"""
import asyncio
import os
from datetime import datetime

from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, select

from qwed_new.core.database import get_session
from qwed_new.core.audit_export import (
    EXPORT_MAX_ROWS,
    TRUNCATED_HEADER,
    as_utc,
    audit_csv,
    newest_logs,
    stored_verdict,
)
from qwed_new.core.audit_logger import SecurityError, get_audit_logger
from qwed_new.core.models import VerificationLog, User
from .roles import ADMIN_ROLES, READ_ROLES
from .routes import ROLE_REFUSED, require_user_role

router = APIRouter(prefix="/audit", tags=["audit"])

# #478: every role may read its organisation's log; only admins and owners may
# export it in bulk or seed samples. Built once, at import (Ruff B008).
_READER = Depends(require_user_role(READ_ROLES))
_ADMIN = Depends(require_user_role(ADMIN_ROLES))

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
    (logic, stats, fact, image, RAG, process, consensus, and batch logic and
    fact items) and on rows written before it was stored.

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

# The export's period (#508). The row cap is EXPORT_MAX_ROWS, shared with
# /admin/compliance/export/csv, and is read at call time so a test can lower it.
_EXPORT_START = Query(None, description="Only entries at or after this time (UTC if no zone; other offsets are converted)")
_EXPORT_END = Query(None, description="Only entries at or before this time (UTC if no zone; other offsets are converted)")
_EXPORT_MAX_ROWS = EXPORT_MAX_ROWS


@router.get(
    "/export",
    responses={**ROLE_REFUSED, 400: {"description": "start is after end"}},
)
async def export_logs(
    start: datetime | None = _EXPORT_START,
    end: datetime | None = _EXPORT_END,
    current_user: User = _ADMIN,
    session: Session = Depends(get_session)
):
    """Export the organisation's audit log as CSV, newest first (#508).

    The columns are those of ``/admin/compliance/export/csv``
    (``AUDIT_CSV_HEADER`` in core/audit_export.py): the stored verdict and
    admission as ``/audit/logs`` returns them, the caller, the verifier
    version and the entry hash, with nothing cut. With ``start`` or ``end``
    only that period is exported; without either, the newest rows.

    At most the newest 1,000 rows: ``X-Export-Truncated`` is "true" when more
    matched, so a period can be narrowed instead of losing rows silently.
    """
    start, end = as_utc(start), as_utc(end)
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=400, detail="start must not be after end")
    logs, truncated = newest_logs(session, current_user.organization_id, start, end, _EXPORT_MAX_ROWS)

    return StreamingResponse(
        iter([audit_csv(logs)]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=qwed_audit_logs.csv",
            TRUNCATED_HEADER: "true" if truncated else "false",
        },
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
