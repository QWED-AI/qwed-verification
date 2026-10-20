"""
Audit log routes for QWED Enterprise Portal.
"""
import asyncio
import os

from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
import csv
import io
from fastapi.responses import StreamingResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, select

from qwed_new.core.database import get_session
from qwed_new.core.audit_logger import SecurityError, get_audit_logger
from qwed_new.core.models import VerificationLog, User
from .roles import ADMIN_ROLES, READ_ROLES
from .routes import ROLE_REFUSED, require_user_role

router = APIRouter(prefix="/audit", tags=["audit"])

# #478: every role may read its organisation's log; only admins and owners may
# export it in bulk or seed samples. Built once, at import (Ruff B008).
_READER = Depends(require_user_role(READ_ROLES))
_ADMIN = Depends(require_user_role(ADMIN_ROLES))

@router.get("/logs", responses=ROLE_REFUSED)
async def get_logs(
    limit: int = Query(50, le=200),
    status: Optional[str] = Query(None),
    current_user: User = _READER,
    session: Session = Depends(get_session)
):
    """Get audit logs for the current organization."""
    statement = select(VerificationLog).where(
        VerificationLog.organization_id == current_user.organization_id
    ).order_by(VerificationLog.timestamp.desc()).limit(limit)
    
    if status:
        # Filter by status (verified/blocked/failed)
        if status == "verified":
            statement = statement.where(VerificationLog.is_verified == True)
        elif status == "blocked":
            statement = statement.where(VerificationLog.is_verified == False)
            # Note: "blocked" logic might need refinement based on result content
            # For now, is_verified=False implies failed/blocked
    
    logs = session.exec(statement).all()
    
    return {
        "total": len(logs),
        "logs": [
            {
                "id": str(log.id),
                "request_input": log.query,
                "verification_result": log.result,
                "engine_used": log.domain,
                "status": "verified" if log.is_verified else "blocked",
                "latency_ms": 0, # Placeholder, add latency to model if needed
                "created_at": log.timestamp.isoformat()
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
    """Get detailed information for a single audit log."""
    log = session.get(VerificationLog, log_id)
    
    if not log or log.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Log not found")
    
    return {
        "id": str(log.id),
        "request_input": log.query,
        "verification_result": log.result,
        "engine_used": log.domain,
        "status": "verified" if log.is_verified else "blocked",
        "created_at": log.timestamp.isoformat()
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
