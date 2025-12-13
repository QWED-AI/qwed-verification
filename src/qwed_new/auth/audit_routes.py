"""
Audit log routes for QWED Enterprise Portal.
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional, List
import csv
import io
from datetime import datetime, timedelta
from fastapi.responses import StreamingResponse
from sqlmodel import Session, select

from qwed_new.core.database import get_session
from qwed_new.core.models import VerificationLog, User
from .routes import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("/logs")
async def get_logs(
    limit: int = Query(50, le=200),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
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

@router.get("/logs/{log_id}")
async def get_log_detail(
    log_id: int,
    current_user: User = Depends(get_current_user),
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

@router.get("/export")
async def export_logs(
    current_user: User = Depends(get_current_user),
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

@router.post("/seed")
async def seed_sample_data(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Seed sample audit logs for testing (dev only)."""
    import random
    
    queries = [
        "Is P=NP?",
        "Verify the Riemann Hypothesis",
        "Check if 1+1=3",
        "Validate secure enclave logic",
        "Analyze quantum coherence state"
    ]
    
    for _ in range(10):
        query = random.choice(queries)
        is_verified = random.choice([True, False])
        
        log = VerificationLog(
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            query=query,
            result="Sample result data",
            is_verified=is_verified,
            domain=random.choice(["MATH", "LOGIC", "PHYSICS"]),
            timestamp=datetime.utcnow() - timedelta(minutes=random.randint(1, 1000))
        )
        session.add(log)
    
    session.commit()
    return {"message": "Sample logs seeded successfully"}
