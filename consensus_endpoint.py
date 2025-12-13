# Append to main.py - Consensus Verification Endpoint

# ============================================================
# ENHANCED VERIFICATION ENDPOINTS (Phase 2B)
# ============================================================

from qwed_new.core.consensus_verifier import consensus_verifier, VerificationMode

class ConsensusVerifyRequest(BaseModel):
    query: str
    verification_mode: str = "single"  # "single", "high", "maximum"
    min_confidence: float = 0.95  # 0.0 to 1.0

@app.post("/verify/consensus")
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
    
    # Check if confidence meets requirement
    if result.confidence < request.min_confidence:
        raise HTTPException(
            status_code=422,
            detail=f"Confidence ({result.confidence:.1%}) below required minimum ({request.min_confidence:.1%})"
        )
    
    # Log to database
    log = VerificationLog(
        organization_id=tenant.organization_id,
        query=request.query,
        result=f"Consensus: {result.agreement_status}, Confidence: {result.confidence:.1%}",
        is_verified=(result.confidence >= request.min_confidence),
        domain="CONSENSUS"
    )
    session.add(log)
    session.commit()
    
    # Format response
    return {
        "final_answer": result.final_answer,
        "confidence": round(result.confidence * 100, 2),  # Convert to percentage
        "engines_used": result.engines_used,
        "agreement_status": result.agreement_status,
        "verification_chain": [
            {
                "engine": r.engine_name,
                "method": r.method,
                "result": str(r.result),
                "confidence": round(r.confidence * 100, 2),
                "latency_ms": round(r.latency_ms, 2),
                "success": r.success
            }
            for r in result.verification_chain
        ],
        "total_latency_ms": round(result.total_latency_ms, 2),
        "meets_requirement": result.confidence >= request.min_confidence
    }
