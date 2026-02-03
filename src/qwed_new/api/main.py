from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from sqlmodel import Session
import os
import logging

from qwed_new.core.security import redact_pii

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from qwed_new.core.control_plane import ControlPlane
from qwed_new.core.tenant_context import get_current_tenant, TenantContext
from qwed_new.core.database import create_db_and_tables, get_session
from qwed_new.core.models import VerificationLog, User, Organization, ApiKey
from qwed_new.core.rate_limiter import check_rate_limit

# Import auth router
# Import auth router
from qwed_new.auth import auth_router
from qwed_new.auth.audit_routes import router as audit_router
from qwed_new.auth.middleware import get_api_key

app = FastAPI(
    title="QWED API",
    description="The Deterministic Verification Protocol for AI",
    version="2.0.0"
)

# CORS - configurable via environment variable
# Default allows all origins for development, restrict in production
CORS_ORIGINS = os.environ.get("QWED_CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(audit_router)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# Initialize Kernel (Control Plane)
control_plane = ControlPlane()

class VerifyRequest(BaseModel):
    query: str
    provider: Optional[str] = None

@app.get("/")
async def root():
    return {"message": "QWED OS is Running", "version": "1.0.0"}

@app.post("/verify/natural_language")
async def verify_natural_language(
    request: VerifyRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Main entry point: Verifies a natural language math query.
    Now routed through the QWED Control Plane with multi-tenancy.
    
    Rate Limits:
    - Per API Key: 100 requests/minute
    - Global: 1000 requests/minute
    """
    # Check rate limits
    check_rate_limit(tenant.api_key)
    
    result = await control_plane.process_natural_language(
        request.query,
        organization_id=tenant.organization_id,
        preferred_provider=request.provider
    )
    
    # Log request to audit trail
    log = VerificationLog(
        organization_id=tenant.organization_id,
        user_id=tenant.user_id if hasattr(tenant, 'user_id') else None,
        query=request.query,
        result=str(result),
        is_verified=result.get("status") == "VERIFIED",
        domain="MATH"
    )
    session.add(log)
    session.commit()
        
    return result

@app.post("/verify/logic")
async def verify_logic(
    request: VerifyRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Verifies a logic puzzle.
    Now routed through the QWED Control Plane.
    
    Rate Limits:
    - Per API Key: 100 requests/minute
    - Global: 1000 requests/minute
    """
    # Check rate limits
    check_rate_limit(tenant.api_key)
    result = await control_plane.process_logic_query(
        request.query,
        organization_id=tenant.organization_id,
        preferred_provider=request.provider
    )
    
    if result["status"] == "BLOCKED":
        raise HTTPException(status_code=403, detail=result["error"])
    
    # Log to database
    log = VerificationLog(
        organization_id=tenant.organization_id,
        query=request.query,
        result=str(result),
        is_verified=(result["status"] == "SAT" or result["status"] == "UNSAT"),
        domain="LOGIC"
    )
    session.add(log)
    session.commit()
        
    return result

@app.post("/verify/stats")
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
        
        result = verifier.verify_stats(query, df, provider=None)
        
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=str(result),
            is_verified=(result["status"] == "SUCCESS"),
            domain="STATS"
        )
        session.add(log)
        session.commit()
        
        return result
        
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e)
        }


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
    
    try:
        from qwed_new.core.fact_verifier import FactVerifier
        verifier = FactVerifier()
        
        claim = request.get("claim")
        context = request.get("context")
        provider = request.get("provider")
        
        if not claim or not context:
            raise HTTPException(status_code=400, detail="Missing 'claim' or 'context'")
        
        result = verifier.verify_fact(claim, context, provider=provider)
        
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=claim,
            result=str(result),
            is_verified=(result.get("verdict") == "SUPPORTED"),
            domain="FACT"
        )
        session.add(log)
        session.commit()
        
        return result
        
    except Exception as e:
    except Exception as e:
        logger.error(f"Fact verification error: {redact_pii(str(e))}", exc_info=True)
        return {
            "status": "ERROR",
            "error": "Internal verification error",
            "verdict": "ERROR"
        }


@app.post("/verify/code")
async def verify_code(
    request: dict,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Verify code for security vulnerabilities using AST analysis.
    
    Request body:
    {
        "code": "import os\\nos.system('ls')",
        "language": "python" (optional, default: python)
    }
    """
    check_rate_limit(tenant.api_key)
    
    try:
        from qwed_new.core.code_verifier import CodeVerifier
        verifier = CodeVerifier()
        
        code = request.get("code")
        language = request.get("language", "python")
        
        if not code:
            raise HTTPException(status_code=400, detail="Missing 'code'")
        
        result = verifier.verify_code(code, language=language)
        
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=code[:200],  # Truncate for logging
            result=str(result),
            is_verified=result.get("is_safe", False),
            domain="CODE"
        )
        session.add(log)
        session.commit()
        
        return result
        
    except Exception as e:
    except Exception as e:
        logger.error(f"Code verification error: {redact_pii(str(e))}", exc_info=True)
        return {
            "status": "ERROR",
            "error": "Internal verification error",
            "is_safe": False
        }


@app.post("/verify/math")
async def verify_math(
    request: dict,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Verify mathematical expression or equation.
    
    Request body:
    {
        "expression": "2+2=4" or "x**2 - y**2 = (x-y)*(x+y)",
        "context": {"domain": "real"} (optional)
    }
    """
    check_rate_limit(tenant.api_key)
    
    try:
        import sympy
        from sympy.parsing.sympy_parser import parse_expr
        from sympy import simplify, symbols, Eq, solve
        
        expression = request.get("expression")
        context_data = request.get("context", {})
        
        if not expression:
            raise HTTPException(status_code=400, detail="Missing 'expression'")
        
        # Check if it's an equation (contains =) or just an expression
        if "=" in expression:
            # It's an equation - verify if it's true/false
            left_str, right_str = expression.split("=", 1)
            
            # Parse both sides
            left = parse_expr(left_str)
            right = parse_expr(right_str)
            
            # Simplify and check equivalence
            difference = simplify(left - right)
            is_valid = difference == 0
            
            result = {
                "is_valid": is_valid,
                "result": is_valid,
                "left_side": str(left),
                "right_side": str(right),
                "simplified_difference": str(difference),
                "message": "Identity is true" if is_valid else "Identity is false"
            }
        else:
            # Just an expression - evaluate or simplify
            try:
                # Convert implicit multiplication to explicit (e.g., 2(x+1) -> 2*(x+1))
                import re
                expression_normalized = re.sub(r'(\d)(\()', r'\1*\2', expression)
                
                # Check for ambiguous expressions BEFORE parsing
                is_ambiguous = False
                if "/" in expression and "(" in expression:
                    # Match patterns like /2(, /10(, etc. (division followed by number then parenthesis)
                    if re.search(r'/\d+\(', expression.replace(" ", "")):
                        is_ambiguous = True
                
                parsed = parse_expr(expression_normalized)
                
                # Check for division by zero before simplifying
                if "/0" in expression.replace(" ", "") or "/ 0" in expression:
                    result = {
                        "is_valid": False,
                        "error": "Division by zero",
                        "message": "Expression contains division by zero"
                    }
                    
                # Check for log(0) or log(negative)
                elif "log(0)" in expression.replace(" ", ""):
                    result = {
                        "is_valid": False,
                        "error": "undefined",
                        "message": "log(0) is undefined"
                    }
                    
                # Check for sqrt of negative in real domain
                elif "sqrt(-" in expression.replace(" ", ""):
                    if context_data.get("domain") == "real":
                        result = {
                            "is_valid": False,
                            "error": "domain error",
                            "message": "Square root of negative number is undefined in real domain"
                        }
                    else:
                        simplified = simplify(parsed)
                        result = {
                            "is_valid": True,
                            "simplified": str(simplified),
                            "original": str(parsed),
                            "is_complex": True
                        }
                        
                # Check for ambiguous expressions (BEFORE simplification)
                elif is_ambiguous:
                    simplified = simplify(parsed)
                    result = {
                        "is_valid": True,
                        "warning": "ambiguous",
                        "message": "Expression may be ambiguous due to implicit multiplication after division",
                        "simplified": str(simplified),
                        "note": "Interpreted using standard order of operations",
                        "original": str(parsed)
                    }
                    
                # Normal expression - evaluate or simplify
                else:
                    simplified = simplify(parsed)
                    
                    # Try to evaluate if it's numeric
                    try:
                        value = float(simplified)
                        result = {
                            "is_valid": True,
                            "value": value,
                            "simplified": str(simplified),
                            "original": str(parsed)
                        }
                    except:
                        # Symbolic expression
                        result = {
                            "is_valid": True,
                            "simplified": str(simplified),
                            "original": str(parsed),
                            "is_symbolic": True
                        }
            except ZeroDivisionError:
                result = {
                    "is_valid": False,
                    "error": "Division by zero",
                    "message": "Expression contains division by zero"
                }
            except Exception as e:
                if "log" in str(e).lower() or "sqrt" in str(e).lower():
                    result = {
                        "is_valid": False,
                        "error": "Domain error",
                        "message": str(e)
                    }
                else:
                    raise
        
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=expression,
            result=str(result),
            is_verified=result.get("is_valid", False),
            domain="MATH"
        )
        session.add(log)
        session.commit()
        
        return result
        
    except Exception as e:
    except Exception as e:
        logger.error(f"Math verification error: {redact_pii(str(e))}", exc_info=True)
        return {
            "status": "ERROR",
            "error": "Internal verification error",
            "is_valid": False
        }


@app.post("/verify/sql")
async def verify_sql(
    request: dict,
    tenant: TenantContext = Depends(get_current_tenant),
    session: Session = Depends(get_session)
):
    """
    Verify SQL query against a provided schema.
    
    Request body:
    {
        "query": "SELECT * FROM users",
        "schema_ddl": "CREATE TABLE users (id INT, name TEXT)",
        "dialect": "sqlite" (optional, default: sqlite)
    }
    """
    check_rate_limit(tenant.api_key)
    
    try:
        from qwed_new.core.sql_verifier import SQLVerifier
        verifier = SQLVerifier()
        
        query = request.get("query")
        schema_ddl = request.get("schema_ddl")
        dialect = request.get("dialect", "sqlite")
        
        if not query or not schema_ddl:
            raise HTTPException(status_code=400, detail="Missing 'query' or 'schema_ddl'")
        
        result = verifier.verify_sql(query, schema_ddl, dialect=dialect)
        
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=query,
            result=str(result),
            is_verified=result.get("is_valid", False),
            domain="SQL"
        )
        session.add(log)
        session.commit()
        
        return result
        
    except Exception as e:
    except Exception as e:
        logger.error(f"SQL verification error: {redact_pii(str(e))}", exc_info=True)
        return {
            "status": "ERROR",
            "error": "Internal verification error",
            "is_valid": False
        }


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
        
        # Log the verification
        log = VerificationLog(
            organization_id=tenant.organization_id,
            query=f"Image claim: {claim}",
            result=str(result),
            is_verified=result.get("verdict") == "SUPPORTED",
            domain="IMAGE"
        )
        session.add(log)
        session.commit()
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        return {
            "status": "ERROR",
            "error": "Internal processing error",
            "verdict": "INCONCLUSIVE",
            "confidence": 0.0
        }


# ============================================================
# OBSERVABILITY ENDPOINTS
# ============================================================

from qwed_new.core.observability import metrics_collector
from datetime import datetime
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
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/metrics")
async def get_global_metrics():
    """
    Get system-wide metrics.
    
    Note: In production, this should require admin authentication.
    """
    global_metrics = metrics_collector.get_global_metrics()
    all_tenant_metrics = metrics_collector.get_all_tenant_metrics()
    
    return {
        "global": global_metrics,
        "tenants": all_tenant_metrics
    }

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
    
    logs = session.exec(statement).all()
    
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

class ToolCallRequest(BaseModel):
    tool_params: dict

@app.post("/agents/register")
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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/agents/{agent_id}/verify")
async def agent_verify(
    agent_id: int,
    request: AgentVerifyRequest,
    x_agent_token: str = Header(...),
    session: Session = Depends(get_session)
):
    """
    Agent makes a verification request through QWED.
    Includes full audit trail.
    """
    import time
    start_time = time.time()
    
    # 1. Authenticate agent
    agent = agent_registry.authenticate_agent(session, x_agent_token)
    if not agent or agent.id != agent_id:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    
    # 2. Check budget
    budget_ok, budget_reason = agent_registry.check_budget(session, agent_id)
    if not budget_ok:
        agent_registry.log_activity(
            session, agent_id, agent.organization_id,
            "verification_request", "Budget exceeded", "blocked",
            input_data=request.query
        )
        raise HTTPException(status_code=403, detail=budget_reason)
    
    # 3. Process via control plane
    try:
        result = await control_plane.process_natural_language(
            request.query,
            organization_id=agent.organization_id,
            preferred_provider=request.provider
        )
    except Exception as e:
    except Exception as e:
        logger.error(f"Agent verification failed: {redact_pii(str(e))}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal agent verification error")
    
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
        logger.error(f"Tool execution failed: {redact_pii(str(error))}")
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
    
    activities = session.exec(statement).all()
    
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
# --- Enterprise Security Endpoints (Week 2) ---

from qwed_new.core.compliance_exporter import ComplianceExporter
from qwed_new.core.threat_detector import threat_detector
from qwed_new.core.key_rotation import key_manager
from qwed_new.core.rbac import require_role, RBACMiddleware

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

from qwed_new.core.batch import batch_service, VerificationType
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

from qwed_new.core.observability import get_prometheus_metrics, get_prometheus_content_type

@app.get("/metrics/prometheus", tags=["Observability"])
async def prometheus_metrics():
    """
    Prometheus-compatible metrics endpoint.
    
    Returns metrics in Prometheus text format for scraping.
    """
    content = get_prometheus_metrics()
    return Response(
        content=content,
        media_type=get_prometheus_content_type()
    )
