"""
Audit logging models for QWED Enterprise Portal.
Tracks all verification requests for compliance and debugging.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class AuditLog(BaseModel):
    id: str
    org_id: str
    user_id: Optional[str] = None
    api_key_id: Optional[str] = None
    
    # Request details
    request_input: str
    llm_response: Optional[str] = None
    verification_result: str
    engine_used: str
    
    # Metadata
    status: str  # "verified", "blocked", "failed"
    latency_ms: float
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    created_at: datetime

class AuditLogListItem(BaseModel):
    id: str
    request_input: str
    verification_result: str
    engine_used: str
    status: str
    latency_ms: float
    created_at: datetime
