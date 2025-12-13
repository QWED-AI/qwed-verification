"""
Audit log database operations.
In-memory store for development.
"""
from datetime import datetime
from typing import List, Optional
import uuid

# In-memory storage
audit_logs_db = {}
logs_by_org = {}

def create_audit_log(
    org_id: str,
    request_input: str,
    verification_result: str,
    engine_used: str,
    status: str,
    latency_ms: float,
    user_id: Optional[str] = None,
    api_key_id: Optional[str] = None,
    llm_response: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> dict:
    """Create a new audit log entry."""
    log_id = str(uuid.uuid4())
    log = {
        "id": log_id,
        "org_id": org_id,
        "user_id": user_id,
        "api_key_id": api_key_id,
        "request_input": request_input,
        "llm_response": llm_response,
        "verification_result": verification_result,
        "engine_used": engine_used,
        "status": status,
        "latency_ms": latency_ms,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "created_at": datetime.utcnow()
    }
    
    audit_logs_db[log_id] = log
    
    # Index by org
    if org_id not in logs_by_org:
        logs_by_org[org_id] = []
    logs_by_org[org_id].append(log)
    
    return log

def get_logs_by_org(org_id: str, limit: int = 50, status_filter: Optional[str] = None) -> List[dict]:
    """Get audit logs for an organization."""
    logs = logs_by_org.get(org_id, [])
    
    # Filter by status if provided
    if status_filter:
        logs = [log for log in logs if log["status"] == status_filter]
    
    # Sort by created_at descending
    logs = sorted(logs, key=lambda x: x["created_at"], reverse=True)
    
    return logs[:limit]

def get_log_by_id(log_id: str) -> Optional[dict]:
    """Get a single audit log by ID."""
    return audit_logs_db.get(log_id)

# Seed some sample logs for testing
def seed_sample_logs(org_id: str):
    """Create sample audit logs for demo purposes."""
    sample_data = [
        {
            "request_input": "What is 2+2?",
            "verification_result": "4",
            "engine_used": "Math Engine",
            "status": "verified",
            "latency_ms": 120.5
        },
        {
            "request_input": "DROP TABLE users;",
            "verification_result": "SQL injection detected",
            "engine_used": "Safety Engine",
            "status": "blocked",
            "latency_ms": 15.2
        },
        {
            "request_input": "Calculate sqrt(16)",
            "verification_result": "4.0",
            "engine_used": "Math Engine",
            "status": "verified",
            "latency_ms": 98.3
        },
        {
            "request_input": "What is the capital of France?",
            "verification_result": "Paris",
            "engine_used": "Fact Engine",
            "status": "verified",
            "latency_ms": 203.7
        },
        {
            "request_input": "exec('import os; os.system(\"rm -rf /\")')",
            "verification_result": "Malicious code execution blocked",
            "engine_used": "Safety Engine",
            "status": "blocked",
            "latency_ms": 8.9
        }
    ]
    
    for data in sample_data:
        create_audit_log(org_id=org_id, **data)
