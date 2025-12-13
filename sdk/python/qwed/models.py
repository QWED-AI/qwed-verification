from pydantic import BaseModel
from typing import Optional, Any, List, Dict

class VerificationResponse(BaseModel):
    """Response from natural language verification."""
    status: str
    final_answer: Optional[Any] = None
    user_query: Optional[str] = None
    translation: Optional[Dict[str, Any]] = None
    verification: Optional[Dict[str, Any]] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None

class LogicResponse(BaseModel):
    """Response from logic verification."""
    status: str
    model: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class FactResponse(BaseModel):
    """Response from fact verification."""
    verdict: str
    reasoning: Optional[str] = None
    citations: Optional[List[str]] = None
