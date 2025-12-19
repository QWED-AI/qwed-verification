"""
QWED SDK Data Models.

Provides typed data classes for SDK responses.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class VerificationType(Enum):
    """Supported verification types."""
    NATURAL_LANGUAGE = "natural_language"
    LOGIC = "logic"
    MATH = "math"
    CODE = "code"
    FACT = "fact"
    SQL = "sql"


@dataclass
class VerificationResult:
    """Result of a single verification request."""
    status: str
    is_verified: bool = False
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    provider_used: Optional[str] = None
    latency_ms: float = 0.0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationResult":
        return cls(
            status=data.get("status", "UNKNOWN"),
            is_verified=data.get("is_verified", data.get("is_valid", False)),
            result=data,
            error=data.get("error"),
            provider_used=data.get("provider_used"),
            latency_ms=data.get("latency_ms", 0.0)
        )


@dataclass
class BatchItem:
    """A single item in a batch result."""
    id: str
    query: str
    type: str
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    latency_ms: float = 0.0


@dataclass
class BatchResult:
    """Result of a batch verification request."""
    job_id: str
    status: str
    progress_percent: float
    total_items: int
    completed_items: int
    failed_items: int
    items: List[BatchItem] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BatchResult":
        items = [
            BatchItem(
                id=item.get("id", ""),
                query=item.get("query", ""),
                type=item.get("type", ""),
                status=item.get("status", ""),
                result=item.get("result"),
                error=item.get("error"),
                latency_ms=item.get("latency_ms", 0.0)
            )
            for item in data.get("items", [])
        ]
        
        return cls(
            job_id=data.get("job_id", ""),
            status=data.get("status", ""),
            progress_percent=data.get("progress_percent", 0.0),
            total_items=data.get("total_items", 0),
            completed_items=data.get("completed_items", 0),
            failed_items=data.get("failed_items", 0),
            items=items
        )
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_items == 0:
            return 0.0
        return ((self.total_items - self.failed_items) / self.total_items) * 100
