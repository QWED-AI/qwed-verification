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
    STATS = "stats"
    CONSENSUS = "consensus"


class VerificationMode(str, Enum):
    """Verification depth modes for consensus."""
    SINGLE = "single"      # Fast, single engine
    HIGH = "high"          # 2 engines
    MAXIMUM = "maximum"    # 3+ engines


@dataclass
class VerificationResult:
    """Result of a single verification request."""
    status: str
    is_verified: bool = False
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    provider_used: Optional[str] = None
    latency_ms: float = 0.0
    # Set only on a VERIFIED answer that passed the server's trust step: its
    # signed attestation, an ES256 JWT (#319). Check it with
    # QWEDClient.verify_attestation or qwed_sdk.attestation.verify_attestation.
    attestation: Optional[str] = None
    proof_ref: Optional[str] = None
    # The server's admission decision, ADMIT or BLOCKED, where the route
    # makes one; the attestation signs it too (#321). Act on it, not on
    # status alone.
    admission: str | None = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationResult":
        return cls(
            status=data.get("status", "UNKNOWN"),
            is_verified=is_admitted(data),
            result=data,
            error=data.get("error"),
            provider_used=data.get("provider_used"),
            latency_ms=data.get("latency_ms", 0.0),
            **token_fields(data),
        )


def is_admitted(data: Dict[str, Any]) -> bool:
    """Whether a response admits its answer (GHSA-jppc-7r58-7pjh).

    A route that decides an admission returns it, and only ``ADMIT``
    admits. A route that decides none is admitted by the server's own rule
    (``admission_decision``): a ``VERIFIED`` status with ``is_valid`` true.
    A bare ``is_valid`` or ``is_verified`` never admits on its own: the
    server flattens the engine's fields into the response, so a result a
    gate blocked can still carry the engine's ``is_valid: true``.
    """
    admission = data.get("admission")
    if admission is not None:
        return admission == "ADMIT"
    return data.get("status") == "VERIFIED" and data.get("is_valid") is True


def token_fields(data: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """A response's ``attestation``, ``proof_ref`` and ``admission``, each
    a non-empty string or None, for every VerificationResult built from a
    server response (#319, #321): what the attestation binds."""
    fields: Dict[str, Optional[str]] = {}
    for name in ("attestation", "proof_ref", "admission"):
        value = data.get(name)
        fields[name] = value if isinstance(value, str) and value else None
    return fields


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
