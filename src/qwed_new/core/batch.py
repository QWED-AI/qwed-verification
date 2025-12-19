"""
Batch Verification Service for QWED.

Provides concurrent processing of multiple verification requests
with progress tracking and result aggregation.
"""

import asyncio
import time
import uuid
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class BatchStatus(Enum):
    """Status of a batch verification job."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    PARTIAL = "partial"  # Some items failed
    FAILED = "failed"


class VerificationType(Enum):
    """Supported verification types."""
    NATURAL_LANGUAGE = "natural_language"
    LOGIC = "logic"
    MATH = "math"
    CODE = "code"
    FACT = "fact"
    SQL = "sql"


@dataclass
class BatchItem:
    """A single item in a batch verification request."""
    id: str
    query: str
    verification_type: VerificationType = VerificationType.NATURAL_LANGUAGE
    params: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    latency_ms: float = 0.0


@dataclass
class BatchJob:
    """A batch verification job with progress tracking."""
    job_id: str
    organization_id: int
    items: List[BatchItem]
    status: BatchStatus = BatchStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    total_items: int = 0
    completed_items: int = 0
    failed_items: int = 0
    
    def __post_init__(self):
        self.total_items = len(self.items)
    
    @property
    def progress_percent(self) -> float:
        if self.total_items == 0:
            return 0.0
        return (self.completed_items / self.total_items) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "progress_percent": round(self.progress_percent, 1),
            "total_items": self.total_items,
            "completed_items": self.completed_items,
            "failed_items": self.failed_items,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


class BatchVerificationService:
    """
    Service for processing batch verification requests.
    
    Features:
    - Concurrent processing with configurable parallelism
    - Progress tracking
    - Error isolation (one failure doesn't stop others)
    - Job storage for status queries
    """
    
    def __init__(self, max_concurrency: int = 10):
        self.max_concurrency = max_concurrency
        self._jobs: Dict[str, BatchJob] = {}
        self._control_plane = None
    
    @property
    def control_plane(self):
        """Lazy load control plane to avoid circular imports."""
        if self._control_plane is None:
            from qwed_new.core.control_plane import ControlPlane
            self._control_plane = ControlPlane()
        return self._control_plane
    
    def create_job(
        self,
        organization_id: int,
        items: List[Dict[str, Any]]
    ) -> BatchJob:
        """
        Create a new batch verification job.
        
        Args:
            organization_id: Tenant ID
            items: List of verification requests
            
        Returns:
            BatchJob instance
        """
        job_id = str(uuid.uuid4())[:8]
        
        batch_items = []
        for idx, item in enumerate(items):
            batch_items.append(BatchItem(
                id=f"{job_id}-{idx}",
                query=item.get("query", ""),
                verification_type=VerificationType(
                    item.get("type", "natural_language")
                ),
                params=item.get("params", {})
            ))
        
        job = BatchJob(
            job_id=job_id,
            organization_id=organization_id,
            items=batch_items
        )
        
        self._jobs[job_id] = job
        return job
    
    async def process_job(self, job: BatchJob) -> BatchJob:
        """
        Process all items in a batch job concurrently.
        
        Args:
            job: The batch job to process
            
        Returns:
            Updated BatchJob with results
        """
        job.status = BatchStatus.PROCESSING
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrency)
        
        async def process_item(item: BatchItem) -> None:
            async with semaphore:
                start_time = time.time()
                try:
                    result = await self._verify_item(item, job.organization_id)
                    item.result = result
                    item.status = "completed"
                    job.completed_items += 1
                except Exception as e:
                    item.error = str(e)
                    item.status = "failed"
                    job.failed_items += 1
                    job.completed_items += 1
                    logger.warning(f"Batch item {item.id} failed: {e}")
                finally:
                    item.latency_ms = (time.time() - start_time) * 1000
        
        # Process all items concurrently
        await asyncio.gather(*[process_item(item) for item in job.items])
        
        # Update job status
        job.completed_at = datetime.utcnow()
        
        if job.failed_items == 0:
            job.status = BatchStatus.COMPLETED
        elif job.failed_items < job.total_items:
            job.status = BatchStatus.PARTIAL
        else:
            job.status = BatchStatus.FAILED
        
        return job
    
    async def _verify_item(
        self,
        item: BatchItem,
        organization_id: int
    ) -> Dict[str, Any]:
        """
        Execute a single verification based on type.
        
        Args:
            item: The batch item to verify
            organization_id: Tenant ID
            
        Returns:
            Verification result
        """
        if item.verification_type == VerificationType.NATURAL_LANGUAGE:
            return await self.control_plane.process_natural_language(
                item.query,
                organization_id=organization_id
            )
        
        elif item.verification_type == VerificationType.LOGIC:
            return await self.control_plane.process_logic_query(
                item.query,
                organization_id=organization_id
            )
        
        elif item.verification_type == VerificationType.MATH:
            from sympy.parsing.sympy_parser import parse_expr
            from sympy import simplify
            
            expression = item.query
            if "=" in expression:
                left, right = expression.split("=", 1)
                left_expr = parse_expr(left)
                right_expr = parse_expr(right)
                diff = simplify(left_expr - right_expr)
                is_valid = diff == 0
                return {
                    "is_valid": is_valid,
                    "type": "math",
                    "message": "Identity verified" if is_valid else "Not equal"
                }
            else:
                parsed = parse_expr(expression)
                simplified = simplify(parsed)
                return {
                    "is_valid": True,
                    "simplified": str(simplified),
                    "type": "math"
                }
        
        elif item.verification_type == VerificationType.CODE:
            from qwed_new.core.code_verifier import CodeVerifier
            verifier = CodeVerifier()
            return verifier.verify_code(
                item.query,
                language=item.params.get("language", "python")
            )
        
        elif item.verification_type == VerificationType.FACT:
            from qwed_new.core.fact_verifier import FactVerifier
            verifier = FactVerifier()
            return verifier.verify_fact(
                item.query,
                item.params.get("context", "")
            )
        
        elif item.verification_type == VerificationType.SQL:
            from qwed_new.core.sql_verifier import SQLVerifier
            verifier = SQLVerifier()
            return verifier.verify_sql(
                item.query,
                item.params.get("schema_ddl", ""),
                dialect=item.params.get("dialect", "sqlite")
            )
        
        else:
            raise ValueError(f"Unknown verification type: {item.verification_type}")
    
    def get_job(self, job_id: str) -> Optional[BatchJob]:
        """Get a batch job by ID."""
        return self._jobs.get(job_id)
    
    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed results for a batch job.
        
        Returns:
            Dict with job metadata and all item results
        """
        job = self._jobs.get(job_id)
        if not job:
            return None
        
        results = job.to_dict()
        results["items"] = [
            {
                "id": item.id,
                "query": item.query[:100],  # Truncate for readability
                "type": item.verification_type.value,
                "status": item.status,
                "result": item.result,
                "error": item.error,
                "latency_ms": round(item.latency_ms, 1)
            }
            for item in job.items
        ]
        
        return results


# Global singleton
batch_service = BatchVerificationService()
