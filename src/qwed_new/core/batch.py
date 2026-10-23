"""
Batch Verification Service for QWED.

Provides concurrent processing of multiple verification requests
with progress tracking and result aggregation.
"""

import asyncio
import os
import time
import uuid
import logging
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from qwed_new.core.diagnostics import DiagnosticResult, admission_decision, merge_diagnostic_result
from qwed_new.core.route_diagnostics import logic_diagnostic, natural_language_diagnostic
from qwed_new.core.trust import attest_and_enforce

logger = logging.getLogger(__name__)


class BatchCapacityError(RuntimeError):
    """Raised when the job store is full of still-running jobs (#391)."""


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
    
    # Cap the in-process job store so completed jobs cannot grow the worker's
    # heap without bound (#391). Oldest jobs are evicted first; their status
    # queries 404 after eviction, as they would after a restart.
    _MAX_JOBS = int(os.environ.get("QWED_BATCH_MAX_JOBS", "1000"))
    # Wall-clock bound per item, so a stalled verification is marked failed
    # rather than keeping the job active forever (#447 review).
    _ITEM_TIMEOUT_SECONDS = float(os.environ.get("QWED_BATCH_ITEM_TIMEOUT", "60"))

    def __init__(self, max_concurrency: int = 10):
        self.max_concurrency = max_concurrency
        self._jobs: "OrderedDict[str, BatchJob]" = OrderedDict()
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
        
        # Keep the store bounded, but never evict a job that is still running
        # (its result would vanish mid-flight). Evict the oldest finished job;
        # if the store is full of active jobs, reject the new one (#391 review).
        active = (BatchStatus.PENDING, BatchStatus.PROCESSING)
        while len(self._jobs) >= self._MAX_JOBS:
            evictable = next(
                (jid for jid, candidate in self._jobs.items() if candidate.status not in active),
                None,
            )
            if evictable is None:
                raise BatchCapacityError("Batch job capacity is full; retry shortly.")
            del self._jobs[evictable]

        self._jobs[job_id] = job
        return job
    
    async def process_job(
        self,
        job: BatchJob,
        audit: Callable[[BatchJob, BatchItem], Awaitable[None]] | None = None,
    ) -> BatchJob:
        """
        Process all items in a batch job concurrently.

        Args:
            job: The batch job to process
            audit: Appends one audit row per item, after the item is verified
                or has failed (#477). If it raises, the item is failed and its
                result withheld, so no result is returned without its row.

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
                    # Bound each item so a stalled verification cannot keep the
                    # job active forever; the timeout is caught below and the
                    # item is marked failed (#447 review).
                    result = await asyncio.wait_for(
                        self._verify_item(item, job.organization_id),
                        timeout=self._ITEM_TIMEOUT_SECONDS,
                    )
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
                if audit is not None:
                    await self._audit_item(job, item, audit)
        
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
    
    @staticmethod
    async def _audit_item(
        job: BatchJob,
        item: BatchItem,
        audit: Callable[[BatchJob, BatchItem], Awaitable[None]],
    ) -> None:
        """Append the item's audit row; fail the item if that fails (#477)."""
        try:
            await audit(job, item)
        except Exception as exc:  # any failure fails the item
            logger.exception("Batch item %s audit append failed: %s", item.id, type(exc).__name__)
            if item.status == "completed":
                job.failed_items += 1
            item.status = "failed"
            item.result = None
            item.error = "audit persistence failed"

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
        # Logic and natural-language items get the DiagnosticResult their
        # routes return, built by the same helpers, not the control plane's
        # raw dict (#494). Every item type takes its route's trust step: a
        # VERIFIED result is signed and its attestation enforced (#320).
        if item.verification_type == VerificationType.NATURAL_LANGUAGE:
            from qwed_new.core.control_plane import natural_language_admission

            result = await self.control_plane.process_natural_language(
                item.query,
                organization_id=organization_id
            )
            dr = attest_and_enforce(
                natural_language_diagnostic(result), engine="natural_language", query=item.query
            )
            # As /verify/natural_language: the verdict covers the translated
            # expression, so admission is decided by its own rule.
            return merge_diagnostic_result(dr) | {"admission": natural_language_admission(dr).value}

        elif item.verification_type == VerificationType.LOGIC:
            result = await self.control_plane.process_logic_query(
                item.query,
                organization_id=organization_id
            )
            dr = attest_and_enforce(logic_diagnostic(result), engine="logic", query=item.query)
            return merge_diagnostic_result(dr)
        
        elif item.verification_type == VerificationType.MATH:
            # sympy is CPU-bound; run it in a worker thread so a batch does not
            # block the event loop per item (#391).
            return await asyncio.to_thread(self._verify_batch_math, item)

        elif item.verification_type == VerificationType.CODE:
            from qwed_new.core.code_verifier import CodeVerifier

            def _verify_code() -> Dict[str, Any]:
                verifier = CodeVerifier()
                result = verifier.verify_code(
                    item.query,
                    language=item.params.get("language", "python")
                )
                dr = attest_and_enforce(result, engine="code", query=item.query)
                serialized = dr.to_dict()
                # Gate on admission like /verify/code: VERIFIED-as-unsafe code
                # must never be admitted by authority-only consumers (#254).
                serialized["admission"] = admission_decision(dr).value
                return serialized

            return await asyncio.to_thread(_verify_code)

        elif item.verification_type == VerificationType.FACT:
            from qwed_new.core.fact_verifier import FactVerifier

            def _verify_fact() -> Dict[str, Any]:
                verifier = FactVerifier()
                result = verifier.verify_fact(
                    item.query,
                    item.params.get("context", "")
                )
                return attest_and_enforce(result, engine="fact", query=item.query).to_dict()

            return await asyncio.to_thread(_verify_fact)

        elif item.verification_type == VerificationType.SQL:
            from qwed_new.core.sql_verifier import SQLVerifier

            def _verify_sql() -> Dict[str, Any]:
                verifier = SQLVerifier()
                result = verifier.verify_sql(
                    item.query,
                    item.params.get("schema_ddl", ""),
                    dialect=item.params.get("dialect", "sqlite")
                )
                dr = attest_and_enforce(result, engine="sql", query=item.query)
                serialized = dr.to_dict()
                # As /verify/sql: a proven-malicious query is VERIFIED but
                # must not be admitted (#307).
                serialized["admission"] = admission_decision(dr).value
                return serialized

            return await asyncio.to_thread(_verify_sql)
        
        else:
            raise ValueError(f"Unknown verification type: {item.verification_type}")

    def _verify_batch_math(self, item: BatchItem) -> Dict[str, Any]:
        """Verify a MATH batch item through the DiagnosticResult + attestation trust boundary (#271)."""
        from qwed_new.core.safe_parser import safe_parse_expr
        from sympy import simplify

        expression = item.query.strip()
        if "=" not in expression:
            parsed = safe_parse_expr(expression)
            simplified = simplify(parsed)
            dr = DiagnosticResult.unverifiable(
                "Expression simplified, but no equality or proof claim was provided",
                developer_fields={"simplified": str(simplified), "type": "math", "is_valid": False, "query": expression},
            )
        else:
            left, right = expression.split("=", 1)
            left_expr = safe_parse_expr(left)
            right_expr = safe_parse_expr(right)
            diff = simplify(left_expr - right_expr)
            if diff != 0:
                dr = DiagnosticResult.unverifiable(
                    f"Not equal: {left_expr} != {right_expr}",
                    developer_fields={"query": expression, "type": "math", "is_valid": False, "diff": str(diff)},
                )
            else:
                evidence = {"left": left.strip(), "right": right.strip(), "diff": str(diff)}
                dr = DiagnosticResult.verified(
                    "Identity verified",
                    developer_fields={"query": expression, "type": "math", "is_valid": True, "diff": str(diff)},
                    evidence=evidence,
                    proof_data=str(evidence),
                )

        # As /verify/math: a VERIFIED identity is signed and its attestation
        # enforced, and is BLOCKED if signing fails (#271, #320). Admission is
        # decided apart from the verdict, as there (#307).
        dr = attest_and_enforce(dr, engine="math", query=item.query)
        return merge_diagnostic_result(dr) | {"admission": admission_decision(dr).value}

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
