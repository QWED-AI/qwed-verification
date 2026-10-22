"""Audit rows for /verify/batch items (#477).

Each batch item appends one chained, signed VerificationLog row, as the single
/verify/* routes do. Kept out of api/main.py, which is at the size limit of
the deterministic security scan; main passes in its append and cap helpers,
so this module does not import it.
"""

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

from qwed_new.core.batch import BatchItem, BatchJob
from qwed_new.core.diagnostics import AdmissionDecision
from qwed_new.core.models import VerificationLog

# The audit domain for each batch item type, as its single route records it.
BATCH_AUDIT_DOMAIN = {
    "natural_language": "MATH",
    "logic": "LOGIC",
    "math": "MATH",
    "code": "CODE",
    "fact": "FACT",
    "sql": "SQL",
}


def batch_item_is_verified(item: BatchItem) -> bool:
    """is_verified for a batch item's row: what its single route records.

    Each item's result is the DiagnosticResult (merged) its route returns
    (#494), so the routes' own rules apply:
    - logic, fact and sql: VERIFIED with a proof_ref (is_authoritative, as on
      their routes; a proven-malicious query is VERIFIED);
    - math and code: VERIFIED with is_valid True (/verify/math and
      /verify/code record is_valid; code proven unsafe is VERIFIED but not
      valid);
    - natural language: admitted, as /verify/natural_language records it.
    A failed item, or a type not listed, is never verified.
    """
    if item.status != "completed" or not isinstance(item.result, dict):
        return False
    result = item.result
    kind = item.verification_type.value
    fields = result.get("developer_fields") or {}
    if kind in ("logic", "fact", "sql"):
        return result.get("status") == "VERIFIED" and bool(result.get("proof_ref"))
    if kind in ("math", "code"):
        return result.get("status") == "VERIFIED" and fields.get("is_valid") is True
    if kind == "natural_language":
        return result.get("admission") == AdmissionDecision.ADMIT.value
    return False


# Batch item types whose route decides an admission and returns it (#307, #494).
_ADMISSION_TYPES = ("code", "natural_language")


def batch_item_admission(item: BatchItem) -> str | None:
    """The admission a batch item's result carries, or None (#307).

    Code and natural-language items decide one in a batch, as /verify/code
    and /verify/natural_language do (#494); a failed item, or any other type,
    stores None: no admission was decided.
    """
    if item.status != "completed" or item.verification_type.value not in _ADMISSION_TYPES:
        return None
    if not isinstance(item.result, dict):
        return None
    admission = item.result.get("admission")
    return admission if admission in (AdmissionDecision.ADMIT.value, AdmissionDecision.BLOCKED.value) else None


def batch_audit_hook(
    tenant: Any,
    *,
    commit_log: Callable[[VerificationLog], None],
    cap_result: Callable[[Any], str],
    max_chars: int,
) -> Callable[[BatchJob, BatchItem], Awaitable[None]]:
    """The per-item append for BatchVerificationService.process_job.

    The row holds the job and item id, the item type and status, and the
    item's result or error under ``details``. Only ``details`` is capped, so
    the identifiers survive a large result; if they would push the row past
    ``max_chars``, ``details`` is reduced to a truncation marker. A failed
    append raises, and the batch service then fails the item and withholds
    its result.
    """
    async def append(job: BatchJob, item: BatchItem) -> None:
        row = {
            "batch_job_id": job.job_id,
            "batch_item_id": item.id,
            "batch_item_type": item.verification_type.value,
            "item_status": item.status,
            "details": json.loads(cap_result({"result": item.result, "error": item.error})),
        }
        text = json.dumps(row)
        if len(text) > max_chars:
            row["details"] = {"truncated": True}
            text = json.dumps(row)
        log = VerificationLog(
            admission=batch_item_admission(item),
            organization_id=job.organization_id,
            user_id=tenant.user_id if hasattr(tenant, "user_id") else None,
            query=item.query,
            result=text,
            is_verified=batch_item_is_verified(item),
            domain=BATCH_AUDIT_DOMAIN.get(item.verification_type.value, "BATCH"),
        )
        await asyncio.to_thread(commit_log, log)

    return append
