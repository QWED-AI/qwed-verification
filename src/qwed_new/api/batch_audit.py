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
from qwed_new.core.control_plane import natural_language_admission
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    enforce_trust_decision,
)
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
    """is_verified for a batch item's row: never more than its single route records.

    - logic: SAT, which /verify/logic turns into VERIFIED with a proof_ref;
    - math and code: VERIFIED with is_valid True (/verify/math and
      /verify/code record is_valid; code proven unsafe is VERIFIED but not
      valid);
    - fact and sql: VERIFIED with a proof_ref (is_authoritative, as on their
      routes; a proven-malicious query is VERIFIED);
    - natural language: admitted by the same rule as /verify/natural_language.
    A failed item, or a type not listed, is never verified.
    """
    if item.status != "completed" or not isinstance(item.result, dict):
        return False
    result = item.result
    kind = item.verification_type.value
    fields = result.get("developer_fields") or {}
    if kind == "logic":
        return result.get("status") == "SAT"
    if kind in ("math", "code"):
        return result.get("status") == "VERIFIED" and fields.get("is_valid") is True
    if kind in ("fact", "sql"):
        return result.get("status") == "VERIFIED" and bool(result.get("proof_ref"))
    if kind == "natural_language":
        return _natural_language_admitted(result, item.query)
    return False


def _natural_language_admitted(result: dict[str, Any], query: str) -> bool:
    """The /verify/natural_language rule: the control plane's diagnostic, trust
    enforcement, then natural_language_admission. Without a diagnostic the route
    falls back to a legacy mapping that can never yield VERIFIED."""
    diagnostic = result.get("diagnostic")
    if not isinstance(diagnostic, dict):
        return False
    try:
        dr = DiagnosticResult.from_dict(diagnostic)
    except (TypeError, ValueError, KeyError, AttributeError):
        return False
    dr = enforce_trust_decision(dr, require_attestation=False, query=query)
    return natural_language_admission(dr) is AdmissionDecision.ADMIT


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
            organization_id=job.organization_id,
            user_id=tenant.user_id if hasattr(tenant, "user_id") else None,
            query=item.query,
            result=text,
            is_verified=batch_item_is_verified(item),
            domain=BATCH_AUDIT_DOMAIN.get(item.verification_type.value, "BATCH"),
        )
        await asyncio.to_thread(commit_log, log)

    return append
