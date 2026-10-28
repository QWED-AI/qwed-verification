"""The audit log's stored verdict, and its CSV export (#484, #508).

``GET /audit/logs`` returns each row's stored verdict, admission, caller and
entry hash. The two CSV exports (``GET /admin/compliance/export/csv`` and
``GET /audit/export``) returned none of them, cut the query and the
signature, and labelled ``is_verified`` as if it were a verdict. Both now
write the same columns, built here, so they cannot drift apart again.
"""

import csv
import io
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from qwed_new.core.models import VerificationLog
from qwed_new.core.verification_context import Verdict

_VERDICTS = frozenset(v.value for v in Verdict)

# One header for both exports. "Is Verified (legacy)" is the row's
# is_verified flag, which each route sets by its own rule: it is neither the
# verdict nor the admission. "Chain Status" says only whether the row has a
# hash; the export does not re-check integrity (/admin/compliance/verify and
# /admin/compliance/verify-trail do).
AUDIT_CSV_HEADER = (
    "ID", "Timestamp", "User ID", "API Key ID", "Verifier Version", "Domain",
    "Query", "Verdict", "Admission", "Is Verified (legacy)", "Result",
    "Latency (ms)", "Entry Hash", "HMAC Signature", "Chain Status",
)

# A cell that starts with one of these is read as a formula by spreadsheet
# software (CSV injection), and the query and result are caller-controlled.
# A leading line feed is included too: some importers drop it and then read
# the rest as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")

# At most this many rows per export. A stored result can be up to 64,000
# characters (_MAX_LOG_RESULT_CHARS in api/main.py) and is written in full, so
# an uncapped period could hold the whole trail in memory twice. The routes
# set X-Export-Truncated when more rows matched.
EXPORT_MAX_ROWS = 1000
TRUNCATED_HEADER = "X-Export-Truncated"


def stored_verdict(result: str) -> str | None:
    """The verdict the verifier stored in a row's result, or None (#484).

    Reads the three shapes a row can hold: a DiagnosticResult from a
    /verify/* route (``status``), a Verification Context document
    (``verdict``), and a /verify/batch item row (its top-level ``verdict``,
    kept outside the capped details since #494, or ``details.result.status``
    on rows written before that).
    Only VERIFIED, UNVERIFIABLE and BLOCKED count; anything else, including
    a truncated result, is None. Nothing is worked out from ``is_verified``.

    This is the verdict, not an admission. VERIFIED means the check ran to a
    proof, not that the claim holds or may be admitted: a disproven identity
    or code proven unsafe is VERIFIED with a DENY admission (see
    ``AdmissionDecision`` in core/diagnostics.py). Never gate on it alone.
    """
    try:
        value: Any = json.loads(result)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("truncated") is True:
        return None
    if "spec_version" in value:
        candidate = value.get("verdict")
    elif "batch_job_id" in value:
        details = value.get("details")
        inner = details.get("result") if isinstance(details, dict) else None
        candidate = value.get("verdict") or (inner.get("status") if isinstance(inner, dict) else None)
    else:
        candidate = value.get("status")
    return candidate if isinstance(candidate, str) and candidate in _VERDICTS else None


def as_utc(value: datetime | None) -> datetime | None:
    """A time in UTC, so it compares with stored times: one without a zone is
    read as UTC (stored times are UTC, and SQLite reads them back naive), and
    one with another offset is converted."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def newest_logs(
    session: Session,
    organization_id: int,
    start: datetime | None,
    end: datetime | None,
    max_rows: int = EXPORT_MAX_ROWS,
) -> tuple[list[VerificationLog], bool]:
    """The organisation's rows in the period, newest first by time and then
    id, at most ``max_rows`` of them, and whether more matched. An open side
    (None) of the period is not bounded."""
    statement = select(VerificationLog).where(VerificationLog.organization_id == organization_id)
    if start is not None:
        statement = statement.where(VerificationLog.timestamp >= start)
    if end is not None:
        statement = statement.where(VerificationLog.timestamp <= end)
    statement = statement.order_by(
        VerificationLog.timestamp.desc(), VerificationLog.id.desc()
    ).limit(max_rows + 1)
    logs = list(session.exec(statement).all())
    return logs[:max_rows], len(logs) > max_rows


def _cell(value: object) -> str:
    """An empty cell for a value that was not recorded, and a leading
    apostrophe on text a spreadsheet would run as a formula."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def audit_csv(logs: Iterable[VerificationLog]) -> str:
    """The rows as CSV under ``AUDIT_CSV_HEADER``, in the order given.

    Nothing is cut: the query, the stored result and the signature are
    written in full. The verdict is the stored verdict as on /audit/logs, and
    the admission the one the route stored (#307); both are empty where none
    was recorded.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(AUDIT_CSV_HEADER)
    for log in logs:
        writer.writerow([_cell(value) for value in (
            log.id,
            as_utc(log.timestamp).isoformat(),
            log.user_id,
            log.api_key_id,
            log.verifier_version,
            log.domain,
            log.query,
            stored_verdict(log.result),
            log.admission,
            "Yes" if log.is_verified else "No",
            log.result,
            log.latency_ms,
            log.entry_hash,
            log.hmac_signature,
            "Chained" if log.entry_hash else "Legacy",
        )])
    return output.getvalue()
