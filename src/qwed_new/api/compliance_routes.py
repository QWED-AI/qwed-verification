"""Whole-chain audit check for the compliance routes (#485).

``GET /admin/compliance/verify/{log_id}`` checks one entry. This route checks
every entry of the caller's organisation in a period, so the dashboard can
say whether the chain is intact up to a given entry. Kept out of api/main.py,
which is at the size limit of the deterministic security scan.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from qwed_new.api.admin_auth import AdminContext, require_admin_role
from qwed_new.core.compliance_exporter import ComplianceExporter

router = APIRouter(prefix="/admin/compliance", tags=["Compliance"])

# Owners and admins, with an API key or a signed-in session.
_REQUIRE_ADMIN_OR_SESSION = Depends(require_admin_role(["owner", "admin"], allow_session=True))
_START = Query(None, description="Check entries at or after this time (UTC if no zone; other offsets are converted)")
_END = Query(None, description="Check entries at or before this time (UTC if no zone; other offsets are converted)")


def _as_utc(value: datetime | None) -> datetime | None:
    """A time in UTC, so it compares with stored times: one without a zone is
    read as UTC, and one with another offset is converted (SQLite drops the
    offset when it compares)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _check_period(start: datetime | None, end: datetime | None) -> None:
    """Refuse a period whose start is after its end. An open side (None)
    cannot be out of order, so it is accepted explicitly."""
    if start is None or end is None:
        return
    if start > end:
        raise HTTPException(status_code=400, detail="start must not be after end")


@router.get(
    "/verify-trail",
    responses={
        400: {"description": "start is after end"},
        401: {"description": "No API key or bearer token"},
        403: {"description": "Not an owner or admin, or an inactive user, organisation or key"},
    },
)
async def verify_audit_trail(
    start: datetime | None = _START,
    end: datetime | None = _END,
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
) -> dict[str, Any]:
    """Check the signature and hash chain of every audit entry in the period.

    Own organisation only. Without ``start`` or ``end`` that side of the
    period is open, so with neither the whole chain is checked. ``status`` is
    VERIFIED (with a ``proof_ref`` over the range checked) only when there
    are entries and all of them check out; NO_ENTRIES when there are none;
    NOT_VERIFIED otherwise, with ``first_failed_entry_id`` and the counts.
    It covers the entries that were recorded; it does not show that every
    request wrote one.
    """
    start, end = _as_utc(start), _as_utc(end)
    _check_period(start, end)
    # Off the event loop: the check queries the database for every entry.
    result = await asyncio.to_thread(ComplianceExporter.audit_trail_check, ctx.organization_id, start, end)
    return {
        "organization_id": ctx.organization_id,
        "start": start.isoformat() if start else None,
        "end": end.isoformat() if end else None,
        **result,
    }
