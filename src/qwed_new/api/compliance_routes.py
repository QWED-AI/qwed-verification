"""Whole-chain audit check (#485) and the audit trail CSV export (#508).

``GET /admin/compliance/verify/{log_id}`` checks one entry. ``verify-trail``
checks every entry of the caller's organisation in a period, so the dashboard
can say whether the chain is intact up to a given entry. ``export/csv``
exports the trail of a period. Kept out of api/main.py, which is at the size
limit of the deterministic security scan.
"""

import asyncio
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from qwed_new.api.admin_auth import AdminContext, require_admin_role
from qwed_new.core.audit_export import as_utc as _as_utc
from qwed_new.core.compliance_exporter import ComplianceExporter

router = APIRouter(prefix="/admin/compliance", tags=["Compliance"])
# Shared with api/main.py, which imports it for the security activity summary.
compliance_exporter = ComplianceExporter()
_FOREIGN_ORG_DETAIL = "Cannot access another organization's data"

# Owners and admins, with an API key or a signed-in session.
_REQUIRE_ADMIN_OR_SESSION = Depends(require_admin_role(["owner", "admin"], allow_session=True))
_START = Query(None, description="Check entries at or after this time (UTC if no zone; other offsets are converted)")
_END = Query(None, description="Check entries at or before this time (UTC if no zone; other offsets are converted)")
_EXPORT_START = Query(None, description="Export entries at or after this time; default 30 days before end")
_EXPORT_END = Query(None, description="Export entries at or before this time; default now")


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

@router.get(
    "/export/csv",
    responses={
        400: {"description": "start is after end"},
        401: {"description": "No API key or bearer token"},
        403: {"description": _FOREIGN_ORG_DETAIL + ", or not an owner or admin, or an inactive user, organisation or key"},
    },
)
async def export_audit_csv(
    organization_id: int,
    start: datetime | None = _EXPORT_START,
    end: datetime | None = _EXPORT_END,
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
) -> Response:
    """Export the audit trail of a period as CSV, newest first (own organisation only).

    Without ``end`` the period ends now; without ``start`` it starts 30 days
    before its end. The columns are those of ``GET /audit/export``
    (``AUDIT_CSV_HEADER`` in core/audit_export.py): the stored verdict and
    admission, the caller, the verifier version and the entry hash, with
    nothing cut (#508).
    """
    if organization_id != ctx.organization_id:
        raise HTTPException(status_code=403, detail=_FOREIGN_ORG_DETAIL)
    start, end = _as_utc(start), _as_utc(end)
    _check_period(start, end)
    # Off the event loop: the export reads every row of the period.
    csv_data = await asyncio.to_thread(compliance_exporter.export_audit_trail_csv, organization_id, start, end)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=qwed_audit_trail.csv"},
    )
