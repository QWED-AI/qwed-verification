"""Read endpoint for the organisation's security events (#486).

``SecurityEvent`` rows were written (a leaked key revoked, for example) but
only ``GET /admin/security/threats/{org_id}`` read them, as a summary. This
route lists the events themselves for the dashboard. Kept out of
api/main.py, which is at the size limit of the deterministic security scan.
"""

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_
from sqlmodel import Session, select

from qwed_new.api.admin_auth import AdminContext, require_admin_role
from qwed_new.core.database import get_session
from qwed_new.core.models import SecurityEvent

router = APIRouter(prefix="/admin/security", tags=["Security"])

# Owners and admins, with an API key or a signed-in session.
_REQUIRE_ADMIN_OR_SESSION = Depends(require_admin_role(["owner", "admin"], allow_session=True))
_SESSION = Depends(get_session)
_LIMIT = Query(50, ge=1, le=200)
_BEFORE = Query(None, description="Return events older than this event id (from next_before)")
_EVENT_TYPE = Query(None, description="Only events of this type, for example SECRET_LEAK_AUTO_REVOKED")

# Anything shaped like a credential is masked before it leaves the server: an
# API key (qwed_live_/qwed_test_ and its body) or an agent token. Writers
# store a preview only; this keeps a token out of the response even if a
# future writer does not. No word boundary before them: a credential right
# after "_" or a digit is masked too.
_CREDENTIAL = re.compile(r"qwed_(?:live|test)_[A-Za-z0-9_-]{8,}|agent_[0-9a-f]{32,}")
# Largest id an SQL BIGINT holds, as on /audit/logs; a larger cursor would
# overflow the query and fail with a server error instead of a 404.
_MAX_EVENT_ID = 2**63 - 1


def _mask(text: str | None) -> str | None:
    return _CREDENTIAL.sub("[redacted credential]", text) if text else text


def _event(event: SecurityEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "severity": event.severity,
        "security_layer": event.security_layer,
        "reason": _mask(event.reason),
        "query": _mask(event.query),
        "user_id": event.user_id,
    }


@router.get(
    "/events",
    responses={
        401: {"description": "No API key or bearer token"},
        403: {"description": "Not an owner or admin, or an inactive user, organisation or key"},
        404: {"description": "The before cursor is not an event in the organisation"},
    },
)
def list_security_events(
    limit: int = _LIMIT,
    before: int | None = _BEFORE,
    event_type: str | None = _EVENT_TYPE,
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
    session: Session = _SESSION,
) -> dict[str, Any]:
    """The organisation's security events, newest first. Own organisation only.

    Paging as on ``/audit/logs``: events come newest first, by timestamp and
    then id, so the order is stable when two share a timestamp.
    ``next_before`` is the last event's id when the page is full; pass it as
    ``before`` for the next page. It is null on a page that is not full.
    Anything shaped like an API key or agent token in ``reason`` or ``query``
    is masked.
    """
    statement = (
        select(SecurityEvent)
        .where(SecurityEvent.organization_id == ctx.organization_id)
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(limit)
    )
    if before is not None:
        cursor = session.get(SecurityEvent, before) if 1 <= before <= _MAX_EVENT_ID else None
        if cursor is None or cursor.organization_id != ctx.organization_id:
            # 404 either way: do not confirm an event in another organisation.
            raise HTTPException(status_code=404, detail="Event not found")
        statement = statement.where(or_(
            SecurityEvent.timestamp < cursor.timestamp,
            and_(SecurityEvent.timestamp == cursor.timestamp, SecurityEvent.id < cursor.id),
        ))
    if event_type:
        statement = statement.where(SecurityEvent.event_type == event_type)

    events = session.exec(statement).all()
    full = bool(events) and len(events) == limit
    return {
        "total": len(events),
        "next_before": str(events[-1].id) if full else None,
        "events": [_event(event) for event in events],
    }
