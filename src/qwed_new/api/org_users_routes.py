"""List the users of the caller's organisation (#507).

``GET /auth/me`` returns the signed-in user only, and the security activity
summary returns just a count, so a client could name a key's owner or an
event's ``user_id`` but never list who is in the organisation. This route is
read-only; inviting users and changing roles are separate work.

Owners and admins, with an API key or a signed-in session. Kept out of
api/main.py, which is at the size limit of the deterministic security scan,
and out of auth/routes.py, which api/admin_auth.py imports.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, select

from qwed_new.api.admin_auth import AdminContext, require_admin_role
from qwed_new.auth.routes import _as_utc
from qwed_new.core.database import get_session
from qwed_new.core.models import User

router = APIRouter(prefix="/auth", tags=["authentication"])

_REQUIRE_ADMIN_OR_SESSION = Depends(require_admin_role(["owner", "admin"], allow_session=True))
_SESSION = Depends(get_session)


class OrgUser(BaseModel):
    id: str
    email: str
    role: str  # owner, admin, member or viewer
    is_active: bool
    created_at: datetime


@router.get(
    "/users",
    response_model=list[OrgUser],
    responses={
        401: {"description": "No API key or bearer token"},
        403: {"description": "Not an owner or admin, or an inactive user, organisation or key"},
    },
)
def list_org_users(
    ctx: AdminContext = _REQUIRE_ADMIN_OR_SESSION,
    session: Session = _SESSION,
) -> list[dict]:
    """Every user of the caller's organisation, oldest first. Own organisation only.

    Inactive users are listed too, with ``is_active`` false, so a client can
    show who was deactivated. No password hash or permission data is returned.
    """
    users = session.exec(
        select(User)
        .where(User.organization_id == ctx.organization_id)
        .order_by(User.created_at, User.id)
    ).all()
    return [
        {
            "id": str(user.id),
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": _as_utc(user.created_at),
        }
        for user in users
    ]
