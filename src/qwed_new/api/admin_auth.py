"""Authentication and role checks for the /admin/* routes and /auth/users.

Moved out of api/main.py, which is at the size limit of the deterministic
security scan. ``require_admin_role`` authenticates with an API key; with
``allow_session=True`` it also accepts a signed-in user's JWT, so the
dashboard can call a route without holding an API key in the browser: the
compliance routes (#485), the security events list (#486), the threat summary
(#506), key rotation (#505) and the organisation's user list (#507). Agent
token reissue stays API-key only. Both paths apply the same role allowlist and
active checks.
"""

import asyncio

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from qwed_new.auth.middleware import api_key_header, get_api_key
from qwed_new.auth.roles import ensure_user_role
from qwed_new.auth.routes import get_current_user_token
from qwed_new.auth.security import is_api_key_live
from qwed_new.core.api_key_usage import record_api_key_use
from qwed_new.core.database import get_session
from qwed_new.core.models import ApiKey, Organization, User

# Dependency singletons (Ruff B008).
_API_KEY = Depends(get_api_key)
_API_KEY_HEADER = Security(api_key_header)
# A security scheme, not a plain header, so OpenAPI lists the bearer token as
# an alternative to the API key and generated clients can model it.
_bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="SessionBearer",
    description="A signed-in user's JWT (owner or admin), as an alternative to x-api-key",
)
_BEARER = Security(_bearer_scheme)
_SESSION = Depends(get_session)


class AdminContext:
    """The authenticated principal for an admin endpoint: the user (which
    carries the role), the organisation they are scoped to, and the API key
    when one was used (None for a signed-in session)."""

    def __init__(self, user: User, api_key: ApiKey | None = None):
        self.api_key = api_key
        self.user = user
        self.organization_id = api_key.organization_id if api_key is not None else user.organization_id
        self.role = user.role


def _admin_from_api_key(api_key: ApiKey, session: Session, allowed_roles: list[str]) -> AdminContext:
    """Fails closed before granting admin access: the key must be live (not
    expired or revoked), the owning user must be active and in the key's own
    organisation (so a key cannot borrow a role from another tenant), the
    organisation must be active, and the role must be allowed."""
    if not is_api_key_live(api_key):
        raise HTTPException(status_code=403, detail="API key is expired or revoked")
    user = session.get(User, api_key.user_id) if api_key.user_id else None
    if user is None or not user.is_active or user.organization_id != api_key.organization_id:
        raise HTTPException(status_code=403, detail="API key is not authorized for admin operations")
    org = session.get(Organization, api_key.organization_id)
    if org is None or not org.is_active:
        raise HTTPException(status_code=403, detail="Organization is not active")
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions for this operation")
    # Only now, so a key refused by any check above is never marked as used
    # (#486). This runs in a worker thread on both admin paths.
    record_api_key_use(session, api_key)
    return AdminContext(user, api_key)


def _admin_from_session(authorization: str, session: Session, allowed_roles: list[str]) -> AdminContext:
    """A signed-in user (#485): a valid JWT, then the same checks as the
    user-session routes (``ensure_user_role``): active user, active
    organisation, role in the allowlist."""
    payload = get_current_user_token(authorization)
    try:
        user = session.get(User, int(payload.get("sub")))
    except (TypeError, ValueError):
        user = None
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return AdminContext(ensure_user_role(user, session, frozenset(allowed_roles)))


def require_admin_role(allowed_roles: list[str], *, allow_session: bool = False):
    """Dependency for admin endpoints (#222). The returned AdminContext carries
    organization_id so the handler can scope the action to the caller's own
    organisation and never act on a caller-supplied id for another tenant.

    An ``x-api-key`` header is checked as before. With ``allow_session``, a
    request without one may instead send ``Authorization: Bearer <jwt>`` for a
    signed-in user; when both are sent, the API key is used. Without either,
    the request is refused with 401.
    """

    def api_key_only(
        api_key: ApiKey = _API_KEY,
        session: Session = _SESSION,
    ) -> AdminContext:
        return _admin_from_api_key(api_key, session, allowed_roles)

    async def api_key_or_session(
        x_api_key: str | None = _API_KEY_HEADER,
        bearer: HTTPAuthorizationCredentials | None = _BEARER,
        session: Session = _SESSION,
    ) -> AdminContext:
        # The role and active checks read the database: run them in a worker
        # thread, as FastAPI runs a sync dependency, not on the event loop.
        if x_api_key:
            api_key = await get_api_key(x_api_key, session)
            return await asyncio.to_thread(_admin_from_api_key, api_key, session, allowed_roles)
        if bearer is not None:
            authorization = f"Bearer {bearer.credentials}"
            return await asyncio.to_thread(_admin_from_session, authorization, session, allowed_roles)
        raise HTTPException(status_code=401, detail="Missing x-api-key header or bearer token")

    return api_key_or_session if allow_session else api_key_only
