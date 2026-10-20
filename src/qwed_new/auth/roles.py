"""Roles and role checks for the portal routes (#478).

Roles, lowest to highest: viewer, member, admin, owner. Every check names the
roles it allows. A role that is not listed, including one added later or a
typo in the database, is refused: the allowlists below are the only way in.

The API-key admin routes in ``api/main.py`` (``require_admin_role``) and the
user-session routes in ``auth/routes.py`` and ``auth/audit_routes.py`` share
``ROLE_RANK`` from here, so there is one ranking.
"""

from fastapi import HTTPException
from sqlmodel import Session

from qwed_new.core.models import Organization, User

ROLE_RANK = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}

# Explicit allowlists.
READ_ROLES = frozenset({"viewer", "member", "admin", "owner"})
WRITE_ROLES = frozenset({"member", "admin", "owner"})
ADMIN_ROLES = frozenset({"admin", "owner"})

# Messages kept in one place so the routes and tests agree.
INSUFFICIENT_ROLE = "Insufficient permissions for this operation"
INACTIVE_USER = "User is not active"
INACTIVE_ORG = "Organization is not active"


def role_rank(role: str | None) -> int:
    """Rank of a role; an unknown role ranks below every known one."""
    return ROLE_RANK.get(role or "", -1)


def outranks_or_equals(actor_role: str | None, target_role: str | None) -> bool:
    """True if the actor's role is at least as high as the target's.

    An unknown actor role never qualifies, even against an unknown target.
    """
    return actor_role in ROLE_RANK and role_rank(actor_role) >= role_rank(target_role)


def ensure_user_role(user: User, session: Session, allowed: frozenset) -> User:
    """Refuse the request unless the user, their organisation and their role allow it.

    Fails closed in this order: an inactive user, a missing or inactive
    organisation, then a role outside ``allowed``. Each is a 403.
    """
    if not user.is_active:
        raise HTTPException(status_code=403, detail=INACTIVE_USER)
    org = session.get(Organization, user.organization_id)
    if org is None or not org.is_active:
        raise HTTPException(status_code=403, detail=INACTIVE_ORG)
    if user.role not in allowed:
        raise HTTPException(status_code=403, detail=INSUFFICIENT_ROLE)
    return user
