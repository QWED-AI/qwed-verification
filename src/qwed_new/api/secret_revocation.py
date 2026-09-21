"""Revocation + owner notification for verified secret-leak reports (issue #368).

Consumes the verified :class:`SecretMatch` batches produced by the
:mod:`qwed_new.api.secret_scanning_routes` trust gate and acts on each match:

* known + active key  -> revoke (``is_active=False``, ``revoked_at=now``),
  write a ``SecurityEvent`` audit row, notify the owner by email;
* known + already revoked -> idempotent no-op, still counted;
* unknown token -> no revocation; tallied as a candidate false positive
  for the #369 feedback reporter (which owns persistence of that tally).

Security model (mirrors the issue requirements):

* The plaintext token lives only in a loop-local variable for the single
  HMAC lookup, then is discarded — never logged, never persisted. Audit
  rows and emails carry only ``key_preview``.
* Revocation commits BEFORE notification. A notification failure is logged
  and never rolls the revocation back.
* Owner emails are never throttled: each revocation is a distinct event.
  (``AlertManager.send_alert`` throttles repeats and is not used here.)
* One DB session per batch, one commit per revocation: a single bad row
  cannot roll back the rest of the batch.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Dict, List, Optional

from sqlmodel import Session, select

from qwed_new.api.secret_scanning_routes import SecretMatch
from qwed_new.auth.security import hash_api_key
from qwed_new.core.alerting import alert_manager
from qwed_new.core.database import engine
from qwed_new.core.models import ApiKey, SecurityEvent, User

logger = logging.getLogger(__name__)

#: Audit event type for auto-revocations. #369 keys its false-positive
#: candidates off a different type; only this one means "we revoked".
REVOKED_EVENT_TYPE = "SECRET_LEAK_AUTO_REVOKED"

#: A session factory covering one sink batch. Overridden in tests with an
#: isolated engine; production uses the shared engine (thread-safe, and the
#: sink already runs off the request path in a background task).
SessionFactory = Callable[[], Session]


def _default_session_factory() -> Session:
    return Session(engine)


def _resolve_owner_email(session: Session, api_key: ApiKey) -> Optional[str]:
    """Best-effort owner address: key user first, then org owner/admins."""
    if api_key.user_id is not None:
        user = session.get(User, api_key.user_id)
        if user is not None and user.is_active and user.email:
            return user.email
    owners = session.exec(
        select(User)
        .where(
            User.organization_id == api_key.organization_id,
            User.is_active == True,
            User.role.in_(["owner", "admin"]),
        )
        .order_by(User.id)
    ).all()
    for candidate in owners:
        if candidate.email:
            return candidate.email
    return None


def _notify_owner(recipient: str, api_key: ApiKey, match: SecretMatch) -> None:
    """Email the owner about the revocation. Raises on delivery failure."""
    location = match.url or "(location not provided)"
    subject = "QWED API key auto-revoked after public exposure"
    body = (
        "A QWED API key was detected as publicly exposed and has been "
        "automatically revoked.\n\n"
        f"Key: {api_key.key_preview} (name: {api_key.name or 'unnamed'})\n"
        f"Found at: {location}\n"
        f"Source: {match.source}\n\n"
        "The key no longer authenticates. Issue a replacement from your "
        "organization settings and rotate any services using the old key.\n"
    )
    alert_manager.send_owner_email(recipient, subject, body)


def _revoke_one(session: Session, api_key: ApiKey, match: SecretMatch) -> None:
    """Revoke a single key and record the audit row (caller commits)."""
    api_key.is_active = False
    api_key.revoked_at = datetime.utcnow()
    session.add(api_key)
    session.add(
        SecurityEvent(
            organization_id=api_key.organization_id,
            user_id=api_key.user_id,
            event_type=REVOKED_EVENT_TYPE,
            # Preview only — the plaintext token must never reach the DB.
            query=f"leaked key {api_key.key_preview}",
            reason=f"Public leak auto-revoked: source={match.source} url={match.url}",
            severity="high",
        )
    )


def revoke_leaked_keys(
    matches: List[SecretMatch],
    session_factory: SessionFactory = _default_session_factory,
) -> Dict[str, int]:
    """Sink entry point: revoke + notify for a verified batch.

    Returns per-batch outcome counts (``revoked``, ``already_revoked``,
    ``unknown``, ``errors``). Unknown tokens are tallied, never acted on —
    #369 consumes that tally for false-positive feedback.
    """
    outcome: Dict[str, int] = {
        "revoked": 0,
        "already_revoked": 0,
        "unknown": 0,
        "errors": 0,
    }
    with session_factory() as session:
        for match in matches:
            token = match.token
            digest = ""
            try:
                digest = hash_api_key(token)
            except Exception:
                logger.exception("leak intake: unable to digest a reported match")
                outcome["errors"] += 1
                continue
            try:
                api_key = session.exec(
                    select(ApiKey).where(ApiKey.key_hash == digest)
                ).first()
                if api_key is None:
                    outcome["unknown"] += 1
                    logger.info(
                        "leak intake: no matching key (type=%s source=%s)",
                        match.type,
                        match.source,
                    )
                    continue
                if not api_key.is_active:
                    outcome["already_revoked"] += 1
                    continue
                _revoke_one(session, api_key, match)
                session.commit()
                outcome["revoked"] += 1
                recipient = _resolve_owner_email(session, api_key)
                if recipient is None:
                    logger.warning(
                        "leak intake: revoked key %d has no reachable owner; "
                        "revocation stands without notification",
                        api_key.id,
                    )
                    continue
                try:
                    _notify_owner(recipient, api_key, match)
                except Exception:
                    # Revocation already committed — notify is best effort.
                    logger.exception(
                        "leak intake: owner notification failed for key %d; "
                        "revocation stands",
                        api_key.id,
                    )
            except Exception:
                logger.exception("leak intake: failed processing a reported match")
                session.rollback()
                outcome["errors"] += 1
            finally:
                # Drop plaintext references as soon as the lookup is done.
                del token
                del digest
    logger.info(
        "leak intake done: revoked=%d already_revoked=%d unknown=%d errors=%d",
        outcome["revoked"],
        outcome["already_revoked"],
        outcome["unknown"],
        outcome["errors"],
    )
    return outcome
