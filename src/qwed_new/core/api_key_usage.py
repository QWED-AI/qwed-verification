"""When an API key was last used (#486).

``ApiKey.last_used_at`` existed but nothing set it, so the dashboard could not
say when a key was last used. ``record_api_key_use`` sets it once a key has
passed every check. It writes at most once a minute per key: a busy key does
not cause a database write on every request.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.attributes import set_committed_value
from sqlmodel import Session

from qwed_new.core.models import ApiKey

logger = logging.getLogger(__name__)

# The most often last_used_at is written for one key.
LAST_USED_INTERVAL = timedelta(minutes=1)


def _as_utc(value: datetime) -> datetime:
    """A stored time without a zone is UTC (SQLite drops the zone)."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def record_api_key_use(session: Session, api_key: ApiKey, now: datetime | None = None) -> bool:
    """Set ``api_key.last_used_at`` to now unless it was set in the last minute.

    The value already loaded with the key decides whether to write, so a key
    used within the minute costs no query. The write is conditional on the
    stored value still being stale, so two workers that both see a stale
    value write it once. A failed write is logged and never fails the
    request: the key has already been accepted. Returns whether it wrote.
    """
    now = now or datetime.now(timezone.utc)
    stale_before = now - LAST_USED_INTERVAL
    if api_key.last_used_at is not None and _as_utc(api_key.last_used_at) > stale_before:
        return False
    try:
        result = session.exec(
            update(ApiKey)
            .where(
                ApiKey.id == api_key.id,
                or_(ApiKey.last_used_at.is_(None), ApiKey.last_used_at <= stale_before),
            )
            .values(last_used_at=now)
            # Not "evaluate": that compares the WHERE in Python against the
            # loaded key, and a stored time without a zone (SQLite) next to
            # an aware one raises TypeError.
            .execution_options(synchronize_session=False)
        )
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.warning("Could not record API key use for key %s: %s", api_key.id, type(exc).__name__)
        return False
    wrote = bool(result.rowcount)
    if wrote and isinstance(api_key, ApiKey):
        # Keep the loaded key in step without marking it changed, so the
        # request's own commit does not write the column a second time.
        set_committed_value(api_key, "last_used_at", now)
    return wrote
