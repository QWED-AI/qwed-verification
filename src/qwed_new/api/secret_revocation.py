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
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlmodel import Session, select, update

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
            User.is_active,
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


def _try_revoke(
    session: Session,
    api_key: ApiKey,
    match: SecretMatch,
    revoked_at: Optional[datetime] = None,
) -> bool:
    """Atomically revoke iff still active. Returns True iff this call won.

    Concurrent deliveries can both SELECT an active key; the conditional
    UPDATE (``WHERE is_active``) lets exactly one win (CodeAnt race review
    on #380). The loser sees rowcount 0 and must treat the key as
    already-revoked — critically, without notifying again. The ORM object
    is synced on win so later reads (preview, ids) stay consistent.
    Also stages the audit row; the caller commits.

    ``revoked_at`` is injectable so tests use a fixed timestamp instead of
    ambient clock (CodeRabbit determinism review on #380); production
    passes nothing and gets UTC now.
    """
    now = revoked_at or datetime.now(timezone.utc)
    result = session.execute(
        update(ApiKey)
        .where(ApiKey.id == api_key.id, ApiKey.is_active)
        .values(is_active=False, revoked_at=now)
    )
    if (result.rowcount or 0) < 1:
        return False
    api_key.is_active = False
    api_key.revoked_at = now
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
    return True


def _redact_token(text: str, token: str) -> str:
    """Remove exact occurrences of a leaked token from scanner metadata.

    A verified report can echo the plaintext credential inside ``url``
    (e.g. a filename containing the key) or other metadata fields. Those
    fields flow into audit rows, emails, and logs — all of which must never
    carry the token (CWE-312, CodeRabbit on #380). Exact-substring redaction
    with the known token is used instead of a heuristic redactor: it cannot
    miss this token and cannot false-positive on anything else.
    """
    if not token:
        return text
    return text.replace(token, "[REDACTED]") if token in text else text


def _redacted_field(text: str, token: str, field: str) -> str:
    """Redact ``token`` from one metadata field, clamped to the model's cap.

    Redaction replaces each token occurrence with ``"[REDACTED]"``, which
    EXPANDS the value when the token is shorter than 10 chars. An expanded
    value past the field's ``max_length`` would raise ``ValidationError``
    inside ``_stage_batch`` and abort the whole batch — one pathological
    match DoSing its legitimate siblings (Sentry LOW on #380). Via GitHub
    this is unreachable (only fixed-length regex matches are forwarded, and
    redacting those always shrinks), but the sink is public and other
    scanners may feed it. The cap is read off the model so it cannot drift.
    Truncation only removes characters, so it can never reintroduce token
    material.
    """
    redacted = _redact_token(text, token)
    cap = next(
        (
            meta.max_length
            for meta in SecretMatch.model_fields[field].metadata
            if hasattr(meta, "max_length")
        ),
        None,
    )
    if cap is not None and len(redacted) > cap:
        return redacted[:cap]
    return redacted


def _sanitized_match(match: SecretMatch, token: str) -> SecretMatch:
    """Copy of ``match`` with any embedded token occurrences redacted.

    The copy's own ``token`` field is replaced with a fixed placeholder:
    nothing downstream needs the plaintext (lookup uses the digest), and a
    live ``token`` attribute would ride along into exception tracebacks and
    error-reporting locals capture (Sentry HIGH on #380). ``token`` still
    satisfies the model's min_length=1 constraint.
    """
    return SecretMatch(
        token="[REDACTED]",
        type=_redacted_field(match.type, token, "type"),
        url=_redacted_field(match.url, token, "url"),
        source=_redacted_field(match.source, token, "source"),
    )


class LeakBatchIncomplete(RuntimeError):
    """A batch finished with per-row enforcement failures.

    Raised AFTER every match was attempted (revocations maximized), so the
    failure is loud instead of a quiet ``errors`` tally (CodeRabbit
    fail-closed review on #380). Carries the outcome counts for monitoring.
    """


def _notify_best_effort(session: Session, api_key: ApiKey, match: SecretMatch) -> None:
    """Resolve the owner and notify, swallowing all notification-plane failures.

    Owner *resolution* failures are best-effort too, not enforcement
    failures: the revocation already committed, and failing the batch over
    an addressing lookup misreports completed enforcement as failed
    (Greptile T-Rex on #380 — the DB row proves revoked while the receipt
    says sink_failed). Genuine enforcement failures (lookup, claim, commit)
    still tally errors in the caller and raise loudly at batch end.
    """
    try:
        recipient = _resolve_owner_email(session, api_key)
    except Exception:
        # Resolution runs post-commit, so nothing staged needs saving — but
        # the failed SELECT poisons the transaction (Postgres aborts it),
        # and every later lookup in this batch would fail with it.
        # Roll back to a clean transaction before returning (Greptile P1
        # on #380).
        session.rollback()
        logger.exception(
            "leak intake: owner resolution failed for key %d; "
            "revocation stands without notification",
            api_key.id,
        )
        return
    if recipient is None:
        logger.warning(
            "leak intake: revoked key %d has no reachable owner; "
            "revocation stands without notification",
            api_key.id,
        )
        return
    try:
        _notify_owner(recipient, api_key, match)
    except Exception:
        logger.exception(
            "leak intake: owner notification failed for key %d; "
            "revocation stands",
            api_key.id,
        )


# Frames that bind the plaintext token as a local and therefore travel
# with any exception raised through them: the hasher's ``api_key`` argument,
# this module's own staging loop, and the sanitizer (its ``token`` argument
# and ``match`` parameter both carry plaintext — Sentry MEDIUM on #380).
# Scrubbed (not merely unreferenced) on the digest-failure path below.
_TOKEN_HOLDING_FRAMES = frozenset({"hash_api_key", "_stage_batch", "_sanitized_match"})


def _scrub_token_frames(exc: BaseException) -> None:
    """Clear locals of dead frames known to hold the plaintext token.

    A traceback keeps every frame it passes through, so deleting names in
    the logging frame is insufficient: ``hash_api_key``'s frame retains its
    ``api_key`` argument, and any locals-capturing reporter ships it with
    the event (Greptile T-Rex on #380 proved exactly this). Clearing a frame
    that has already exited is safe — none of them resume. The CURRENT
    (still-executing) frame is never touched: it has logging left to do.
    """
    current = sys._getframe(1)
    seen = set()
    error: Optional[BaseException] = exc
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        tb = error.__traceback__
        while tb is not None:
            frame = tb.tb_frame
            if frame is not current and frame.f_code.co_name in _TOKEN_HOLDING_FRAMES:
                frame.clear()
            tb = tb.tb_next
        error = error.__cause__ or error.__context__


def _stage_batch(matches: List[SecretMatch]) -> List[tuple]:
    """Digest + sanitize every match up front.

    Returns ``[(sanitized_match, digest)]``. Plaintext tokens live ONLY in
    this helper's frame — and on failure the frame is scrubbed before
    re-raising (CodeRabbit CWE-532 on #380): a traceback keeps every frame
    it passes through, so deleting names in the *caller* is not enough;
    each frame must clean itself. All four names below are pre-bound so the
    cleanup dels can never NameError.
    """
    staged = []
    token = ""
    original = None
    digest = ""
    try:
        for original in matches:
            token = original.token
            digest = hash_api_key(token)
            staged.append((_sanitized_match(original, token), digest))
    except Exception:
        del token, original, digest, matches
        raise
    return staged


def revoke_leaked_keys(
    matches: List[SecretMatch],
    session_factory: SessionFactory = _default_session_factory,
) -> Dict[str, int]:
    """Sink entry point: revoke + notify for a verified batch.

    Returns per-batch outcome counts (``revoked``, ``already_revoked``,
    ``unknown``, ``errors``). Unknown tokens are tallied, never acted on —
    #369 consumes that tally for false-positive feedback. A digest failure
    means enforcement cannot run at all, so it aborts the batch loudly
    instead of tallying (CodeRabbit fail-closed on #380). Per-row failures
    tally ``errors`` without blocking sibling keys — then the batch raises
    ``LeakBatchIncomplete`` so the failure is loud, not a quiet tally.
    """
    outcome: Dict[str, int] = {
        "revoked": 0,
        "already_revoked": 0,
        "unknown": 0,
        "errors": 0,
    }
    with session_factory() as session:
        try:
            staged = _stage_batch(matches)
        except Exception as exc:
            # Digest failure means enforcement cannot run at all: scrub the
            # callee frames (hash_api_key's api_key argument travels with
            # the traceback), drop our own batch reference, then fail loud.
            _scrub_token_frames(exc)
            del matches
            logger.exception(
                "leak intake: unable to digest — enforcement cannot run, "
                "failing the batch closed"
            )
            raise
        # The raw batch is no longer needed: every logging site below sees
        # only sanitized copies and one-way digests.
        del matches
        for match, digest in staged:
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
                if not _try_revoke(session, api_key, match):
                    # Lost a concurrent race: the key flipped after our
                    # SELECT. Same tally as already-revoked, no notify.
                    session.rollback()
                    outcome["already_revoked"] += 1
                    continue
                session.commit()
                outcome["revoked"] += 1
                _notify_best_effort(session, api_key, match)
            except Exception:
                logger.exception("leak intake: failed processing a reported match")
                session.rollback()
                outcome["errors"] += 1
            finally:
                # Drop the digest once the lookup is done.
                del digest
    logger.info(
        "leak intake done: revoked=%d already_revoked=%d unknown=%d errors=%d",
        outcome["revoked"],
        outcome["already_revoked"],
        outcome["unknown"],
        outcome["errors"],
    )
    if outcome["errors"]:
        raise LeakBatchIncomplete(
            "leak intake finished with per-row enforcement failures: "
            f"{outcome}"
        )
    return outcome
