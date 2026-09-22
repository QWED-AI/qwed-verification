"""False-positive feedback reporter for verified leak matches (issue #369).

After a batch of leak matches is processed, report back one label per
match so the scanning source can improve detection quality over time
(and qualify for the partner program's lenient 30s timeout)::

    [{"token_hash": "<SHA-256 of the raw token>", "token_type": "<pattern name>", "label": "true_positive"}]

Rules (from the issue — structural, enforced by the model below):

* Send either ``token_raw`` or ``token_hash`` — never both. Default to
  ``token_hash`` so the plaintext secret is never transmitted back out.
* The hash, when used, is SHA-256 and nothing else.
* ``label`` is exactly ``true_positive`` or ``false_positive``.
* A match is a true positive when the ``hash_api_key()`` lookup found a
  real key; false positive when nothing matched.

Participation is opt-in: the reporter is behind ``QWED_LEAK_FEEDBACK_ENABLED``
(default off) and needs ``QWED_LEAK_FEEDBACK_URL``. Raw-token mode needs the
separate explicit ``QWED_LEAK_FEEDBACK_SEND_RAW`` opt-in.

Frame hygiene: classification binds raw tokens transiently, so logging
follows one rule — no log is ever emitted while token-bearing names are
bound in the emitting frame. Per-match skips are silent (a re-raise would
trade a partial truthful batch for total silence, and enforcement
fail-closed lives in the sink, not this telemetry path); an all-skipped
batch is still loud via counts alone. Raw mode is silent on the send path
for the same reason (see send_leak_feedback). The prepared items travel
onward instead of the batch: in the default hash mode they are one-way
digests, safe in any frame.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, model_validator
from sqlmodel import Session, select

if TYPE_CHECKING:  # pragma: no cover - import for type checking only; avoids a routes <-> feedback cycle
    from qwed_new.api.secret_scanning_routes import SecretMatch
from qwed_new.auth.security import hash_api_key
from qwed_new.core.database import engine
from qwed_new.core.models import ApiKey

logger = logging.getLogger(__name__)

#: Label literals — the only two values the feedback receiver accepts.
TRUE_POSITIVE = "true_positive"
FALSE_POSITIVE = "false_positive"

#: Upper bound for the outbound feedback POST. Kept short on purpose: the
#: POST runs on the delivery path, and a sick feedback endpoint must not
#: hold delivery workers long (CodeAnt nitpick on #386). 5s is generous
#: for a label batch; anything slower is logged and dropped.
_FEEDBACK_TIMEOUT_SECONDS = 5.0


def _default_session_factory() -> Session:
    return Session(engine)


class FeedbackItem(BaseModel):
    """One labeled match. Exactly one of ``token_hash`` / ``token_raw``."""

    token_type: str
    label: Literal["true_positive", "false_positive"]
    token_hash: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")
    token_raw: str | None = None

    @model_validator(mode="after")
    def _exactly_one_token_form(self) -> FeedbackItem:
        if bool(self.token_hash) == bool(self.token_raw):
            raise ValueError("exactly one of token_hash / token_raw must be set")
        return self


def feedback_enabled() -> bool:
    """Opt-in participation flag. Off unless explicitly enabled."""
    return os.getenv("QWED_LEAK_FEEDBACK_ENABLED", "false").lower() == "true"


def feedback_endpoint() -> str:
    """Where labeled matches are POSTed. Empty means unconfigured."""
    return os.getenv("QWED_LEAK_FEEDBACK_URL", "").strip()


def send_raw_enabled() -> bool:
    """Separate explicit opt-in for transmitting plaintext tokens."""
    return os.getenv("QWED_LEAK_FEEDBACK_SEND_RAW", "false").lower() == "true"


def _sha256_token(token: str) -> str:
    """SHA-256 hex digest of a raw token — the only hash the receiver takes."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _classify_matches(
    matches: list[SecretMatch],
    session_factory,
) -> list[FeedbackItem]:
    """Label every match by read-only lookup. May raise; caller contains it.

    A match is a true positive iff the ``hash_api_key()`` digest finds a
    real key row — the same found/not-found rule the revocation sink uses,
    minus the side effects. Digests are computed locally for all matches,
    then resolved with a SINGLE ``IN`` query: per-match SELECTs would put
    up to 500 round-trips (the request cap) ahead of revocation, delaying
    enforcement by seconds under load (Greptile P1 T-Rex on #386 measured
    1.6s). Classification runs before revocation, which is safe: a key
    revoked after classification was still a real key at label time, and
    unknown tokens stay unknown (digests are unforgeable).
    """
    raw = bool(send_raw_enabled())
    entries = []
    for match in matches:
        # Per-match containment: one bad token skips only itself instead of
        # discarding the whole batch's labels — a re-raise would trade a
        # partial truthful batch for total silence, while enforcement
        # fail-closed lives in the sink and is unaffected (CodeRabbit
        # re-raise demand on #386, declined for this reason). The skip is
        # SILENT by necessity: this frame binds raw tokens, so no log may
        # be emitted from it (CWE-532). An all-skipped batch is still loud:
        # prepare() detects it from counts alone (CWE-532, CodeRabbit #386).
        # Silent by necessity: this frame binds raw tokens, so no log may
        # be emitted from it (CWE-532).
        try:
            token = match.token
            digest = hash_api_key(token)
        except Exception:  # noqa: BLE001, S112
            continue
        entries.append((match, token, digest))
    found: set[str] = set()
    if entries:
        with session_factory() as session:
            rows = session.exec(
                select(ApiKey.key_hash).where(
                    ApiKey.key_hash.in_([digest for _, _, digest in entries])
                )
            ).all()
            found = set(rows)
    return [
        FeedbackItem(
            token_type=match.type,
            label=TRUE_POSITIVE if digest in found else FALSE_POSITIVE,
            token_hash=None if raw else _sha256_token(token),
            token_raw=token if raw else None,
        )
        for match, token, digest in entries
    ]


def prepare_leak_feedback(
    matches: list[SecretMatch], session_factory=None
) -> list[FeedbackItem]:
    """Build labeled items for a batch. Never raises; [] on any failure.

    Disabled flag short-circuits before touching the batch. Anything else
    that goes wrong (digest failure, DB outage) is message-logged without a
    traceback — the batch is still bound in this frame, and a
    locals-capturing reporter must never observe it here. The log call sits
    outside the handler on purpose: logging with the traceback attached
    (``logger.exception`` or ``exc_info``) would ship the callee frames that
    bind the plaintext token. An all-skipped batch (e.g. dead lookup
    secret, where every per-match digest fails) is detected from counts
    alone and logged loudly: at that point the frame holds only an empty
    list and ints, safe in both modes.
    """
    if not feedback_enabled():
        return []
    if session_factory is None:
        session_factory = _default_session_factory
    total = len(matches)
    classification_error = None
    try:
        items = _classify_matches(matches, session_factory)
    except Exception as exc:  # noqa: BLE001
        classification_error = exc
    del matches
    if classification_error is not None:
        logger.error("leak feedback skipped: %s", classification_error)
        return []
    if not items and total:
        logger.warning("leak feedback labeled 0 of %d matches", total)
    return items


def send_leak_feedback(items: list[FeedbackItem]) -> None:
    """POST labeled items to the configured endpoint. Never raises.

    Logging discipline: every log below runs only after the token-bearing
    names (``items``, ``payload``) are deleted — in raw mode they hold
    plaintext, and the delivery frames up-stack still bind it, so raw mode
    is SILENT by design (no delivered/refused/failed lines). Hash mode
    keeps its logs: one-way digests are safe in any frame. Failures stay
    message-only regardless.
    """
    count = len(items)
    if count == 0:
        return
    if not feedback_enabled():
        return
    url = feedback_endpoint()
    raw = any(item.token_raw for item in items)
    if not url:
        if not raw:
            logger.warning("leak feedback enabled but QWED_LEAK_FEEDBACK_URL is unset; dropping batch")
        return
    if raw and urlparse(url).scheme != "https":
        # Silent by design (see docstring): the delivery frames still bind
        # plaintext, so even the refusal line is skipped in raw mode.
        return
    payload: list[dict[str, str]] = []
    delivery_error = None
    try:
        payload = [item.model_dump(exclude_none=True) for item in items]
        response = httpx.post(url, json=payload, timeout=_FEEDBACK_TIMEOUT_SECONDS)
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        delivery_error = exc
    del items, payload
    if delivery_error is not None:
        if not raw:
            logger.warning("leak feedback not delivered: %s", delivery_error)
        return
    if not raw:
        logger.info("leak feedback delivered: count=%d", count)
