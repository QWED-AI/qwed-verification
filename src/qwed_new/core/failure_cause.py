"""One verdict for each cause that stops a verification, on every route (#519).

A missing provider, a failed translation, a refused question and a policy
block used to read differently from one route to the next: the same missing
model was BLOCKED on ``/verify/logic``, "inconclusive" on
``/verify/natural_language`` and "all engines blocked" on
``/verify/consensus``. Each cause now has one name and one verdict:

- ``translation.no_provider``: no model is configured, or the provider named
  is not one QWED knows. Nothing was translated, so nothing was verified:
  UNVERIFIABLE. The message names the setting to fix.
- ``translation.failed``: the provider failed, or its translation could not
  be used. UNVERIFIABLE, with a message that carries nothing from the
  provider.
- ``security.input_refused``: the injection screen refused the caller's text
  before any model saw it. BLOCKED, with the one message below on every
  route: the screen's own reason names the pattern it matched, which is
  detection logic, so it stays in the server log.
- ``security.output_refused``: the safety check refused the model's
  translation. BLOCKED.
- ``policy.blocked``: the control plane's policy refused the request.
  BLOCKED.

None of them is admitted. The route that meets one writes its audit row as
for any other verdict.
"""

import math
import threading
import time
from decimal import Context, Decimal
from typing import Any

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.providers.base import ProviderConfigError, TranslationRefused

NO_PROVIDER = "translation.no_provider"
TRANSLATION_FAILED = "translation.failed"
INPUT_REFUSED = "security.input_refused"
OUTPUT_REFUSED = "security.output_refused"
POLICY_BLOCKED = "policy.blocked"

# The causes that mean nothing was translated: UNVERIFIABLE.
TRANSLATION_CAUSES = frozenset({NO_PROVIDER, TRANSLATION_FAILED})
CAUSES = TRANSLATION_CAUSES | {INPUT_REFUSED, OUTPUT_REFUSED, POLICY_BLOCKED}

_DEFAULT_MESSAGES = {
    NO_PROVIDER: "No model provider is configured, so the question was not translated and nothing was verified",
    TRANSLATION_FAILED: "The translation by the model failed, so nothing was verified",
    INPUT_REFUSED: "The input was refused by the injection screen before any model saw it",
    OUTPUT_REFUSED: "The safety check refused the translation by the model",
    POLICY_BLOCKED: "The request was refused by policy",
}


def cause_of(exc: BaseException) -> str:
    """The cause an exception raised while translating stands for.

    A wrapped exception (``raise ValueError(...) from exc``, as the consensus
    engines do) is read through its ``__cause__`` chain, so the cause does
    not depend on which engine met it. Any exception it does not recognise
    reads as a failed translation, so callers pass only an exception from
    the translation step: once the model has answered, an error is the
    engine's, not a translation cause.
    """
    from qwed_new.core.translator import SecurityError

    seen = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ProviderConfigError):
            return NO_PROVIDER
        if isinstance(current, TranslationRefused):
            return INPUT_REFUSED
        if isinstance(current, SecurityError):
            return OUTPUT_REFUSED
        current = current.__cause__
    return TRANSLATION_FAILED


def message_for(cause: str) -> str:
    """The message a caller sees for ``cause`` when nothing more may be said."""
    return _DEFAULT_MESSAGES[cause]


def message_of(exc: BaseException, cause: str) -> str:
    """The message a caller may see for ``exc``: the text of a
    ProviderConfigError, which names the setting to fix and carries nothing
    from a provider; otherwise the cause's own message. A refusal's text is
    never passed on: the screen's reason names the pattern it matched, and
    a caller who reads it can reword the question around that pattern."""
    current: BaseException | None = exc
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if cause == NO_PROVIDER and isinstance(current, ProviderConfigError):
            return str(current)
        current = current.__cause__
    return message_for(cause)


def diagnostic_for(
    cause: str,
    message: str | None = None,
    developer_fields: dict[str, Any] | None = None,
) -> DiagnosticResult:
    """The one verdict for ``cause``, with ``constraint_id`` set to it."""
    if cause not in CAUSES:
        raise ValueError(f"unknown cause: {cause!r}")
    fields = {**(developer_fields or {}), "constraint_id": cause}
    text = message or _DEFAULT_MESSAGES[cause]
    if cause in TRANSLATION_CAUSES:
        return DiagnosticResult.unverifiable(text, developer_fields=fields)
    return DiagnosticResult.blocked(text, developer_fields=fields)


def diagnostic_for_exception(
    exc: BaseException, developer_fields: dict[str, Any] | None = None
) -> DiagnosticResult:
    """``diagnostic_for`` the cause ``exc``, an exception from the
    translation step, stands for (see ``cause_of``)."""
    cause = cause_of(exc)
    return diagnostic_for(cause, message_of(exc, cause), developer_fields)


def now_ns() -> int:
    """The clock a deadline, an engine's start and a translation's landing
    are read on (#519): ``time.monotonic_ns``."""
    return time.monotonic_ns()


# The deadline's own decimal context, so the caller's (a lower precision, a
# trap on Inexact) can neither round a duration nor refuse it. A float's
# shortest decimal form has at most 17 digits and a billion adds ten, so 40
# digits hold every product exactly.
_NANOSECONDS = Context(prec=40, traps=[])


def nanoseconds(seconds: float) -> int:
    """``seconds`` as whole nanoseconds, converted once, exactly, with no
    floating-point product and whatever decimal context the caller has set,
    so 1.001 seconds is 1,001,000,000 nanoseconds. ``seconds`` must be
    finite."""
    if not math.isfinite(seconds):
        raise ValueError(f"a deadline needs a finite number of seconds, not {seconds!r}")
    return int(_NANOSECONDS.multiply(Decimal(str(seconds)), 1_000_000_000))


def deadline_after(seconds: float) -> int:
    """The ``now_ns`` reading ``seconds`` from now (see ``nanoseconds``)."""
    return now_ns() + nanoseconds(seconds)


# How early a timer may end a wait: its clock's resolution, about 16 ms at
# most (Windows' tick clock), well inside this bound.
_EARLY_BY_AT_MOST_NS = 100_000_000
# One tick more than what is left, so a clock that reads in ticks has reached
# the deadline when the sleep ends.
_CLOCK_RESOLUTION_S = time.get_clock_info("monotonic").resolution


def wait_out(deadline_ns: int) -> None:
    """Once a wait for ``deadline_ns`` has ended, sleep out what is left of
    it, so what landed is read at or after the deadline: a timer may end a
    wait up to its clock's resolution early, and a translation that lands in
    that time came in time. Nothing is left to wait for a deadline that has
    passed, or one far ahead, which is not the deadline that ended the wait."""
    remaining = deadline_ns - now_ns()
    if 0 < remaining <= _EARLY_BY_AT_MOST_NS:
        time.sleep(remaining / 1_000_000_000 + _CLOCK_RESOLUTION_S)


class LandedTranslations(list):
    """A request's translations, each noted with when it landed (#519).

    A provider call runs on a worker thread that no deadline stops, so the
    model may answer after the deadline expired and before the request
    reads this list. Whether the model answered in time, and so whether the
    deadline is a failed translation, is read from ``read``: an answer that
    lands late cannot change the cause. The list itself keeps a late
    answer, for the audit row (#578). Only ``append`` notes a landing: an
    entry added any other way never counts as in time."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._landed: list[tuple[int, Any]] = []

    def append(self, translation: Any) -> None:
        with self._lock:
            self._landed.append((now_ns(), translation))
            super().append(translation)

    def read(self, deadline_ns: int) -> tuple[list[Any], list[Any]]:
        """Every translation, and those that landed before ``deadline_ns``,
        in one read under the lock: an append under way is in both or in
        neither, so the audit row and the cause cannot disagree."""
        with self._lock:
            return list(self), [found for landed, found in self._landed if landed < deadline_ns]

    def __eq__(self, other: object) -> bool:
        # Equal as lists are, by the translations held: when each landed is
        # bookkeeping, not part of the value.
        return list.__eq__(self, other)
