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
  before any model saw it. BLOCKED.
- ``security.output_refused``: the safety check refused the model's
  translation. BLOCKED.
- ``policy.blocked``: the control plane's policy refused the request.
  BLOCKED.

None of them is admitted. The route that meets one writes its audit row as
for any other verdict.
"""

import threading
import time
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
    INPUT_REFUSED: "The question was refused by the injection screen before any model saw it",
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


def message_of(exc: BaseException, cause: str) -> str:
    """The message a caller may see for ``exc``: the text of a
    ProviderConfigError or a refusal, which carries nothing from a provider;
    otherwise the cause's own message."""
    current: BaseException | None = exc
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if cause == NO_PROVIDER and isinstance(current, ProviderConfigError):
            return str(current)
        if cause == INPUT_REFUSED and isinstance(current, TranslationRefused):
            return str(current)
        current = current.__cause__
    return _DEFAULT_MESSAGES[cause]


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


def deadline_after(seconds: float) -> int:
    """The ``time.monotonic_ns`` reading ``seconds`` from now: a deadline a
    translation's landing is read against (``LandedTranslations``)."""
    return time.monotonic_ns() + int(seconds * 1_000_000_000)


class LandedTranslations(list):
    """A request's translations, each noted with when it landed (#519).

    A provider call runs on a worker thread that no deadline stops, so the
    model may answer after the deadline expired and before the request
    reads this list. Whether the model answered in time, and so whether the
    deadline is a failed translation, is read from ``before``: an answer
    that lands late cannot change the cause. The list itself keeps a late
    answer, for the audit row (#578). Only ``append`` notes a landing: an
    entry added any other way never counts as in time."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._landed: list[tuple[int, Any]] = []

    def append(self, translation: Any) -> None:
        with self._lock:
            self._landed.append((time.monotonic_ns(), translation))
            super().append(translation)

    def before(self, deadline_ns: int) -> list[Any]:
        """The translations that landed before ``deadline_ns``."""
        with self._lock:
            return [found for landed, found in self._landed if landed < deadline_ns]
