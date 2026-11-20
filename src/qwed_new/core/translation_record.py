"""What a model translated, kept for the audit row (#578) and named in the
result (#585).

A route that asks a model to translate decides on what the model returned:
the formula, the constraints, the code or the fact advisory. The audit row
kept none of it, so a verdict on a translation could not be re-checked from
the row. Each translation is now kept as QWED parsed it, with the provider
and model that answered, and stored in ``raw_llm_output``, which the audit
chain hashes.

The record is canonical, strict JSON (sorted keys, no spaces, ASCII, no NaN),
so a reader can rebuild it byte for byte and any JSON parser reads it. It is
never returned to the caller: it is the model's output before any output
sanitising. A record over ``MAX_RECORD_CHARS`` is stored as its length, its
SHA-256 and a preview, so a row stays bounded and still names the full text.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, List, Optional

if TYPE_CHECKING:
    from qwed_new.core.diagnostics import DiagnosticResult

# The key a control-plane result carries the record under, and the audit
# row's column. Routes move it onto the DiagnosticResult, never into a response.
RAW_LLM_OUTPUT_KEY = "raw_llm_output"

MAX_RECORD_CHARS = 64_000
# A preview is ASCII JSON, so escaping it again at most doubles it: the
# truncated record stays well under MAX_RECORD_CHARS.
PREVIEW_CHARS = 16_000

# JSON has no number for these, so a model's NaN or infinity is written as
# the text Python's own JSON writer would use.
_NON_FINITE = {"nan": "NaN", "inf": "Infinity", "-inf": "-Infinity"}


@dataclass(frozen=True)
class Translation:
    """One model translation: what the model returned, as QWED parsed it,
    and the provider and model that answered.

    ``kind`` is what was asked ("math", "logic", "stats" or "fact"), and
    ``engine`` names the consensus engine that asked, where one did. Under
    auto-shift, ``provider_used`` is the provider selected ("auto"), as the
    result names it, and ``answering_provider`` the side that answered. The
    provider and model come from QWED's configuration, never from the model's
    own answer, and admit nothing (#585).
    """

    kind: str
    output: Any
    provider_used: Optional[str]
    translation_model: Optional[str]
    engine: Optional[str] = None
    answering_provider: Optional[str] = None

    def provenance(self) -> dict:
        """The provider and model, as a result names them."""
        return {"provider_used": self.provider_used, "translation_model": self.translation_model}

    def for_engine(self, engine: str) -> "Translation":
        """This translation, as the consensus engine ``engine`` asked for it."""
        return Translation(
            kind=self.kind,
            output=self.output,
            provider_used=self.provider_used,
            translation_model=self.translation_model,
            engine=engine,
            answering_provider=self.answering_provider,
        )

    def entry(self) -> dict:
        """This translation as one entry of the audit record."""
        entry = {"kind": self.kind, **self.provenance(), "output": _plain(self.output)}
        if self.engine is not None:
            entry["engine"] = self.engine
        if self.answering_provider is not None:
            entry["answering_provider"] = self.answering_provider
        return entry


def translation_of(
    translator: Any, kind: str, output: Any, provider_key: Optional[str] = None, *, engine: Optional[str] = None
) -> Translation:
    """What ``translator`` just translated, with the provider and model its
    ``translation`` names (``TranslationLayer.translation``).

    Recording a translation never fails one that succeeded: an object that
    gives no ``Translation`` (a stand-in for the translation layer) still
    has its output kept, naming no provider or model, as
    ``translation_model`` names none for a provider QWED does not know.
    """
    record = getattr(translator, "translation", None)
    if callable(record):
        try:
            found = record(kind, output, provider_key, engine=engine)
        except Exception:  # naming the model must not fail the translation
            found = None
        if isinstance(found, Translation):
            return found
    return Translation(kind=kind, output=output, provider_used=None, translation_model=None, engine=engine)


def translation_in(error: BaseException) -> Optional[Translation]:
    """The translation an error carries, where the model's output was
    refused after it returned (``SecurityError.translation``), else None."""
    found = getattr(error, "translation", None)
    return found if isinstance(found, Translation) else None


def _plain(value: Any) -> Any:
    """A parsed model output (a pydantic task) as JSON values; other values
    as they are."""
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    return value


def _json_value(value: Any) -> Any:
    """``value`` as plain JSON values: text, numbers, booleans, None, lists,
    and objects with text keys. A NaN or infinity becomes the text JSON has
    no number for. Anything else (a set, an object) raises TypeError, so a
    record is never built from a display string that can differ between
    runs."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else _NON_FINITE[repr(value)]
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("an object key is not text")
        return {key: _json_value(item) for key, item in value.items()}
    raise TypeError(f"{type(value).__name__} is not a JSON value")


def _canonical(value: Any) -> str:
    return json.dumps(
        _json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def audit_record(translations: Iterable[Optional[Translation]]) -> Optional[str]:
    """The ``raw_llm_output`` of an audit row: every translation the verdict
    rests on, or None when no model translated.

    A record that cannot be written as JSON (a value JSON has no type for,
    keys that are not text, nesting deeper than the interpreter allows) is
    stored as that fact, so the audit row is still written.
    """
    entries = [translation.entry() for translation in translations if translation is not None]
    if not entries:
        return None
    try:
        text = _canonical({"translations": entries})
    except (TypeError, ValueError, RecursionError):
        return _canonical({"unserializable": True, "translations": len(entries)})
    if len(text) <= MAX_RECORD_CHARS:
        return text
    return _canonical({
        "truncated": True,
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("ascii")).hexdigest(),
        "preview": text[:PREVIEW_CHARS],
    })


def with_translations(
    dr: "DiagnosticResult", translations: List[Translation], *, provenance: bool = True
) -> "DiagnosticResult":
    """``dr`` carrying the translations it rests on (#578, #585).

    The record goes in ``raw_llm_output``, for the audit row only. With
    ``provenance`` and one translation, its provider and model are named in
    the developer fields too, as the natural-language and logic verdicts
    name theirs; a route whose verdict does not rest on the model (a fact
    advisory) names them where the model's output is shown instead. With no
    translation, ``dr`` is returned as it is.
    """
    if not translations:
        return dr
    fields = dr.developer_fields
    if provenance and len(translations) == 1:
        fields = {**fields, **translations[0].provenance()}
    return dr.with_audit_record(audit_record(translations), developer_fields=fields)
