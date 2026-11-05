from typing import Any

import pytest

from qwed_new.config import ProviderType
from qwed_new.core.router import Router
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.translator import TranslationLayer


class _DummyCompatProvider:
    def translate(self, user_query: str) -> MathVerificationTask:
        return MathVerificationTask(
            expression="2 + 2",
            claimed_answer=4.0,
            reasoning=f"translated: {user_query}",
            confidence=1.0,
        )

    def translate_logic(self, user_query: str) -> dict[str, str]:
        return {"logic": user_query}

    def refine_logic(self, user_query: str, previous_error: str) -> dict[str, str]:
        return {"refined": user_query, "error": previous_error}

    def translate_stats(self, query: str, columns: list[str]) -> str:
        return f"{query}:{','.join(columns)}"

    def verify_fact(self, claim: str, context: str) -> dict:
        return {"claim": claim, "context": context}

    def verify_image(self, image_bytes: bytes, claim: str) -> dict:
        raise NotImplementedError


class _DummyDirectProvider(_DummyCompatProvider):
    def verify_fact(self, claim: str, context: str) -> dict[str, Any]:
        return {"claim": claim, "context": context}


def test_provider_enum_includes_openai_compat():
    assert ProviderType.OPENAI_COMPAT.value == "openai_compat"


def test_translation_layer_supports_openai_compat(monkeypatch):
    monkeypatch.setattr("qwed_new.core.translator.OpenAICompatProvider", _DummyCompatProvider)
    monkeypatch.setattr("qwed_new.core.translator.settings.ACTIVE_PROVIDER", "openai_compat")

    layer = TranslationLayer()
    task = layer.translate("two plus two", provider="openai_compat")
    assert task.expression == "2 + 2"
    assert task.claimed_answer == 4.0


def test_translation_layer_normalize_none_returns_none(monkeypatch):
    monkeypatch.setattr("qwed_new.core.translator.OpenAICompatProvider", _DummyCompatProvider)
    monkeypatch.setattr("qwed_new.core.translator.settings.ACTIVE_PROVIDER", "openai_compat")

    layer = TranslationLayer()

    assert layer._normalize_provider_key(None) is None


def test_translation_layer_openai_uses_direct_provider(monkeypatch):
    monkeypatch.setattr("qwed_new.core.translator.OpenAIDirectProvider", _DummyDirectProvider)
    monkeypatch.setattr("qwed_new.core.translator.settings.ACTIVE_PROVIDER", "openai")

    layer = TranslationLayer()
    task = layer.translate("2+2", provider="openai")

    assert task.claimed_answer == 4.0
    assert layer.last_resolved_provider == "openai"


def test_translation_layer_normalizes_openai_compatible_alias(monkeypatch):
    monkeypatch.setattr("qwed_new.core.translator.OpenAICompatProvider", _DummyCompatProvider)
    monkeypatch.setattr("qwed_new.core.translator.settings.ACTIVE_PROVIDER", "auto")

    layer = TranslationLayer()
    task = layer.translate("2+2", provider=" OpenAI-Compatible ")

    assert task.claimed_answer == 4.0
    assert layer.last_resolved_provider == "openai_compat"


def test_translation_layer_refuses_an_invalid_provider(monkeypatch):
    monkeypatch.setattr("qwed_new.core.translator.OpenAICompatProvider", _DummyCompatProvider)
    monkeypatch.setattr("qwed_new.core.translator.settings.ACTIVE_PROVIDER", "openai_compat")

    layer = TranslationLayer()
    # The configured provider does not stand in for the one the request names (#574).
    with pytest.raises(ValueError, match="The request names a provider QWED does not know"):
        layer.translate("2+2", provider=" definitely-not-valid ")

    assert layer.last_resolved_provider == "unknown"


def test_translation_layer_delegates_logic_stats_and_fact_calls(monkeypatch):
    monkeypatch.setattr("qwed_new.core.translator.OpenAICompatProvider", _DummyCompatProvider)
    monkeypatch.setattr("qwed_new.core.translator.settings.ACTIVE_PROVIDER", "openai_compat")

    layer = TranslationLayer()

    assert layer.translate_logic("x > 5", provider="openai_compat") == {"logic": "x > 5"}
    assert layer.refine_logic("x > 5", "missing var", provider="openai_compat") == {
        "refined": "x > 5",
        "error": "missing var",
    }
    assert layer.translate_stats("mean", ["a", "b"], provider="openai_compat") == "mean:a,b"
    assert layer.verify_fact("sky is blue", "context", provider="openai_compat") == {
        "claim": "sky is blue",
        "context": "context",
    }


def test_router_respects_default_provider_for_logic_queries(monkeypatch):
    monkeypatch.setattr("qwed_new.core.router.settings.ACTIVE_PROVIDER", "openai_compat")
    router = Router()

    assert router.route("solve x > 5 and x < 3") == "openai_compat"
    # The query's wording does not select a provider (#574).
    assert router.route("write a short story about moon") == "openai_compat"


def test_router_normalizes_preferred_provider_alias(monkeypatch):
    monkeypatch.setattr("qwed_new.core.router.settings.ACTIVE_PROVIDER", "auto")
    router = Router()

    assert router.route("anything", preferred_provider=" OpenAI-Compatible ") == "openai_compat"


def test_router_labels_an_invalid_preferred_provider_unknown(monkeypatch):
    monkeypatch.setattr("qwed_new.core.router.settings.ACTIVE_PROVIDER", "openai_compat")
    router = Router()

    # Not the configured provider, and not the request's own text (#574).
    assert router.route("anything", preferred_provider="definitely-not-a-provider") == "unknown"
