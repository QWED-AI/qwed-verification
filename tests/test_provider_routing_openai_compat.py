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

    def translate_logic(self, user_query: str):
        raise NotImplementedError

    def refine_logic(self, user_query: str, previous_error: str):
        raise NotImplementedError

    def translate_stats(self, query: str, columns: list[str]) -> str:
        raise NotImplementedError

    def verify_fact(self, claim: str, context: str) -> dict:
        raise NotImplementedError

    def verify_image(self, image_bytes: bytes, claim: str) -> dict:
        raise NotImplementedError


def test_translation_layer_accepts_string_provider_key(monkeypatch):
    monkeypatch.setattr("qwed_new.core.translator.OpenAICompatProvider", _DummyCompatProvider)
    monkeypatch.setattr("qwed_new.core.translator.settings.ACTIVE_PROVIDER", "openai_compat")

    layer = TranslationLayer()
    task = layer.translate("two plus two", provider="openai_compat")

    assert task.claimed_answer == 4.0


def test_router_returns_string_for_preferred_provider(monkeypatch):
    monkeypatch.setattr("qwed_new.core.router.settings.ACTIVE_PROVIDER", "openai_compat")
    router = Router()

    assert router.route("logic puzzle", preferred_provider="openai_compat") == "openai_compat"
    assert router.route("logic puzzle", preferred_provider="openai-compatible") == "openai_compat"
