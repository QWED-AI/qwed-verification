from unittest.mock import patch

import pytest

from qwed_new.core.translator import TranslationLayer
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.config import ProviderType
from qwed_new.core.translator import SecurityError

class TestTranslationLayerProviderFallback:
    @patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test-mock"})
    def test_get_provider_fallback_to_default(self):
        """Test that invalid provider falls back to default provider."""
        tl = TranslationLayer()
        # Mock default provider setting
        tl.default_provider = ProviderType.OPENAI
        
        # Requesting a non-existent provider key
        provider = tl._get_provider("invalid-provider-key-123")
        
        # It should fall back to OPENAI
        assert list(tl._providers.keys())[0] == ProviderType.OPENAI
        assert tl._providers[ProviderType.OPENAI] is provider


def test_validate_math_output_uses_generic_message_for_unsafe_expression():
    tl = TranslationLayer()
    task = MathVerificationTask(
        expression="2 + @",
        claimed_answer=2.0,
        reasoning="test",
        confidence=1.0,
    )

    with pytest.raises(SecurityError, match="Expression rejected by safety validator"):
        tl._validate_math_output(task)


def test_validate_math_output_uses_generic_message_for_long_expression():
    tl = TranslationLayer()
    task = MathVerificationTask(
        expression="1" * 501,
        claimed_answer=1.0,
        reasoning="test",
        confidence=1.0,
    )

    with pytest.raises(SecurityError, match="Expression rejected by safety validator"):
        tl._validate_math_output(task)


def test_validate_math_output_uses_generic_message_for_code_execution_tokens():
    tl = TranslationLayer()
    task = MathVerificationTask(
        expression="__import__('os')",
        claimed_answer=0.0,
        reasoning="test",
        confidence=1.0,
    )

    with pytest.raises(SecurityError, match="Expression rejected by safety validator"):
        tl._validate_math_output(task)


def test_validate_math_output_rejects_invalid_confidence_without_leaking_value():
    tl = TranslationLayer()
    task = MathVerificationTask(
        expression="2 + 2",
        claimed_answer=4.0,
        reasoning="test",
        confidence=1.0,
    )
    task.confidence = 1.5

    with pytest.raises(SecurityError, match="Invalid confidence value"):
        tl._validate_math_output(task)


def test_get_provider_allows_gemini_alias_without_unknown_fallback(monkeypatch):
    class _DummyAutoProvider:
        def translate(self, user_query: str):
            return MathVerificationTask(
                expression="2 + 2",
                claimed_answer=4.0,
                reasoning="test",
                confidence=1.0,
            )

    monkeypatch.setattr("qwed_new.core.translator.AutoShiftProvider", _DummyAutoProvider)

    tl = TranslationLayer()
    provider = tl._get_provider("gemini")

    assert isinstance(provider, _DummyAutoProvider)
    assert tl.last_resolved_provider == "gemini"
