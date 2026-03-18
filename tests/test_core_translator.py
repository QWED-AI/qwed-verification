import pytest
from unittest.mock import patch, MagicMock

from qwed_new.core.translator import TranslationLayer
from qwed_new.config import ProviderType

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
