"""
Tests for router.py — Provider routing logic.

Covers: Router.__init__, route() with valid/invalid/unknown providers,
slug normalization, heuristic routing, default fallback.
"""

from unittest.mock import patch


class TestRouter:
    @patch("qwed_new.core.router.settings")
    def test_default_provider(self, mock_settings):
        mock_settings.ACTIVE_PROVIDER = "openai"
        from qwed_new.core.router import Router
        r = Router()
        assert r.default_provider == "openai"

    @patch("qwed_new.core.router.settings")
    def test_route_with_valid_provider(self, mock_settings):
        mock_settings.ACTIVE_PROVIDER = "openai"
        from qwed_new.core.router import Router
        r = Router()
        result = r.route("test query", preferred_provider="ollama")
        result_str = getattr(result, "value", result)
        assert result_str == "ollama"

    @patch("qwed_new.core.router.settings")
    def test_route_unknown_provider_fallback(self, mock_settings):
        """Unknown provider should fall back to default, not raw string."""
        mock_settings.ACTIVE_PROVIDER = "openai"
        from qwed_new.core.router import Router
        r = Router()
        result = r.route("test query", preferred_provider="nonexistent-typo")
        result_str = getattr(result, "value", result)
        assert result_str == "openai"

    @patch("qwed_new.core.router.settings")
    def test_route_slug_normalization(self, mock_settings):
        """openai-compatible should normalize to openai_compat ProviderType."""
        mock_settings.ACTIVE_PROVIDER = "openai"
        from qwed_new.core.router import Router
        r = Router()
        result = r.route("test", preferred_provider="openai-compatible")
        result_str = getattr(result, "value", result)
        assert result_str == "openai_compat"

    @patch("qwed_new.core.router.settings")
    def test_route_no_preferred(self, mock_settings):
        """Without preferred, returns default provider."""
        mock_settings.ACTIVE_PROVIDER = "anthropic"
        from qwed_new.core.router import Router
        r = Router()
        result = r.route("calculate 2+2")
        result_str = getattr(result, "value", result)
        assert result_str == "anthropic"

    @patch("qwed_new.core.router.settings")
    def test_route_math_keywords(self, mock_settings):
        """Math keywords should still use default provider."""
        mock_settings.ACTIVE_PROVIDER = "openai"
        from qwed_new.core.router import Router
        r = Router()
        result = r.route("calculate the equation for x")
        result_str = getattr(result, "value", result)
        assert result_str == "openai"
