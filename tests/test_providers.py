"""
Tests for provider modules — OllamaProvider, OpenAIDirectProvider, OpenAICompatProvider.

Uses monkeypatching to ensure deterministic tests without network calls.
Covers: initialization, API key handling, exception sanitization, translate/verify methods.
"""

import pytest
from unittest.mock import patch, MagicMock

from qwed_new.providers.registry import PROVIDER_REGISTRY, get_provider, list_providers, AuthType


# ── Registry Tests ──────────────────────────────────────────

class TestProviderRegistry:
    def test_all_release1_providers(self):
        assert "openai" in PROVIDER_REGISTRY
        assert "anthropic" in PROVIDER_REGISTRY
        assert "ollama" in PROVIDER_REGISTRY
        assert "openai-compatible" in PROVIDER_REGISTRY

    def test_get_provider_valid(self):
        p = get_provider("openai")
        assert p.slug == "openai"
        assert p.auth_type == AuthType.API_KEY

    def test_get_provider_invalid(self):
        with pytest.raises(KeyError, match="Unknown provider"):
            get_provider("nonexistent")

    def test_list_providers(self):
        providers = list_providers()
        assert len(providers) == 4
        slugs = [p.slug for p in providers]
        assert "openai" in slugs

    def test_ollama_is_local(self):
        p = get_provider("ollama")
        assert p.is_local is True
        assert p.auth_type == AuthType.LOCAL

    def test_env_vars_have_names(self):
        for slug, meta in PROVIDER_REGISTRY.items():
            for ev in meta.env_vars:
                assert ev.name, f"Provider {slug} has env var without name"

    def test_openai_key_pattern(self):
        import re
        p = get_provider("openai")
        assert p.key_pattern is not None
        fake_key = "sk-proj-" + "A" * 30
        assert re.fullmatch(p.key_pattern, fake_key)

    def test_anthropic_key_pattern(self):
        import re
        p = get_provider("anthropic")
        fake_key = "sk-ant-" + "B" * 30
        assert re.fullmatch(p.key_pattern, fake_key)


# ── Ollama Provider Tests ──────────────────────────────────

class TestOllamaProvider:
    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_init_no_key(self, mock_openai_cls):
        """Ollama initializes with empty string api_key, not None."""
        from qwed_new.providers.ollama_provider import OllamaProvider
        with patch.dict("os.environ", {}, clear=False):
            OllamaProvider()
        # Verify OpenAI was called with empty string, not None
        call_kwargs = mock_openai_cls.call_args
        assert call_kwargs is not None
        assert call_kwargs.kwargs.get("api_key") == "" or call_kwargs[1].get("api_key") == ""

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_init_with_key(self, mock_openai_cls):
        """Ollama uses env var key when set."""
        from qwed_new.providers.ollama_provider import OllamaProvider
        with patch.dict("os.environ", {"OLLAMA_API_KEY": "test-ollama-key-12345"}, clear=False):
            OllamaProvider()
        call_kwargs = mock_openai_cls.call_args
        assert call_kwargs.kwargs.get("api_key") == "test-ollama-key-12345" or call_kwargs[1].get("api_key") == "test-ollama-key-12345"

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_translate_error_sanitized(self, mock_openai_cls):
        """Translation errors are sanitized — no raw exception details."""
        from qwed_new.providers.ollama_provider import OllamaProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("SECRET_KEY_LEAKED_HERE")

        provider = OllamaProvider()
        with pytest.raises(ValueError) as exc_info:
            provider.translate("test")
        assert "SECRET_KEY_LEAKED_HERE" not in str(exc_info.value)

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_translate_logic_error_sanitized(self, mock_openai_cls):
        """Logic translation errors sanitized."""
        from qwed_new.providers.ollama_provider import OllamaProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("INTERNAL_ERROR")

        provider = OllamaProvider()
        with pytest.raises(ValueError) as exc_info:
            provider.translate_logic("test logic")
        assert "INTERNAL_ERROR" not in str(exc_info.value)


# ── OpenAI Direct Provider Tests ───────────────────────────

class TestOpenAIDirectProvider:
    def test_init_no_key_raises(self):
        """Missing API key raises clear error."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="API key not found"):
                OpenAIDirectProvider()

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_translate_error_sanitized(self, mock_openai_cls):
        """Translation errors never expose raw details."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("RAW_SDK_ERROR")

        provider = OpenAIDirectProvider(api_key="sk-proj-" + "A" * 30)
        with pytest.raises(ValueError) as exc_info:
            provider.translate("test")
        assert "RAW_SDK_ERROR" not in str(exc_info.value)

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_translate_stats_error_sanitized(self, mock_openai_cls):
        """Stats translation errors sanitized."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("STATS_ERROR")

        provider = OpenAIDirectProvider(api_key="sk-proj-" + "B" * 30)
        with pytest.raises(ValueError) as exc_info:
            provider.translate_stats("query", ["col1", "col2"])
        assert "STATS_ERROR" not in str(exc_info.value)

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_verify_fact_error_sanitized(self, mock_openai_cls):
        """Fact verification errors sanitized."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("FACT_ERROR")

        provider = OpenAIDirectProvider(api_key="sk-proj-" + "C" * 30)
        with pytest.raises(ValueError) as exc_info:
            provider.verify_fact("claim", "context")
        assert "FACT_ERROR" not in str(exc_info.value)

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_verify_image_jpeg(self, mock_openai_cls):
        """Image verification detects JPEG MIME type."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"verdict": "SUPPORTED", "reasoning": "test", "confidence": 0.9}'
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAIDirectProvider(api_key="sk-proj-" + "D" * 30)
        # JPEG magic bytes
        result = provider.verify_image(b"\xff\xd8\xff\xe0" + b"\x00" * 100, "test claim")
        assert result["verdict"] == "SUPPORTED"
        # Verify the data URI uses image/jpeg
        call_args = mock_client.chat.completions.create.call_args
        messages = call_args.kwargs.get("messages") or call_args[1].get("messages")
        user_content = messages[1]["content"]
        image_url = user_content[0]["image_url"]["url"]
        assert "data:image/jpeg;base64," in image_url

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_verify_image_png(self, mock_openai_cls):
        """Image verification detects PNG MIME type."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"verdict": "SUPPORTED", "reasoning": "test", "confidence": 0.9}'
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAIDirectProvider(api_key="sk-proj-" + "E" * 30)
        # PNG magic bytes
        result = provider.verify_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100, "test claim")
        assert result["verdict"] == "SUPPORTED"

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_verify_image_unsupported_format(self, mock_openai_cls):
        """Unsupported image format returns ERROR."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider
        provider = OpenAIDirectProvider(api_key="sk-proj-" + "F" * 30)
        result = provider.verify_image(b"not-an-image-format", "test claim")
        assert result["verdict"] == "ERROR"
        assert "Unsupported" in result["reasoning"]


# ── OpenAI Compat Provider Tests ───────────────────────────

class TestOpenAICompatProvider:
    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_init_no_key_uses_dummy(self, mock_openai_cls):
        """No API key → uses 'dummy' for no-auth endpoints."""
        from qwed_new.providers.openai_compat import OpenAICompatProvider
        with patch.dict("os.environ", {}, clear=True):
            OpenAICompatProvider(base_url="http://localhost:8080/v1")
        call_kwargs = mock_openai_cls.call_args
        assert call_kwargs.kwargs.get("api_key") == "dummy" or call_kwargs[1].get("api_key") == "dummy"

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_init_with_key(self, mock_openai_cls):
        """Provided key is passed through."""
        from qwed_new.providers.openai_compat import OpenAICompatProvider
        OpenAICompatProvider(base_url="http://example.com/v1", api_key="test-fake-key-12345")
        call_kwargs = mock_openai_cls.call_args
        assert call_kwargs.kwargs.get("api_key") == "test-fake-key-12345" or call_kwargs[1].get("api_key") == "test-fake-key-12345"

    def test_init_no_base_url_raises(self):
        """Missing base URL raises clear error."""
        from qwed_new.providers.openai_compat import OpenAICompatProvider
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="Base URL not found"):
                OpenAICompatProvider()

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_translate_error_sanitized(self, mock_openai_cls):
        """Translation errors sanitized."""
        from qwed_new.providers.openai_compat import OpenAICompatProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("COMPAT_ERROR")

        provider = OpenAICompatProvider(base_url="http://localhost/v1", api_key="test-key-xyz")
        with pytest.raises(ValueError) as exc_info:
            provider.translate("test")
        assert "COMPAT_ERROR" not in str(exc_info.value)

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_verify_image_not_supported(self, mock_openai_cls):
        """Image verification returns NOT_SUPPORTED."""
        from qwed_new.providers.openai_compat import OpenAICompatProvider
        provider = OpenAICompatProvider(base_url="http://localhost/v1", api_key="test-key-xyz")
        result = provider.verify_image(b"image", "claim")
        assert result["verdict"] == "NOT_SUPPORTED"

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_translate_stats_error_sanitized(self, mock_openai_cls):
        """Stats translation errors sanitized."""
        from qwed_new.providers.openai_compat import OpenAICompatProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("STATS_COMPAT_ERR")

        provider = OpenAICompatProvider(base_url="http://localhost/v1", api_key="test-key-xyz")
        with pytest.raises(ValueError) as exc_info:
            provider.translate_stats("query", ["col"])
        assert "STATS_COMPAT_ERR" not in str(exc_info.value)

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_json_parse_error_sanitized(self, mock_openai_cls):
        """JSON parse errors don't leak raw exception text."""
        from qwed_new.providers.openai_compat import OpenAICompatProvider
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        # Mock response that returns invalid JSON
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "not valid json at all"
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAICompatProvider(base_url="http://localhost/v1", api_key="test-key-xyz")
        with pytest.raises(ValueError) as exc_info:
            provider.translate("test query")
        error_msg = str(exc_info.value)
        # Should NOT contain raw json.JSONDecodeError details
        assert "Expecting value" not in error_msg
