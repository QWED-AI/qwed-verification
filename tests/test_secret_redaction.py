"""
Secret Redaction Tests — Verify API keys NEVER leak in exceptions, logs, or repr.

Mandatory security gate before merge (per reviewer feedback).
"""

import pytest
import re
from qwed_new.providers.key_validator import mask_key, validate_key_format
from qwed_new.providers.key_validator import test_connection as check_connection
from qwed_new.providers.registry import PROVIDER_REGISTRY, get_provider


class TestMaskKey:
    """Test that mask_key never exposes full keys."""

    def test_mask_standard_key(self):
        """Standard OpenAI key is masked properly."""
        key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        masked = mask_key(key)
        assert masked == "sk-proj-****"
        assert key not in masked

    def test_mask_short_key(self):
        """Short keys become fully masked."""
        assert mask_key("abc") == "****"
        assert mask_key("12345678") == "****"

    def test_mask_empty(self):
        """Empty/None keys are safe."""
        assert mask_key("") == "****"
        assert mask_key(None) == "****"

    def test_mask_anthropic_key(self):
        """Anthropic key is masked."""
        key = "sk-ant-api03-abcdefghijklmnop"
        masked = mask_key(key)
        assert masked == "sk-ant-a****"
        assert key not in masked

    def test_mask_do_key(self):
        """DigitalOcean key is masked."""
        key = "sk-do-vrDHX9xzTTVfXXJrHqpHEefsn5mHcPLyGWVydX_vfFLuABLx61svVQyBOc"
        masked = mask_key(key)
        assert "vrDHX9xzTTVfXXJr" not in masked  # No raw key content beyond 8 chars
        assert masked.endswith("****")


class TestKeyFormatValidation:
    """Test key format regex patterns."""

    def test_openai_valid_key(self):
        """Valid OpenAI key format passes."""
        provider = get_provider("openai")
        is_valid, _ = validate_key_format("sk-proj-abcdefghijklmnopqrstuv", provider.key_pattern)
        assert is_valid

    def test_openai_invalid_key(self):
        """Invalid OpenAI key format fails."""
        provider = get_provider("openai")
        is_valid, _ = validate_key_format("invalid-key-format", provider.key_pattern)
        assert not is_valid

    def test_anthropic_valid_key(self):
        """Valid Anthropic key format passes."""
        provider = get_provider("anthropic")
        is_valid, _ = validate_key_format("sk-ant-abcdefghijklmnopqrstuv", provider.key_pattern)
        assert is_valid

    def test_anthropic_invalid_key(self):
        """Invalid Anthropic key format fails."""
        provider = get_provider("anthropic")
        is_valid, _ = validate_key_format("not-an-anthropic-key", provider.key_pattern)
        assert not is_valid

    def test_no_pattern_accepts_any(self):
        """Providers without patterns accept any non-empty string."""
        is_valid, _ = validate_key_format("anything-goes-here", None)
        assert is_valid

    def test_empty_key_rejected(self):
        """Empty keys always rejected."""
        is_valid, _ = validate_key_format("", r"^sk-.*$")
        assert not is_valid

    def test_validation_message_never_contains_key(self):
        """Validation error messages must NOT contain the full key."""
        test_key = "sk-proj-REALSECRETKEY12345678901234567890"
        _, msg = validate_key_format(test_key, r"^sk-(proj-)?[A-Za-z0-9_-]{20,}$")
        assert "REALSECRETKEY" not in msg


class TestSecretRedactionInExceptions:
    """Ensure exceptions from providers never contain API keys."""

    def test_openai_direct_exception_no_key(self):
        """OpenAI provider ValueError must not contain the API key."""
        from qwed_new.providers.openai_direct import OpenAIDirectProvider

        fake_key = "sk-proj-TOPSECRET123456789012345678"
        try:
            # This will fail because the key is invalid — but the error
            # message must NOT contain the key
            provider = OpenAIDirectProvider(api_key=fake_key, model="gpt-fake")
            provider.translate("test query")
        except Exception as e:
            error_msg = str(e)
            assert "TOPSECRET" not in error_msg, f"API key leaked in exception: {error_msg}"

    def test_connection_test_exception_no_key(self):
        """Connection test errors must not contain API key."""
        fake_key = "sk-proj-SUPERSECRETKEY99999999999"
        success, msg = check_connection(
            provider_slug="openai",
            api_key=fake_key,
            base_url=None,
        )
        # Whether success or failure, message must not contain full key
        assert "SUPERSECRETKEY" not in msg


class TestProviderRegistry:
    """Test the provider registry is properly structured."""

    def test_all_release1_providers_exist(self):
        """All Release 1 providers are registered."""
        assert "openai" in PROVIDER_REGISTRY
        assert "anthropic" in PROVIDER_REGISTRY
        assert "ollama" in PROVIDER_REGISTRY
        assert "openai-compatible" in PROVIDER_REGISTRY

    def test_ollama_is_local(self):
        """Ollama is marked as local (no API key needed)."""
        ollama = get_provider("ollama")
        assert ollama.is_local is True

    def test_openai_has_key_pattern(self):
        """OpenAI has a regex pattern for key validation."""
        openai = get_provider("openai")
        assert openai.key_pattern is not None
        assert re.match(openai.key_pattern, "sk-proj-abcdefghij1234567890")

    def test_unknown_provider_raises(self):
        """Unknown provider slug raises KeyError."""
        with pytest.raises(KeyError):
            get_provider("nonexistent-provider")

    def test_env_vars_have_names(self):
        """All provider env vars have a name."""
        for slug, meta in PROVIDER_REGISTRY.items():
            for env_var in meta.env_vars:
                assert env_var.name, f"Provider {slug} has env var without name"
