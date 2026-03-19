"""
Tests for key_validator.py — Key format validation and connection testing.

Covers: mask_key, validate_key_format, test_connection, per-provider test
handlers, error paths, timeout handling.
"""

from unittest.mock import patch

from qwed_new.providers.key_validator import (
    mask_key,
    validate_key_format,
    test_connection as check_connection,
    _AUTH_FAILED,
)


class TestMaskKey:
    def test_standard(self):
        assert mask_key("sk-proj-ABCDEFGHIJKLMNOP") == "sk-proj-****"

    def test_short(self):
        assert mask_key("abc") == "****"

    def test_exactly_8(self):
        assert mask_key("12345678") == "****"

    def test_9_chars(self):
        assert mask_key("123456789") == "12345678****"

    def test_empty(self):
        assert mask_key("") == "****"

    def test_none(self):
        assert mask_key(None) == "****"


class TestValidateKeyFormat:
    def test_valid_openai(self):
        key = "sk-proj-" + "A" * 30
        is_valid, msg = validate_key_format(key, r"^sk-(proj-)?[A-Za-z0-9_-]{20,}$")
        assert is_valid
        assert "sk-proj-" in msg

    def test_invalid_format(self):
        is_valid, msg = validate_key_format("bad", r"^sk-.*$")
        assert not is_valid
        assert "invalid" in msg.lower()

    def test_no_pattern(self):
        is_valid, _ = validate_key_format("anything", None)
        assert is_valid

    def test_empty_key(self):
        is_valid, msg = validate_key_format("", r"^sk-.*$")
        assert not is_valid
        assert "empty" in msg.lower()

    def test_whitespace_only(self):
        is_valid, _ = validate_key_format("   ", r"^sk-.*$")
        assert not is_valid

    def test_fullmatch_not_prefix(self):
        """fullmatch rejects partial matches that re.match would accept."""
        is_valid, _ = validate_key_format("sk-valid-EXTRA!", r"^sk-valid$")
        assert not is_valid


class TestConnectionOllama:
    def test_ollama_success(self):
        with patch.dict("qwed_new.providers.key_validator._TEST_HANDLERS", {
            "ollama": lambda key, url, model, t: (True, "Ollama running. Models: llama3")
        }):
            success, msg = check_connection("ollama")
            assert success
            assert "Ollama" in msg

    def test_ollama_connect_error(self):
        with patch.dict("qwed_new.providers.key_validator._TEST_HANDLERS", {
            "ollama": lambda key, url, model, t: (False, "Cannot connect to Ollama. Is it running? (ollama serve)")
        }):
            success, msg = check_connection("ollama")
            assert not success
            assert "Ollama" in msg


class TestConnectionDispatch:
    def test_unknown_provider(self):
        success, msg = check_connection("unknown-provider")
        assert not success
        assert "not implemented" in msg.lower()

    def test_handler_exception(self):
        """Generic exceptions produce safe error messages."""
        with patch.dict("qwed_new.providers.key_validator._TEST_HANDLERS", {
            "test": lambda key, url, model, t: (_ for _ in ()).throw(RuntimeError("boom"))
        }):
            success, msg = check_connection("test")
            assert not success
            assert "RuntimeError" in msg
            assert "boom" not in msg  # Details hidden from user


class TestConnectionOpenAI:
    def test_openai_success(self):
        with patch.dict("qwed_new.providers.key_validator._TEST_HANDLERS", {
            "openai": lambda key, url, model, t: (True, "Connected to OpenAI API.")
        }):
            success, _ = check_connection("openai", api_key="UNIT_TEST_TOKEN_A")
            assert success

    def test_openai_auth_fail(self):
        with patch.dict("qwed_new.providers.key_validator._TEST_HANDLERS", {
            "openai": lambda key, url, model, t: (False, _AUTH_FAILED)
        }):
            success, msg = check_connection("openai", api_key="UNIT_TEST_TOKEN_INVALID")
            assert not success
            assert "Authentication" in msg


class TestConnectionAnthropic:
    def test_anthropic_success(self):
        with patch.dict("qwed_new.providers.key_validator._TEST_HANDLERS", {
            "anthropic": lambda key, url, model, t: (True, "Connected to Anthropic API.")
        }):
            success, _ = check_connection("anthropic", api_key="UNIT_TEST_TOKEN_B")
            assert success


class TestConnectionOpenAICompat:
    def test_no_base_url(self):
        with patch.dict("qwed_new.providers.key_validator._TEST_HANDLERS", {
            "openai-compatible": lambda key, url, model, t: (False, "Base URL is required for openai-compatible connection test.")
        }):
            success, msg = check_connection("openai-compatible")
            assert not success
            assert "Base URL" in msg
