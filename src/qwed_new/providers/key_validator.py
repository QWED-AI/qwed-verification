"""
Key Validator — Format validation + optional connection test.

Security rules:
  - NEVER log full API keys (mask to first 8 chars)
  - NEVER include keys in exception messages
  - Connection tests use 5s timeout
"""

import re
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

# Shared error messages
_AUTH_FAILED = "Authentication failed. Check your API key."
_TIMEOUT_MSG = "Connection timed out (5s). Check endpoint URL."
_CONNECT_FAIL = "Cannot connect to endpoint. Check URL and network."


def mask_key(key: str) -> str:
    """Mask API key for safe display. Shows first 8 chars + ****."""
    if not key or len(key) <= 8:
        return "****"
    return key[:8] + "****"


def validate_key_format(key: str, pattern: Optional[str]) -> Tuple[bool, str]:
    """
    Stage 1: Regex format validation (no network call).

    Returns:
        (is_valid, message)
    """
    if not key or not key.strip():
        return False, "API key cannot be empty."

    key = key.strip()

    if pattern is None:
        # No pattern defined (e.g., generic endpoint) — accept anything non-empty
        return True, f"Key accepted: {mask_key(key)}"

    if re.fullmatch(pattern, key):
        return True, f"Key format valid: {mask_key(key)}"

    return False, "Key format invalid. Expected pattern like the provider's standard format."


def _test_ollama(base_url: Optional[str], timeout: float) -> Tuple[bool, str]:
    """Test Ollama server connectivity."""
    import httpx

    url = (base_url or "http://localhost:11434").rstrip("/")
    if url.endswith("/v1"):
        url = url[:-3]
    try:
        resp = httpx.get(f"{url}/api/tags", timeout=timeout)
    except httpx.ConnectError:
        return False, "Cannot connect to Ollama. Is it running? (ollama serve)"
    except httpx.TimeoutException:
        return False, _TIMEOUT_MSG

    if resp.status_code != 200:
        return False, f"Ollama returned status {resp.status_code}"

    data = resp.json()
    models = [m.get("name", "?") for m in data.get("models", [])]
    if models:
        return True, f"Ollama running. Models: {', '.join(models[:5])}"
    return True, "Ollama running (no models pulled yet — run: ollama pull llama3)"


def _test_openai(api_key: Optional[str], timeout: float) -> Tuple[bool, str]:
    """Test OpenAI API connectivity."""
    import httpx

    try:
        resp = httpx.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
    except httpx.ConnectError:
        return False, _CONNECT_FAIL
    except httpx.TimeoutException:
        return False, _TIMEOUT_MSG

    if resp.status_code == 200:
        return True, "Connected to OpenAI API."
    if resp.status_code == 401:
        return False, _AUTH_FAILED
    return False, f"OpenAI returned status {resp.status_code}"


def _test_anthropic(
    api_key: Optional[str], model: Optional[str], timeout: float
) -> Tuple[bool, str]:
    """Test Anthropic API connectivity."""
    import httpx

    try:
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model or "claude-sonnet-4-20250514",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "hi"}],
            },
            timeout=timeout,
        )
    except httpx.ConnectError:
        return False, _CONNECT_FAIL
    except httpx.TimeoutException:
        return False, _TIMEOUT_MSG

    if resp.status_code == 200:
        return True, "Connected to Anthropic API."
    if resp.status_code == 401:
        return False, _AUTH_FAILED
    return False, f"Anthropic returned status {resp.status_code}"


def _test_openai_compat(
    api_key: Optional[str], base_url: Optional[str], timeout: float
) -> Tuple[bool, str]:
    """Test OpenAI-compatible endpoint connectivity."""
    import httpx

    url = (base_url or "").rstrip("/")
    if not url:
        return False, "Base URL is required for openai-compatible connection test."

    try:
        resp = httpx.get(
            f"{url}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
    except httpx.ConnectError:
        return False, _CONNECT_FAIL
    except httpx.TimeoutException:
        return False, _TIMEOUT_MSG

    if resp.status_code == 200:
        return True, f"Connected to {url}"
    if resp.status_code == 401:
        return False, _AUTH_FAILED
    return False, f"Endpoint returned status {resp.status_code}"


# Provider -> test function mapping
_TEST_HANDLERS = {
    "ollama": lambda key, url, model, t: _test_ollama(url, t),
    "openai": lambda key, url, model, t: _test_openai(key, t),
    "anthropic": lambda key, url, model, t: _test_anthropic(key, model, t),
    "openai-compatible": lambda key, url, model, t: _test_openai_compat(key, url, t),
}


def test_connection(
    provider_slug: str,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Stage 2: Optional lightweight connection test.

    Tests by hitting a safe read-only endpoint (e.g., GET /models).
    Uses httpx with 5s timeout. NEVER logs the full key.

    Returns:
        (success, message)
    """
    timeout = 5.0

    handler = _TEST_HANDLERS.get(provider_slug)
    if not handler:
        return False, f"Connection test not implemented for '{provider_slug}'"

    try:
        return handler(api_key, base_url, model, timeout)
    except Exception as e:
        # NEVER leak the key in error messages
        logger.debug("Connection test error for %s: %s", provider_slug, type(e).__name__)
        return False, f"Connection test failed: {type(e).__name__}"
