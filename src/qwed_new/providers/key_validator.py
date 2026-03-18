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
    else:
        return False, "Key format invalid. Expected pattern like the provider's standard format."


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
    import httpx

    timeout = 5.0

    try:
        if provider_slug == "ollama":
            # Ollama: check if server is running
            url = (base_url or "http://localhost:11434").rstrip("/")
            # Strip /v1 if present for the tags endpoint
            if url.endswith("/v1"):
                url = url[:-3]
            resp = httpx.get(f"{url}/api/tags", timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "?") for m in data.get("models", [])]
                if models:
                    return True, f"Ollama running. Models: {', '.join(models[:5])}"
                return True, "Ollama running (no models pulled yet — run: ollama pull llama3)"
            return False, f"Ollama returned status {resp.status_code}"

        elif provider_slug == "openai":
            resp = httpx.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                return True, "Connected to OpenAI API."
            elif resp.status_code == 401:
                return False, "Authentication failed. Check your API key."
            return False, f"OpenAI returned status {resp.status_code}"

        elif provider_slug == "anthropic":
            # Anthropic doesn't have a /models endpoint — use a minimal message
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
            if resp.status_code == 200:
                return True, "Connected to Anthropic API."
            elif resp.status_code == 401:
                return False, "Authentication failed. Check your API key."
            return False, f"Anthropic returned status {resp.status_code}"

        elif provider_slug == "openai-compatible":
            # Generic: try GET /models on the custom endpoint
            url = (base_url or "").rstrip("/")
            if not url:
                return False, "Base URL is required for openai-compatible connection test."
            resp = httpx.get(
                f"{url}/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                return True, f"Connected to {url}"
            elif resp.status_code == 401:
                return False, "Authentication failed. Check your API key."
            return False, f"Endpoint returned status {resp.status_code}"

        else:
            return False, f"Connection test not implemented for '{provider_slug}'"

    except httpx.ConnectError:
        if provider_slug == "ollama":
            return False, "Cannot connect to Ollama. Is it running? (ollama serve)"
        return False, "Cannot connect to endpoint. Check URL and network."
    except httpx.TimeoutException:
        return False, "Connection timed out (5s). Check endpoint URL."
    except Exception as e:
        # NEVER leak the key in error messages
        logger.debug(f"Connection test error for {provider_slug}: {type(e).__name__}")
        return False, f"Connection test failed: {type(e).__name__}"
