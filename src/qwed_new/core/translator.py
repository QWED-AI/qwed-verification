"""
Translation Layer: The Bridge.

This module now uses the Provider Pattern to support multiple LLMs.
It selects the active provider based on configuration.
"""

from qwed_new.config import settings, ProviderType
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.providers.base import LLMProvider
from qwed_new.providers.azure_openai import AzureOpenAIProvider
from qwed_new.providers.anthropic import AnthropicProvider
from qwed_new.providers.claude_opus import ClaudeOpusProvider
from qwed_new.providers.auto_shift import AutoShiftProvider
from qwed_new.providers.openai_direct import OpenAIDirectProvider
from qwed_new.providers.gemini_provider import GeminiProvider
from qwed_new.providers.openai_compat import OpenAICompatProvider
from qwed_new.providers.ollama_provider import OllamaProvider


class SecurityError(ValueError):
    """Raised when LLM output violates safety checks."""


SAFETY_VALIDATOR_REJECTION = "Expression rejected by safety validator"


class TranslationLayer:
    """
    The main entry point for translation.
    Delegates to the configured LLM provider.
    """
    
    def __init__(self):
        # Lazy loading: providers are instantiated on first use
        self._providers = {}
        self._provider_classes = {
            ProviderType.OPENAI.value: OpenAIDirectProvider,
            ProviderType.OPENAI_DIRECT.value: OpenAIDirectProvider,
            ProviderType.OPENAI_COMPAT.value: OpenAICompatProvider,
            ProviderType.AZURE_OPENAI.value: AzureOpenAIProvider,
            ProviderType.ANTHROPIC.value: AnthropicProvider,
            ProviderType.CLAUDE_OPUS.value: ClaudeOpusProvider,
            ProviderType.AUTO.value: AutoShiftProvider,
            ProviderType.GEMINI.value: GeminiProvider,
            ProviderType.OLLAMA.value: OllamaProvider,
        }
        # Default fallback
        configured_default = self._normalize_provider_key(
            getattr(settings.ACTIVE_PROVIDER, "value", settings.ACTIVE_PROVIDER)
        )
        self.default_provider = configured_default if configured_default in self._provider_classes else ProviderType.AUTO.value
        self.last_resolved_provider: str | None = None

    def _normalize_provider_key(self, provider_key: str | None = None) -> str | None:
        """Normalize provider key from enum/string into a stable identifier."""
        if provider_key is None:
            return None
        normalized = str(getattr(provider_key, "value", provider_key)).strip().lower()
        normalized = normalized.replace("-", "_").replace(" ", "_")
        aliases = {
            "openai_compatible": ProviderType.OPENAI_COMPAT.value,
            "openai_direct": ProviderType.OPENAI_DIRECT.value,
            "azure_openai": ProviderType.AZURE_OPENAI.value,
        }
        return aliases.get(normalized, normalized)
    
    def _get_provider(self, provider_key: str | None = None) -> LLMProvider:
        """Get the requested provider or default (lazy initialization)."""
        requested = self._normalize_provider_key(provider_key) or self.default_provider
        key = requested
        if key not in self._provider_classes:
            # Fallback to default if key is invalid/unknown.
            key = self.default_provider
        
        self.last_resolved_provider = key

        # Lazy instantiation: only create provider when first requested
        if key not in self._providers:
            self._providers[key] = self._provider_classes[key]()
        
        return self._providers[key]
    
    def _validate_math_output(self, task: MathVerificationTask) -> None:
        """
        Validate LLM output before using it.
        OWASP LLM05:2025 - Treat LLM outputs as untrusted input.
        """
        # 1. Check for code execution attempts in expression
        dangerous_keywords = ['exec', 'eval', '__import__', 'compile', 'open', 'file', '__']
        expr_lower = task.expression.lower()
        for keyword in dangerous_keywords:
            if keyword in expr_lower:
                raise SecurityError(SAFETY_VALIDATOR_REJECTION)
        
        # 2. Validate expression contains only safe characters
        import re
        # Allow: numbers, operators, parentheses, decimals, e/pi, common math functions
        safe_pattern = r'^[0-9+\-*/().epi \ssqrtsincostandlogexpabsln]+$'
        if not re.match(safe_pattern, task.expression.replace(' ', ''), re.IGNORECASE):
            raise SecurityError(SAFETY_VALIDATOR_REJECTION)
        
        # 3. Check for excessive length (possible DoS)
        if len(task.expression) > 500:
            raise SecurityError(SAFETY_VALIDATOR_REJECTION)
        
        # 4. Validate confidence is in valid range
        if not (0.0 <= task.confidence <= 1.0):
            raise SecurityError("Invalid confidence value")

    def translate(self, user_query: str, provider: str | None = None) -> MathVerificationTask:
        """
        Translate query using the specified provider.
        Includes output verification for security.
        """
        task = self._get_provider(provider).translate(user_query)
        
        # ADD: Output verification (OWASP LLM05:2025)
        self._validate_math_output(task)
        
        return task

    def translate_logic(self, user_query: str, provider: str | None = None):
        """
        Translate logic query using the specified provider.
        """
        return self._get_provider(provider).translate_logic(user_query)

    def refine_logic(self, user_query: str, previous_error: str, provider: str | None = None):
        """
        Refine logic query based on feedback.
        """
        return self._get_provider(provider).refine_logic(user_query, previous_error)

    def translate_stats(self, query: str, columns: list[str], provider: str | None = None) -> str:
        """
        Generate Python code for statistical verification.
        """
        return self._get_provider(provider).translate_stats(query, columns)

    def verify_fact(self, claim: str, context: str, provider: str | None = None) -> dict:
        """
        Verify a claim against a context.
        """
        return self._get_provider(provider).verify_fact(claim, context)
