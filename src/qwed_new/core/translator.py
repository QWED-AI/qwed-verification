"""
Translation Layer: The Bridge.

This module now uses the Provider Pattern to support multiple LLMs.
It selects the active provider based on configuration.
"""

from typing import Optional

from qwed_new.config import settings, ProviderType
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.providers.base import LLMProvider
from qwed_new.providers.azure_openai import AzureOpenAIProvider
from qwed_new.providers.anthropic import AnthropicProvider
from qwed_new.providers.claude_opus import ClaudeOpusProvider
from qwed_new.providers.auto_shift import AutoShiftProvider
from qwed_new.providers.openai_direct import OpenAIDirectProvider
from qwed_new.providers.openai_compat import OpenAICompatProvider
from qwed_new.providers.ollama_provider import OllamaProvider

class TranslationLayer:
    """
    The main entry point for translation.
    Delegates to the configured LLM provider.
    """
    
    def __init__(self):
        # Lazy loading: providers are instantiated on first use
        self._providers = {}
        self._provider_classes = {
            ProviderType.AZURE_OPENAI.value: AzureOpenAIProvider,
            ProviderType.ANTHROPIC.value: AnthropicProvider,
            ProviderType.CLAUDE_OPUS.value: ClaudeOpusProvider,
            ProviderType.AUTO.value: AutoShiftProvider,
            ProviderType.OPENAI.value: OpenAIDirectProvider,
            ProviderType.OPENAI_DIRECT.value: OpenAIDirectProvider,
            ProviderType.OLLAMA.value: OllamaProvider,
            ProviderType.OPENAI_COMPAT.value: OpenAICompatProvider,
        }
        # Default fallback
        self.default_provider = str(getattr(settings.ACTIVE_PROVIDER, "value", settings.ACTIVE_PROVIDER))

    def _normalize_provider_key(self, provider_key: str = None) -> Optional[str]:
        """Normalize enum/string providers to a stable string key."""
        if provider_key is None:
            return None
        return str(getattr(provider_key, "value", provider_key)).strip()
    
    def _get_provider(self, provider_key: str = None) -> LLMProvider:
        """Get the requested provider or default (lazy initialization)."""
        requested = self._normalize_provider_key(provider_key) or self.default_provider
        key = requested
        if key not in self._provider_classes:
            # Fallback to default if key is invalid/unknown and default is supported.
            if self.default_provider in self._provider_classes:
                key = self.default_provider
            else:
                supported = ", ".join(sorted(self._provider_classes.keys()))
                raise ValueError(
                    f"Unsupported provider '{requested}'. Supported providers: {supported}"
                )
        
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
                raise ValueError(f"Security: code execution attempt detected in expression: {task.expression}")
        
        # 2. Validate expression contains only safe characters
        import re
        # Allow: numbers, operators, parentheses, decimals, e/pi, common math functions
        safe_pattern = r'^[0-9+\-*/().epi \ssqrtsincostandlogexpabsln]+$'
        if not re.match(safe_pattern, task.expression.replace(' ', ''), re.IGNORECASE):
            raise ValueError(f"Expression contains unsafe characters: {task.expression}")
        
        # 3. Check for excessive length (possible DoS)
        if len(task.expression) > 500:
            raise ValueError(f"Expression too long ({len(task.expression)} chars, max 500)")
        
        # 4. Validate confidence is in valid range
        if not (0.0 <= task.confidence <= 1.0):
            raise ValueError(f"Invalid confidence score: {task.confidence}")

    def translate(self, user_query: str, provider: str = None) -> MathVerificationTask:
        """
        Translate query using the specified provider.
        Includes output verification for security.
        """
        task = self._get_provider(provider).translate(user_query)
        
        # ADD: Output verification (OWASP LLM05:2025)
        self._validate_math_output(task)
        
        return task

    def translate_logic(self, user_query: str, provider: str = None):
        """
        Translate logic query using the specified provider.
        """
        return self._get_provider(provider).translate_logic(user_query)

    def refine_logic(self, user_query: str, previous_error: str, provider: str = None):
        """
        Refine logic query based on feedback.
        """
        return self._get_provider(provider).refine_logic(user_query, previous_error)

    def translate_stats(self, query: str, columns: list[str], provider: str = None) -> str:
        """
        Generate Python code for statistical verification.
        """
        return self._get_provider(provider).translate_stats(query, columns)

    def verify_fact(self, claim: str, context: str, provider: str = None) -> dict:
        """
        Verify a claim against a context.
        """
        return self._get_provider(provider).verify_fact(claim, context)
