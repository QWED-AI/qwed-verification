"""
Router Module: The Traffic Controller.

This module decides which LLM provider to use for a given request.
It implements the "Model Routing" layer of the QWED OS.
"""

from typing import Optional
from qwed_new.config import settings, ProviderType

# The label for a provider a request names that QWED does not know. The router
# passes it on, so the translator refuses the request; it never passes the
# request's own text, which would reach responses and metrics (#574).
UNKNOWN_PROVIDER = "unknown"

class Router:
    """
    Routes each request to the provider its user selected.
    """
    
    def __init__(self):
        configured_default = self._canonicalize_provider(getattr(settings.ACTIVE_PROVIDER, "value", settings.ACTIVE_PROVIDER))
        # A blank ACTIVE_PROVIDER is unset, which Settings reads as Ollama. A
        # name QWED does not know stays as it is: the translator refuses it and
        # names ACTIVE_PROVIDER, rather than the router choosing another provider.
        self.default_provider = configured_default or ProviderType.OLLAMA.value

    def _canonicalize_provider(self, provider: object) -> str:
        """Normalize enum/string providers to canonical routing tokens."""
        canonical = str(getattr(provider, "value", provider)).strip().lower()
        canonical = canonical.replace("-", "_").replace(" ", "_")
        aliases = {
            "openai_compatible": ProviderType.OPENAI_COMPAT.value,
        }
        return aliases.get(canonical, canonical)
        
    def route(self, query: str, preferred_provider: Optional[str] = None) -> str:
        """
        Return the provider for a request.

        It is the provider the request names, else the configured one
        (ACTIVE_PROVIDER). A name QWED does not know gives UNKNOWN_PROVIDER,
        which the translator refuses: no other provider stands in for the one
        the request selected. The query's wording never selects a provider: a
        query with "write" or "story" in it once went to Anthropic whatever the
        user had configured (#574).
        """
        if preferred_provider:
            normalized = self._canonicalize_provider(preferred_provider)
            if normalized in {provider.value for provider in ProviderType}:
                return normalized
            if normalized:
                return UNKNOWN_PROVIDER
        return self.default_provider
