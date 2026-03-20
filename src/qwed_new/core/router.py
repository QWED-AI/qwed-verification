"""
Router Module: The Traffic Controller.

This module decides which LLM provider to use for a given request.
It implements the "Model Routing" layer of the QWED OS.
"""

from typing import Optional
from qwed_new.config import settings, ProviderType

class Router:
    """
    Routes requests to the most appropriate LLM provider.
    """
    
    def __init__(self):
        configured_default = self._canonicalize_provider(getattr(settings.ACTIVE_PROVIDER, "value", settings.ACTIVE_PROVIDER))
        try:
            self.default_provider = ProviderType(configured_default).value
        except ValueError:
            self.default_provider = ProviderType.AUTO.value

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
        Determine the best provider for the query.
        
        Strategy:
        1. If user specifies a provider, use it (if valid).
        2. If query implies math/logic complexity, prefer Azure OpenAI (GPT-4).
        3. If query implies creative/long-context, prefer Anthropic (Claude).
        4. Fallback to default.
        """
        if preferred_provider:
            normalized = self._canonicalize_provider(preferred_provider)
            try:
                return ProviderType(normalized).value
            except ValueError:
                return self.default_provider
            
        # Simple heuristic routing (Phase 1)
        # In the future, this could use a small classifier model
        query_lower = query.lower()
        
        # Math/Logic keywords -> respect configured default provider
        if any(k in query_lower for k in ['calculate', 'solve', 'math', 'equation', 'logic', 'proof']):
            return self.default_provider
            
        # Creative/Writing keywords -> Claude (Anthropic)
        if any(k in query_lower for k in ['write', 'compose', 'essay', 'creative', 'story']):
            return ProviderType.ANTHROPIC.value
            
        return self.default_provider
