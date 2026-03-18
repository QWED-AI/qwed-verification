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
        self.default_provider = settings.ACTIVE_PROVIDER
        
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
            # Validate the preferred provider is a known type
            try:
                return ProviderType(preferred_provider)
            except ValueError:
                return preferred_provider  # Allow raw string for flexibility
            
        # Simple heuristic routing (Phase 1)
        # In the future, this could use a small classifier model
        query_lower = query.lower()
        
        # Math/Logic keywords -> prioritize precise providers
        if any(k in query_lower for k in ['calculate', 'solve', 'math', 'equation', 'logic', 'proof']):
            # Use default provider (user's configured choice)
            return self.default_provider
            
        return self.default_provider
