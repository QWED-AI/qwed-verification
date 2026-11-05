"""
Auto-Shift Provider: High Availability Wrapper.

This provider wraps multiple LLM providers (Azure OpenAI and Anthropic) and automatically
fails over to the secondary provider if the primary one fails.
"""

import logging
from typing import Dict, Any, List
from qwed_new.core.schemas import MathVerificationTask, LogicVerificationTask
from qwed_new.providers.base import LLMProvider, ProviderConfigError
from qwed_new.providers.azure_openai import AzureOpenAIProvider
from qwed_new.providers.anthropic import AnthropicProvider

# Configure logging
logger = logging.getLogger(__name__)

class AutoShiftProvider(LLMProvider):
    """
    A composite provider that implements the "Auto-Shift" failover logic.
    Primary: Azure OpenAI, running AZURE_OPENAI_DEPLOYMENT (e.g. GPT-4)
    Secondary: Anthropic, running ANTHROPIC_MODEL (e.g. Claude 3.5 Sonnet)

    Each runs only its configured model. It runs only when ACTIVE_PROVIDER
    (or the request) selects "auto".
    """
    
    def __init__(self):
        errors = []
        try:
            self.primary = AzureOpenAIProvider()
            logger.info("Primary Provider (Azure OpenAI) initialized.")
        except Exception as e:
            logger.warning(f"Failed to initialize Primary Provider: {e}")
            self.primary = None
            errors.append(e)
            
        try:
            self.secondary = AnthropicProvider()
            logger.info("Secondary Provider (Anthropic) initialized.")
        except Exception as e:
            logger.warning(f"Failed to initialize Secondary Provider: {e}")
            self.secondary = None
            errors.append(e)
            
        if not self.primary and not self.secondary:
            # Neither side has a model: name both settings, as a single
            # provider does. Their messages carry nothing from a provider.
            if all(isinstance(e, ProviderConfigError) for e in errors):
                raise ProviderConfigError(
                    "Auto-shift can run neither of its providers. " + " ".join(map(str, errors))
                )
            raise RuntimeError("CRITICAL: Both Primary and Secondary providers failed to initialize.")

    def _execute_with_fallback(self, method_name: str, *args, **kwargs):
        """
        Generic wrapper to execute a method on the primary provider, 
        falling back to secondary on failure.
        """
        # Try Primary
        if self.primary:
            try:
                method = getattr(self.primary, method_name)
                return method(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Primary Provider ({method_name}) failed: {e}. Attempting Auto-Shift...")
        
        # Try Secondary
        if self.secondary:
            try:
                logger.info(f"Auto-Shift: Switching to Secondary Provider for {method_name}")
                method = getattr(self.secondary, method_name)
                return method(*args, **kwargs)
            except Exception as e:
                logger.error(f"Secondary Provider ({method_name}) also failed: {e}")
                raise e
        
        # If we get here, it means primary failed (or is None) and secondary is None
        raise RuntimeError("No available providers to execute request.")

    def translate(self, user_query: str) -> MathVerificationTask:
        return self._execute_with_fallback('translate', user_query)

    def translate_logic(self, user_query: str) -> LogicVerificationTask:
        return self._execute_with_fallback('translate_logic', user_query)

    def refine_logic(self, user_query: str, previous_error: str) -> LogicVerificationTask:
        return self._execute_with_fallback('refine_logic', user_query, previous_error)

    def translate_stats(self, query: str, columns: List[str]) -> str:
        return self._execute_with_fallback('translate_stats', query, columns)

    def verify_fact(self, claim: str, context: str) -> Dict[str, Any]:
        return self._execute_with_fallback('verify_fact', claim, context)

    def verify_image(self, image_bytes: bytes, claim: str) -> Dict[str, Any]:
        return self._execute_with_fallback('verify_image', image_bytes, claim)
