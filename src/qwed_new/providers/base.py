"""
Base class for LLM Providers.

This defines the interface that all providers (Azure OpenAI, Anthropic, etc.) must implement.
This is the core of the "Model-Agnostic" architecture.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from qwed_new.core.schemas import MathVerificationTask, LogicVerificationTask


def sanitized_provider_error(logger: logging.Logger, summary: str, exc: Exception) -> ValueError:
    """Log a provider SDK exception for operators and return a ValueError whose
    message carries no internal detail to the caller (#225).

    Provider SDK errors embed internal topology — endpoint URLs, deployment
    names, request IDs, rate-limit headers. The full exception goes to the
    server log, where operators need it to debug; the returned ValueError says
    only what failed, so nothing internal rides a raised exception up to the API
    layer or a client. Raise it with ``from exc`` so the cause chain stays in the
    server traceback:

        raise sanitized_provider_error(logger, "Azure OpenAI translation failed", exc) from exc
    """
    logger.warning("%s: %s", summary, exc)
    return ValueError(f"{summary}.")


class LLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    """
    
    @abstractmethod
    def translate(self, user_query: str) -> MathVerificationTask:
        """Translate natural language to MathVerificationTask."""
        pass

    @abstractmethod
    def translate_logic(self, user_query: str) -> 'LogicVerificationTask':
        """Translate natural language to LogicVerificationTask (for Z3)."""
        pass

    @abstractmethod
    def refine_logic(self, user_query: str, previous_error: str) -> 'LogicVerificationTask':
        """
        Refine logic translation based on Z3 error feedback.
        """
        pass

    @abstractmethod
    def translate_stats(self, query: str, columns: List[str]) -> str:
        """
        Generate Python code for statistical verification.
        """
        pass

    @abstractmethod
    def verify_fact(self, claim: str, context: str) -> Dict[str, Any]:
        """Verify a claim against a context."""
        pass

    @abstractmethod
    def verify_image(self, image_bytes: bytes, claim: str) -> Dict[str, Any]:
        """Verify a claim against an image."""
        pass
