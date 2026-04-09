"""
Pytest fixtures for QWED Adversarial Hidden Reasoning tests.

Provides LLM provider and QWED engine instances.
Requires env vars: CUSTOM_BASE_URL, CUSTOM_API_KEY, CUSTOM_MODEL
"""

import os
import pytest


def _has_gradient_config() -> bool:
    """Check if Gradient API environment is configured."""
    return bool(os.getenv("CUSTOM_BASE_URL") and os.getenv("CUSTOM_API_KEY"))


# Skip entire module if no API config
requires_llm = pytest.mark.skipif(
    not _has_gradient_config(),
    reason="CUSTOM_BASE_URL and CUSTOM_API_KEY not set — skipping live LLM tests",
)


@pytest.fixture(scope="session")
def llm_provider():
    """Gradient-backed LLM provider (Claude/GPT via DigitalOcean)."""
    if not _has_gradient_config():
        pytest.skip("No Gradient API config")

    from qwed_new.providers.openai_compat import OpenAICompatProvider

    return OpenAICompatProvider()


@pytest.fixture(scope="session")
def math_engine():
    """QWED Math Verification Engine (SymPy)."""
    from qwed_new.core.verifier import VerificationEngine

    return VerificationEngine()


@pytest.fixture(scope="session")
def logic_engine():
    """QWED Logic Verification Engine (Z3)."""
    from qwed_new.core.logic_verifier import LogicVerifier

    return LogicVerifier(timeout_ms=10000)


@pytest.fixture(scope="session")
def reasoning_engine():
    """QWED Reasoning Verification Engine."""
    from qwed_new.core.reasoning_verifier import ReasoningVerifier

    return ReasoningVerifier(enable_cache=False)
