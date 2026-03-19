"""
Provider Registry — Canonical metadata for all supported LLM providers.

This is the single source of truth for provider configuration.
Used by: CLI init wizard, key validator, .env.example generator.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict
from enum import Enum


class AuthType(str, Enum):
    """How the provider authenticates."""
    API_KEY = "api_key"          # Simple bearer token (OpenAI, Anthropic, HF)
    ENDPOINT_KEY = "endpoint_key"  # Endpoint URL + API key (Azure, DO)
    LOCAL = "local"              # No auth needed (Ollama)


@dataclass(frozen=True)
class EnvVar:
    """Environment variable specification."""
    name: str
    description: str
    required: bool = True
    default: Optional[str] = None


@dataclass(frozen=True)
class ProviderMeta:
    """Immutable metadata for a single LLM provider."""
    slug: str
    name: str
    auth_type: AuthType
    env_vars: List[EnvVar]
    key_pattern: Optional[str] = None  # Regex for format validation
    key_hint: str = ""                 # Human-readable key format hint
    install_cmd: Optional[str] = None
    docs_url: str = ""
    is_local: bool = False             # No network needed (Ollama)
    default_model: str = "gpt-4o-mini"


# Shared descriptions
_MODEL_DESC = "Model name"


# ─────────────────────────────────────────────────────────────
# Release 1 Providers
# ─────────────────────────────────────────────────────────────

PROVIDER_REGISTRY: Dict[str, ProviderMeta] = {
    "openai": ProviderMeta(
        slug="openai",
        name="OpenAI",
        auth_type=AuthType.API_KEY,
        env_vars=[
            EnvVar("OPENAI_API_KEY", "Your OpenAI API key"),
            EnvVar("OPENAI_MODEL", _MODEL_DESC, required=False, default="gpt-4o-mini"),
        ],
        key_pattern=r"^sk-(proj-)?[A-Za-z0-9_-]{20,}$",
        key_hint="sk-... or sk-proj-...",
        install_cmd="pip install openai",
        docs_url="https://platform.openai.com/api-keys",
        default_model="gpt-4o-mini",
    ),

    "anthropic": ProviderMeta(
        slug="anthropic",
        name="Anthropic",
        auth_type=AuthType.API_KEY,
        env_vars=[
            EnvVar("ANTHROPIC_API_KEY", "Your Anthropic API key"),
            EnvVar("ANTHROPIC_MODEL", _MODEL_DESC, required=False, default="claude-sonnet-4-20250514"),
        ],
        key_pattern=r"^sk-ant-[A-Za-z0-9_-]{20,}$",
        key_hint="sk-ant-...",
        install_cmd="pip install anthropic",
        docs_url="https://console.anthropic.com/settings/keys",
        default_model="claude-sonnet-4-20250514",
    ),

    "ollama": ProviderMeta(
        slug="ollama",
        name="Ollama (Local)",
        auth_type=AuthType.LOCAL,
        env_vars=[
            EnvVar("OLLAMA_BASE_URL", "Ollama endpoint", required=False, default="http://localhost:11434/v1"),
            EnvVar("OLLAMA_MODEL", _MODEL_DESC, required=False, default="llama3"),
        ],
        key_hint="No API key needed — runs locally",
        install_cmd="ollama pull llama3",
        docs_url="https://ollama.com/library",
        is_local=True,
        default_model="llama3",
    ),

    "openai-compatible": ProviderMeta(
        slug="openai-compatible",
        name="OpenAI-Compatible (DO, Groq, Together, LM Studio, etc.)",
        auth_type=AuthType.ENDPOINT_KEY,
        env_vars=[
            EnvVar("CUSTOM_BASE_URL", "API endpoint URL (e.g., https://inference.do-ai.run/v1)"),
            EnvVar("CUSTOM_API_KEY", "API key for the endpoint"),
            EnvVar("CUSTOM_MODEL", _MODEL_DESC, required=False, default="gpt-4o-mini"),
        ],
        key_hint="Any bearer token format",
        install_cmd="pip install openai",
        docs_url="",
        default_model="gpt-4o-mini",
    ),
}


def get_provider(slug: str) -> ProviderMeta:
    """Get provider metadata by slug. Raises KeyError if not found."""
    if slug not in PROVIDER_REGISTRY:
        valid = ", ".join(PROVIDER_REGISTRY.keys())
        raise KeyError(f"Unknown provider '{slug}'. Valid: {valid}")
    return PROVIDER_REGISTRY[slug]


def list_providers() -> List[ProviderMeta]:
    """Return all registered providers in display order."""
    return list(PROVIDER_REGISTRY.values())
