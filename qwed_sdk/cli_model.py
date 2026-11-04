# Copyright (c) 2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""The model the qwed CLI runs: the one its user configures (#574).

QWED is model-agnostic and names no model of its own. ``qwed verify`` and
``qwed interactive`` take ``--model``, else the selected provider's model
variable, and stop with a message naming it when neither is set. Without
``--provider``, the selected provider is the one ``qwed init`` saved
(ACTIVE_PROVIDER). ``qwed init`` stops the same way rather than choosing a
model.

Kept out of cli.py, which is at the security scan's file size limit.
"""

import os
import sys
from pathlib import Path
from typing import NamedTuple, NoReturn, Optional

import click

from qwed_sdk.qwed_local import HAS_COLOR, QWED

OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434/v1"

# Where `qwed verify` and `qwed interactive` read the model for --provider.
PROVIDER_MODEL_ENV = {
    "openai": "OPENAI_MODEL",
    "anthropic": "ANTHROPIC_MODEL",
    "gemini": "GEMINI_MODEL",
}

# Where they read the API key of the provider `qwed init` saved.
PROVIDER_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GOOGLE_API_KEY",
}


class SavedProvider(NamedTuple):
    """The provider ACTIVE_PROVIDER selects, as `qwed init` saved it."""

    provider: Optional[str]  # a named provider, for QWEDLocal(provider=...)
    base_url: Optional[str]  # an endpoint, for QWEDLocal(base_url=...)
    api_key: Optional[str]
    model_env: Optional[str]  # the variable that names its model
    notice: str  # the line that says which provider runs


def stop(message: str, hint: Optional[str] = None) -> NoReturn:
    """Print an error, and a hint when there is one, and stop the command."""
    click.echo(f"{QWED.ERROR}{message}{QWED.RESET}" if HAS_COLOR else message, err=True)
    if hint:
        click.echo(hint, err=True)
    sys.exit(1)


def saved_provider(api_key: Optional[str] = None) -> SavedProvider:
    """The provider `qwed verify` and `qwed interactive` run without
    --provider or --base-url: the one ACTIVE_PROVIDER selects, and Ollama when
    it is unset, as the server reads it. ``api_key`` wins over the saved key.

    A provider only the server runs (azure_openai or auto, say) stops the
    command with a message naming ACTIVE_PROVIDER. No other provider stands
    in for it.
    """
    active = os.getenv("ACTIVE_PROVIDER", "").strip()
    if active in ("", "ollama"):
        base_url = os.getenv("OLLAMA_BASE_URL", OLLAMA_DEFAULT_BASE_URL)
        return SavedProvider(None, base_url, api_key, "OLLAMA_MODEL", f"ℹ️  Using Ollama at {base_url}")
    if active in ("openai-compatible", "openai_compat"):
        base_url = os.getenv("CUSTOM_BASE_URL", "")
        if not base_url:
            stop(
                "ERROR: CUSTOM_BASE_URL is required for openai-compatible provider",
                "Set CUSTOM_BASE_URL env var or run: qwed init",
            )
        key = api_key or os.getenv("CUSTOM_API_KEY", "")
        return SavedProvider(None, base_url, key, "CUSTOM_MODEL", f"ℹ️  Using configured provider: {active}")
    if active not in PROVIDER_MODEL_ENV:
        stop(
            f"ERROR: ACTIVE_PROVIDER is '{active}', which the qwed CLI cannot run.",
            "Pass --provider (openai, anthropic or gemini) or --base-url, or set ACTIVE_PROVIDER "
            "to ollama, openai-compatible, openai, anthropic or gemini.",
        )
    key = api_key or os.getenv(PROVIDER_KEY_ENV[active], os.getenv("QWED_API_KEY", ""))
    return SavedProvider(
        active, None, key, PROVIDER_MODEL_ENV[active], f"INFO: Using configured provider: {active}"
    )


def load_saved_env() -> None:
    """Load the .env files `qwed init` writes, as load_dotenv_ordered does,
    without overriding the shell.

    It does not import qwed_new.config, whose Settings raise without the
    server's API_KEY_SECRET: a local session has no server secrets.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(Path.cwd() / ".env", override=False)
    load_dotenv(Path.home() / ".qwed" / ".env", override=False)


def has_model(model: Optional[str]) -> bool:
    """A blank model is no model."""
    return bool(model and model.strip())


def model_or_variable(model: Optional[str], model_env: Optional[str]) -> Optional[str]:
    """``--model``, else the model in the variable ``model_env`` names."""
    if has_model(model) or not model_env:
        return model
    return os.getenv(model_env)


def exit_without_model(model: Optional[str], model_env: Optional[str]) -> None:
    """Stop `qwed verify` or `qwed interactive` when no model is configured."""
    if has_model(model):
        return
    hint = f"Pass --model or set {model_env}." if model_env else "Pass --model."
    stop(f"ERROR: No model is configured. {hint}")


def require_provider_model(profile, resolved_model: str) -> None:
    """Stop `qwed init` when the onboarding ``profile`` has no model."""
    if not resolved_model:
        raise RuntimeError(
            f"{profile.model_env} is required for provider '{profile.slug}'. "
            f"Pass --model or set {profile.model_env}."
        )
