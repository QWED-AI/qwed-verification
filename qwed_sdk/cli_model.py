# Copyright (c) 2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""The model the qwed CLI runs: the one its user configures (#574).

QWED is model-agnostic and names no model of its own. ``qwed verify`` and
``qwed interactive`` take ``--model``, else the selected provider's model
variable, and stop with a message naming it when neither is set. ``qwed init``
stops the same way rather than choosing a model.

Kept out of cli.py, which is at the security scan's file size limit.
"""

import os
import sys
from pathlib import Path
from typing import Optional

import click

from qwed_sdk.qwed_local import HAS_COLOR, QWED

# Where `qwed verify` and `qwed interactive` read the model for --provider.
PROVIDER_MODEL_ENV = {
    "openai": "OPENAI_MODEL",
    "anthropic": "ANTHROPIC_MODEL",
    "gemini": "GEMINI_MODEL",
}


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
    message = f"ERROR: No model is configured. {hint}"
    click.echo(f"{QWED.ERROR}{message}{QWED.RESET}" if HAS_COLOR else message, err=True)
    sys.exit(1)


def require_provider_model(profile, resolved_model: str) -> None:
    """Stop `qwed init` when the onboarding ``profile`` has no model."""
    if not resolved_model:
        raise RuntimeError(
            f"{profile.model_env} is required for provider '{profile.slug}'. "
            f"Pass --model or set {profile.model_env}."
        )
