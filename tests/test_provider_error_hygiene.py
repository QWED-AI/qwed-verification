"""#225: provider SDK exceptions embed internal topology — endpoint URLs,
deployment names, request IDs. That detail must stay in the server log for
operators and must NOT ride a raised exception (or a result dict) up to the API
layer or a client. sanitized_provider_error is the one place that policy lives.

The provider methods are driven here with a mock client whose call raises, so
every error path is exercised and asserted to surface a sanitized result.
"""
import logging
from unittest.mock import MagicMock

import pytest

from qwed_new.providers.anthropic import AnthropicProvider
from qwed_new.providers.azure_openai import AzureOpenAIProvider
from qwed_new.providers.base import sanitized_provider_error
from qwed_new.providers.claude_opus import ClaudeOpusProvider

# Synthetic internal detail an SDK error might carry. Not a real secret — it
# stands in for the endpoint/deployment/request-id topology that must not leak.
_DETAIL = "connect to https://acct.internal.example/deployments/prod failed (request id 5f3a-internal)"
_LEAKY = ("internal.example", "deployments", "request id", _DETAIL)


# --- the shared policy helper --------------------------------------------------

def test_returned_error_message_carries_no_internal_detail():
    err = sanitized_provider_error(
        logging.getLogger("t"), "Azure OpenAI translation failed", RuntimeError(_DETAIL)
    )
    assert isinstance(err, ValueError)
    message = err.args[0]
    assert message == "Azure OpenAI translation failed."
    for leak in _LEAKY:
        assert leak not in message


def test_full_detail_is_logged_for_operators(caplog):
    with caplog.at_level(logging.WARNING):
        sanitized_provider_error(
            logging.getLogger("qwed_provider_hygiene_test"),
            "Anthropic logic translation failed",
            RuntimeError(_DETAIL),
        )
    messages = [r.getMessage() for r in caplog.records]
    assert any("internal.example" in m for m in messages)  # operators keep the cause
    assert any("Anthropic logic translation failed" in m for m in messages)


# --- every provider error path surfaces a sanitized result ---------------------

def _provider(cls, client_path):
    """Build a provider without its credential-bound __init__ and give it a
    client whose SDK call raises with internal detail."""
    p = cls.__new__(cls)
    p.deployment = "test-deployment"
    p.tool_schema = MagicMock()  # some translate paths build the request from this
    p.client = MagicMock()
    # client_path is e.g. ("chat", "completions", "create") or ("messages", "create").
    target = p.client
    for attr in client_path[:-1]:
        target = getattr(target, attr)
    getattr(target, client_path[-1]).side_effect = RuntimeError(_DETAIL)
    return p


_AZURE = ("chat", "completions", "create")
_ANTHROPIC = ("messages", "create")

# (provider cls, client path, method, args, kind) — kind "raise" asserts a
# sanitized ValueError; "dict" asserts a sanitized fallback result.
_RAISING = [
    (AzureOpenAIProvider, _AZURE, "translate", ("q",), "Azure OpenAI translation failed."),
    (AzureOpenAIProvider, _AZURE, "translate_logic_dsl", ("q",), "Azure OpenAI DSL translation failed."),
    (AzureOpenAIProvider, _AZURE, "translate_logic", ("q",), "Azure OpenAI logic translation failed."),
    (AzureOpenAIProvider, _AZURE, "refine_logic", ("q", "err"), "Azure OpenAI logic refinement failed."),
    (AzureOpenAIProvider, _AZURE, "translate_stats", ("q", ["a", "b"]), "Azure OpenAI stats translation failed."),
    (AnthropicProvider, _ANTHROPIC, "translate", ("q",), "Anthropic translation failed."),
    (AnthropicProvider, _ANTHROPIC, "translate_logic_dsl", ("q",), "Anthropic DSL translation failed."),
    (AnthropicProvider, _ANTHROPIC, "translate_logic", ("q",), "Anthropic logic translation failed."),
    (AnthropicProvider, _ANTHROPIC, "refine_logic", ("q", "err"), "Anthropic logic refinement failed."),
    (AnthropicProvider, _ANTHROPIC, "translate_stats", ("q", ["a", "b"]), "Anthropic stats translation failed."),
    (AnthropicProvider, _ANTHROPIC, "verify_fact", ("claim", "ctx"), "Anthropic fact verification failed."),
    (ClaudeOpusProvider, _ANTHROPIC, "translate", ("q",), "Claude Opus translation failed."),
    (ClaudeOpusProvider, _ANTHROPIC, "translate_logic", ("q",), "Claude Opus logic translation failed."),
    (ClaudeOpusProvider, _ANTHROPIC, "refine_logic", ("q", "err"), "Claude Opus logic refinement failed."),
    (ClaudeOpusProvider, _ANTHROPIC, "translate_stats", ("q", ["a", "b"]), "Claude Opus stats translation failed."),
    (ClaudeOpusProvider, _ANTHROPIC, "verify_fact", ("claim", "ctx"), "Claude Opus fact verification failed."),
]

_RETURNING = [
    (AzureOpenAIProvider, _AZURE, "verify_fact", ("claim", "ctx")),
    (AzureOpenAIProvider, _AZURE, "verify_image", (b"x", "claim")),
    (AnthropicProvider, _ANTHROPIC, "verify_image", (b"x", "claim")),
    (ClaudeOpusProvider, _ANTHROPIC, "verify_image", (b"x", "claim")),
]


@pytest.mark.parametrize("cls,path,method,args,summary", _RAISING,
                         ids=[f"{c.__name__}.{m}" for c, _, m, _, _ in _RAISING])
def test_error_path_raises_sanitized(cls, path, method, args, summary):
    provider = _provider(cls, path)
    with pytest.raises(ValueError) as excinfo:
        getattr(provider, method)(*args)
    message = excinfo.value.args[0]
    assert message == summary
    for leak in _LEAKY:
        assert leak not in message
    # The original cause is preserved (raised `from e`) for the server traceback.
    assert excinfo.value.__cause__ is not None


@pytest.mark.parametrize("cls,path,method,args", _RETURNING,
                         ids=[f"{c.__name__}.{m}" for c, _, m, _ in _RETURNING])
def test_error_path_returns_sanitized_dict(cls, path, method, args):
    provider = _provider(cls, path)
    result = getattr(provider, method)(*args)
    assert result["verdict"] == "ERROR"
    for leak in _LEAKY:
        assert leak not in result["reasoning"]
