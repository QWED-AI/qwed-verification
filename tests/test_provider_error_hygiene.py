"""#225: provider SDK exceptions embed internal topology — endpoint URLs,
deployment names, request IDs. That detail must stay in the server log for
operators and must NOT ride a raised exception (or a result dict) up to the API
layer or a client. sanitized_provider_error is the one place that policy lives.

The provider methods are driven here with a mock SDK client whose call raises, so
every error path is exercised and asserted to surface a sanitized result that
chains from the real (mocked) SDK error.
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
#
# Each builder constructs a provider without its credential-bound __init__, sets
# the attributes its request-building reads, and makes the one SDK call raise
# _DETAIL — so the method reaches that call and the except wraps the real error.

def _base(cls):
    p = cls.__new__(cls)
    p.deployment = "test-deployment"
    p.function_schema = MagicMock()  # azure reads this when building the request
    p.tool_schema = MagicMock()      # anthropic / claude read this
    p.client = MagicMock()
    return p


def _azure():
    p = _base(AzureOpenAIProvider)
    p.client.chat.completions.create.side_effect = RuntimeError(_DETAIL)
    return p


def _anthropic():
    p = _base(AnthropicProvider)
    p.client.messages.create.side_effect = RuntimeError(_DETAIL)
    return p


def _claude():
    p = _base(ClaudeOpusProvider)
    p.client.messages.create.side_effect = RuntimeError(_DETAIL)
    return p


# (id, builder, action, expected sanitized message)
_RAISING = [
    ("azure.translate", _azure, lambda p: p.translate("q"), "Azure OpenAI translation failed."),
    ("azure.translate_logic_dsl", _azure, lambda p: p.translate_logic_dsl("q"), "Azure OpenAI DSL translation failed."),
    ("azure.translate_logic", _azure, lambda p: p.translate_logic("q"), "Azure OpenAI logic translation failed."),
    ("azure.refine_logic", _azure, lambda p: p.refine_logic("q", "err"), "Azure OpenAI logic refinement failed."),
    ("azure.translate_stats", _azure, lambda p: p.translate_stats("q", ["a", "b"]), "Azure OpenAI stats translation failed."),
    ("anthropic.translate", _anthropic, lambda p: p.translate("q"), "Anthropic translation failed."),
    ("anthropic.translate_logic_dsl", _anthropic, lambda p: p.translate_logic_dsl("q"), "Anthropic DSL translation failed."),
    ("anthropic.translate_logic", _anthropic, lambda p: p.translate_logic("q"), "Anthropic logic translation failed."),
    ("anthropic.refine_logic", _anthropic, lambda p: p.refine_logic("q", "err"), "Anthropic logic refinement failed."),
    ("anthropic.translate_stats", _anthropic, lambda p: p.translate_stats("q", ["a", "b"]), "Anthropic stats translation failed."),
    ("anthropic.verify_fact", _anthropic, lambda p: p.verify_fact("claim", "ctx"), "Anthropic fact verification failed."),
    ("claude.translate", _claude, lambda p: p.translate("q"), "Claude Opus translation failed."),
    ("claude.translate_logic", _claude, lambda p: p.translate_logic("q"), "Claude Opus logic translation failed."),
    ("claude.refine_logic", _claude, lambda p: p.refine_logic("q", "err"), "Claude Opus logic refinement failed."),
    ("claude.translate_stats", _claude, lambda p: p.translate_stats("q", ["a", "b"]), "Claude Opus stats translation failed."),
    ("claude.verify_fact", _claude, lambda p: p.verify_fact("claim", "ctx"), "Claude Opus fact verification failed."),
]

_RETURNING = [
    ("azure.verify_fact", _azure, lambda p: p.verify_fact("claim", "ctx")),
    ("azure.verify_image", _azure, lambda p: p.verify_image(b"x", "claim")),
    ("anthropic.verify_image", _anthropic, lambda p: p.verify_image(b"x", "claim")),
    ("claude.verify_image", _claude, lambda p: p.verify_image(b"x", "claim")),
]


@pytest.mark.parametrize("build,action,summary", [c[1:] for c in _RAISING],
                         ids=[c[0] for c in _RAISING])
def test_error_path_raises_sanitized(build, action, summary):
    provider = build()
    with pytest.raises(ValueError) as excinfo:
        action(provider)
    message = excinfo.value.args[0]
    assert message == summary
    for leak in _LEAKY:
        assert leak not in message
    # The real (mocked) SDK error is the preserved cause, raised `from e`.
    assert isinstance(excinfo.value.__cause__, RuntimeError)


@pytest.mark.parametrize("build,action", [c[1:] for c in _RETURNING],
                         ids=[c[0] for c in _RETURNING])
def test_error_path_returns_sanitized_dict(build, action):
    provider = build()
    result = action(provider)
    assert result["verdict"] == "ERROR"
    for leak in _LEAKY:
        assert leak not in result["reasoning"]
