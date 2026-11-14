"""#617: claude_opus was the Anthropic provider under one model's name.

``ClaudeOpusProvider`` was a copy of ``AnthropicProvider`` that read
``CLAUDE_OPUS_*`` settings, so QWED shipped a provider named after one model,
and a change to one had to be made in both. The CLI's connection check for it
read the ``ANTHROPIC_*`` settings, so it checked other settings than the
server used.

It is gone: the Anthropic provider runs any model set in ``ANTHROPIC_MODEL``.
``ACTIVE_PROVIDER=claude_opus`` is refused, as a name QWED does not know is,
and the message says what to set instead.
"""

import importlib.util

import pytest

from qwed_new.config import ProviderType, settings
from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.reasoning_verifier import _PROVIDER_NAMES, ReasoningVerifier
from qwed_new.core.translator import TranslationLayer
from qwed_new.providers.base import ProviderConfigError
from qwed_sdk.cli import _provider_connection_profile
from tests.test_issue_574_no_default_model import _verify_apples

ANTHROPIC_SETTINGS = ("ANTHROPIC_ENDPOINT", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL")


def test_the_provider_is_gone_everywhere_it_was_named():
    assert importlib.util.find_spec("qwed_new.providers.claude_opus") is None
    assert "claude_opus" not in {provider.value for provider in ProviderType}
    assert "claude_opus" not in TranslationLayer()._provider_classes
    assert "claude_opus" not in _PROVIDER_NAMES
    assert _provider_connection_profile("claude_opus") == {}


def test_active_provider_claude_opus_is_refused_with_what_to_set(monkeypatch):
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "claude_opus")

    with pytest.raises(ProviderConfigError) as raised:
        TranslationLayer().translate("What is 2 + 2?")

    message = str(raised.value)
    assert "ACTIVE_PROVIDER is set to 'claude_opus', a provider QWED no longer has." in message
    assert "Set it to anthropic" in message
    for name in ANTHROPIC_SETTINGS:
        assert name in message


def test_a_request_naming_it_gets_the_unknown_provider_refusal(monkeypatch):
    # A request's name is not echoed or explained: it is refused as unknown.
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "anthropic")

    with pytest.raises(ProviderConfigError, match="The request names a provider QWED does not know"):
        TranslationLayer().translate("What is 2 + 2?", provider="claude_opus")


def test_the_reasoning_verifier_says_what_to_set_too(monkeypatch):
    monkeypatch.setenv("ACTIVE_PROVIDER", "claude_opus")

    result = _verify_apples(ReasoningVerifier(enable_cache=False))

    assert result.status == DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == "reasoning_verifier.provider_config_error"
    assert "a provider QWED no longer has" in result.agent_message
    for name in ANTHROPIC_SETTINGS:
        assert name in result.agent_message
