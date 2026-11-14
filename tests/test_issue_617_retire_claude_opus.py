"""#617: claude_opus was the Anthropic provider under one model's name.

``ClaudeOpusProvider`` was a copy of ``AnthropicProvider`` that read
``CLAUDE_OPUS_*`` settings, so QWED shipped a provider named after one model,
and a change to one had to be made in both. The CLI's connection check for it
read the ``ANTHROPIC_*`` settings, so it checked other settings than the
server used.

It is gone: the Anthropic provider runs any model set in ``ANTHROPIC_MODEL``.
``ACTIVE_PROVIDER=claude_opus`` is refused, as a name QWED does not know is,
and the message says what to set instead, with ANTHROPIC_DEPLOYMENT unset,
since it wins over ANTHROPIC_MODEL (CodeAnt on #618).

In the reasoning verifier's provider list, a retired name, or one QWED does
not know, refuses the whole list: no other configured provider runs in its
place, and the result is BLOCKED with the setting to fix (CodeRabbit on #618).
"""

import importlib.util
from types import SimpleNamespace

import pytest

from qwed_new.config import ProviderType, settings
from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.reasoning_verifier import _PROVIDER_NAMES, ReasoningVerifier
from qwed_new.core.translator import TranslationLayer
from qwed_new.providers.base import ProviderConfigError
from qwed_sdk.cli import _provider_connection_profile
from tests.test_issue_574_no_default_model import _verify_apples

ANTHROPIC_SETTINGS = ("ANTHROPIC_ENDPOINT", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL")
# ANTHROPIC_DEPLOYMENT wins over ANTHROPIC_MODEL (test_issue_574), so a
# setup that keeps it would go on running its old deployment.
DEPLOYMENT_NOTE = "and ANTHROPIC_DEPLOYMENT unset, since it wins over ANTHROPIC_MODEL"


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
    assert DEPLOYMENT_NOTE in message


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
    assert DEPLOYMENT_NOTE in result.agent_message


class _RecordingProvider:
    """A provider that would run: it records each call made to it."""

    def __init__(self, calls):
        self.calls = calls

    def complete(self, _prompt):
        self.calls.append("complete")
        return "1. Extract 10 and 5\n2. Add them to get 15"

    def translate(self, _query):
        self.calls.append("translate")
        return SimpleNamespace(expression="10 + 5")


def _verifier_with_working_providers(names, *, enable_cache=False):
    # Anthropic and OpenAI would both run, so only the names decide.
    calls = []
    verifier = ReasoningVerifier(providers=names, enable_cache=enable_cache)
    verifier._provider_loaders["anthropic"] = lambda: _RecordingProvider(calls)
    verifier._provider_loaders["openai"] = lambda: _RecordingProvider(calls)
    return verifier, calls


def _verify(verifier, cross_validation):
    return verifier.verify_understanding(
        query="Alice has 10 apples and gets 5 more. How many apples does she have?",
        primary_task=SimpleNamespace(expression="10 + 5", reasoning="1. Add 10 and 5"),
        enable_cross_validation=cross_validation,
    )


@pytest.mark.parametrize(
    "names, said",
    [
        (["claude_opus", "anthropic"], "a provider QWED no longer has"),
        (["anthropic", "claude_opus"], "a provider QWED no longer has"),
        (["anthropic", "openai", "claude-opus"], "a provider QWED no longer has"),
        (["ollmaa", "anthropic"], "a provider QWED does not know"),
        (["anthropic", "ollmaa"], "a provider QWED does not know"),
    ],
)
@pytest.mark.parametrize("cross_validation", [False, True])
def test_a_name_it_cannot_load_refuses_the_whole_provider_list(names, said, cross_validation):
    # Before: the other provider ran in its place, and the result was
    # UNVERIFIABLE, with the setting to fix only in the log.
    verifier, calls = _verifier_with_working_providers(names)

    result = _verify(verifier, cross_validation)

    assert result.status == DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == "reasoning_verifier.provider_config_error"
    assert said in result.agent_message
    assert calls == []
    assert verifier.primary_llm is None
    assert verifier.secondary_llm is None


def test_a_cached_result_is_refused_the_same_way():
    verifier, calls = _verifier_with_working_providers(["claude_opus", "anthropic"], enable_cache=True)

    first = _verify(verifier, cross_validation=False)
    second = _verify(verifier, cross_validation=False)

    assert first.status == second.status == DiagnosticStatus.BLOCKED
    assert second.developer_fields["cached"] is True
    assert "a provider QWED no longer has" in second.agent_message
    assert calls == []


@pytest.mark.parametrize("cross_validation", [False, True])
def test_a_list_of_names_it_can_load_still_runs(cross_validation):
    verifier, calls = _verifier_with_working_providers(["anthropic", "openai"])

    result = _verify(verifier, cross_validation)

    assert result.status == DiagnosticStatus.UNVERIFIABLE
    assert "complete" in calls
    assert ("translate" in calls) is cross_validation
