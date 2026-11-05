"""QWED names no model: every provider runs the model its user configured.

Runtime code used to fall back to a model of its own when none was set
(gpt-4o-mini, gpt-3.5-turbo, llama3, gemini-1.5-pro, claude-sonnet-4-5, and a
hardcoded Haiku 3 in the reasoning trace), and those names went stale as
providers retired models. Now a provider with no model configured raises and
names the variable to set, and any model ID the user sets reaches the
provider's API unchanged. Each request goes to the provider the user
selected, whatever its wording.
"""

import ast
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import NAMESPACE_URL, uuid5

import pytest
from click.testing import CliRunner

import qwed_sdk.qwed_local as qwed_local_module
from qwed_new.config import ProviderType, settings
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.reasoning_verifier import _PROVIDER_NAMES, ReasoningVerifier
from qwed_new.core.router import Router
from qwed_new.core.schemas import LogicVerificationTask
from qwed_new.core.translator import TranslationLayer
from qwed_new.providers import gemini_provider
from qwed_new.providers import registry as registry_module
from qwed_new.providers.anthropic import AnthropicProvider
from qwed_new.providers.auto_shift import AutoShiftProvider
from qwed_new.providers.azure_openai import AzureOpenAIProvider
from qwed_new.providers.base import ProviderConfigError
from qwed_new.providers.claude_opus import ClaudeOpusProvider
from qwed_new.providers.gemini_provider import GeminiProvider
from qwed_new.providers.ollama_provider import OllamaProvider
from qwed_new.providers.openai_compat import OpenAICompatProvider
from qwed_new.providers.openai_direct import OpenAIDirectProvider
from qwed_sdk.cli import (
    OnboardingProvider,
    _resolve_provider_model,
    _test_provider_connection_loop,
    init,
    interactive,
    verify,
)
from qwed_sdk.cli_model import saved_provider

ROOT = Path(__file__).resolve().parents[1]

# No provider's model: an ID must reach the API exactly as the user set it.
ANY_MODEL = "acme-labs/reasoner-v9:2026-11@eu-west"
STATS_CODE = "result = df['a'].mean()"
# Test-only key material, the same on every run (uuid5 is derived from its
# name); no test reaches a provider over the network.
FAKE_KEY = f"unit-test-{uuid5(NAMESPACE_URL, 'qwed-tests/issue-574').hex}"

# provider class -> (its model variable, the other settings it needs)
PROVIDERS = {
    OpenAIDirectProvider: ("OPENAI_MODEL", {"OPENAI_API_KEY": FAKE_KEY}),
    AzureOpenAIProvider: (
        "AZURE_OPENAI_DEPLOYMENT",
        {
            "AZURE_OPENAI_ENDPOINT": "http://localhost:1",
            "AZURE_OPENAI_API_KEY": FAKE_KEY,
            "AZURE_OPENAI_API_VERSION": "2024-01-01",
        },
    ),
    AnthropicProvider: (
        "ANTHROPIC_MODEL",
        {"ANTHROPIC_ENDPOINT": "http://localhost:1", "ANTHROPIC_API_KEY": FAKE_KEY},
    ),
    ClaudeOpusProvider: (
        "CLAUDE_OPUS_DEPLOYMENT",
        {"CLAUDE_OPUS_ENDPOINT": "http://localhost:1", "CLAUDE_OPUS_API_KEY": FAKE_KEY},
    ),
    OllamaProvider: ("OLLAMA_MODEL", {}),
    OpenAICompatProvider: ("CUSTOM_MODEL", {"CUSTOM_BASE_URL": "http://localhost:1/v1"}),
    GeminiProvider: ("GEMINI_MODEL", {"GOOGLE_API_KEY": FAKE_KEY}),
}
MODEL_VARIABLES = {model_env for model_env, _ in PROVIDERS.values()} | {"ANTHROPIC_DEPLOYMENT"}
# Every key and endpoint a test here gives a provider; none may come from
# the shell, so each test sets what it needs.
PROVIDER_SETTINGS = {name for _, env in PROVIDERS.values() for name in env} | {
    "CUSTOM_API_KEY",
    "GEMINI_API_KEY",
    "OLLAMA_BASE_URL",
    "QWED_API_KEY",
}

# provider class -> the model it runs
MODEL_OF = {
    OpenAIDirectProvider: lambda provider: provider.model,
    AzureOpenAIProvider: lambda provider: provider.deployment,
    AnthropicProvider: lambda provider: provider.deployment,
    ClaudeOpusProvider: lambda provider: provider.deployment,
    OllamaProvider: lambda provider: provider.model,
    OpenAICompatProvider: lambda provider: provider.model,
    GeminiProvider: lambda provider: provider.model_name,
}

OPENAI_PROFILE = OnboardingProvider(
    slug="openai",
    name="OpenAI",
    active_provider="openai",
    key_env="OPENAI_API_KEY",
    model_env="OPENAI_MODEL",
    base_url_env=None,
    default_base_url=None,
    connection_slug="openai",
    key_pattern=None,
)


@pytest.fixture(autouse=True)
def _no_model_configured(monkeypatch):
    """Start with no provider, model, key or endpoint set, whatever the
    shell has."""
    for name in MODEL_VARIABLES | PROVIDER_SETTINGS | {"ACTIVE_PROVIDER"}:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake_genai(monkeypatch):
    """Stand in for google.generativeai, recording the model each
    GenerativeModel is built for."""
    built = []

    def generative_model(name):
        built.append(name)
        return SimpleNamespace(generate_content=lambda *_args, **_kwargs: SimpleNamespace(text=STATS_CODE))

    fake = SimpleNamespace(
        configure=lambda **_kwargs: None,
        GenerativeModel=generative_model,
        types=SimpleNamespace(GenerationConfig=lambda **kwargs: kwargs),
    )
    monkeypatch.setattr(gemini_provider, "genai", fake)
    return built


def _configure(monkeypatch, provider_cls, model):
    model_env, env = PROVIDERS[provider_cls]
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    if model is not None:
        monkeypatch.setenv(model_env, model)
    return model_env


def _chat_response(**_kwargs):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=STATS_CODE))])


def _text_response(**_kwargs):
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=STATS_CODE)])


def _recorder(sent, make_response):
    def create(**kwargs):
        sent.append(kwargs["model"])
        return make_response(**kwargs)

    return create


# --------------------------------------------------------------------------
# Server providers
# --------------------------------------------------------------------------


@pytest.mark.parametrize("model", [None, "", "   "], ids=["unset", "empty", "blank"])
@pytest.mark.parametrize("provider_cls", PROVIDERS, ids=lambda cls: cls.__name__)
def test_a_provider_with_no_model_configured_raises(monkeypatch, fake_genai, provider_cls, model):
    model_env = _configure(monkeypatch, provider_cls, model)

    with pytest.raises(ProviderConfigError, match=f"No model is configured .* Set {model_env} "):
        provider_cls()


@pytest.mark.parametrize("provider_cls", PROVIDERS, ids=lambda cls: cls.__name__)
def test_any_model_id_reaches_the_provider_api_unchanged(monkeypatch, fake_genai, provider_cls):
    _configure(monkeypatch, provider_cls, ANY_MODEL)
    provider = provider_cls()
    # Gemini records its model as it is built; the others as they call the API.
    sent = fake_genai
    if provider_cls in (AnthropicProvider, ClaudeOpusProvider):
        monkeypatch.setattr(provider.client.messages, "create", _recorder(sent, _text_response))
    elif provider_cls is not GeminiProvider:
        monkeypatch.setattr(provider.client.chat.completions, "create", _recorder(sent, _chat_response))

    assert provider.translate_stats("mean of a", ["a"]) == STATS_CODE
    assert sent == [ANY_MODEL]


@pytest.mark.parametrize(
    "provider_cls",
    [OpenAIDirectProvider, OllamaProvider, OpenAICompatProvider, GeminiProvider],
    ids=lambda cls: cls.__name__,
)
def test_a_model_passed_to_the_provider_wins_over_its_variable(monkeypatch, fake_genai, provider_cls):
    _configure(monkeypatch, provider_cls, "a-model-from-the-environment")

    provider = provider_cls(model=ANY_MODEL)

    assert MODEL_OF[provider_cls](provider) == ANY_MODEL


@pytest.mark.parametrize("deployment", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_anthropic_runs_the_model_qwed_init_sets(monkeypatch, deployment):
    _configure(monkeypatch, AnthropicProvider, ANY_MODEL)
    if deployment is not None:
        monkeypatch.setenv("ANTHROPIC_DEPLOYMENT", deployment)

    assert AnthropicProvider().deployment == ANY_MODEL


def test_anthropic_deployment_still_wins_over_its_model(monkeypatch):
    _configure(monkeypatch, AnthropicProvider, "a-model-from-qwed-init")
    monkeypatch.setenv("ANTHROPIC_DEPLOYMENT", ANY_MODEL)

    assert AnthropicProvider().deployment == ANY_MODEL


# --------------------------------------------------------------------------
# ReasoningVerifier: the configured provider, and only its own call
# --------------------------------------------------------------------------


def test_reasoning_verifier_uses_the_configured_provider(monkeypatch):
    monkeypatch.setenv("ACTIVE_PROVIDER", "gemini")

    assert ReasoningVerifier().provider_names == ["gemini"]


def test_reasoning_verifier_reads_an_unset_provider_as_the_server_does():
    assert ReasoningVerifier().provider_names == [ProviderType.OLLAMA.value]


LOADED = {
    "anthropic": AnthropicProvider,
    "claude_opus": ClaudeOpusProvider,
    "azure": AzureOpenAIProvider,
    "azure_openai": AzureOpenAIProvider,
    "openai": OpenAIDirectProvider,
    "openai_direct": OpenAIDirectProvider,
    "openai_compat": OpenAICompatProvider,
    "openai-compatible": OpenAICompatProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def test_every_provider_name_the_reasoning_verifier_takes_is_covered():
    assert set(_PROVIDER_NAMES) == (set(LOADED) - {"openai-compatible"}) | {"auto"}


@pytest.mark.parametrize("name, provider_cls", LOADED.items())
def test_reasoning_verifier_loads_each_provider_with_its_configured_model(
    monkeypatch, fake_genai, name, provider_cls
):
    _configure(monkeypatch, provider_cls, ANY_MODEL)

    provider = ReasoningVerifier(providers=[name], enable_cache=False).primary_llm

    assert type(provider) is provider_cls
    assert MODEL_OF[provider_cls](provider) == ANY_MODEL


def test_reasoning_verifier_takes_a_provider_type(monkeypatch):
    _configure(monkeypatch, OllamaProvider, ANY_MODEL)

    provider = ReasoningVerifier(providers=[ProviderType.OLLAMA], enable_cache=False).primary_llm

    assert type(provider) is OllamaProvider


def test_reasoning_verifier_loads_auto_shift(monkeypatch):
    _configure(monkeypatch, AzureOpenAIProvider, ANY_MODEL)

    provider = ReasoningVerifier(providers=["auto"], enable_cache=False).primary_llm

    assert type(provider) is AutoShiftProvider
    assert provider.primary.deployment == ANY_MODEL


def test_reasoning_verifier_loads_nothing_for_a_name_it_does_not_know():
    assert ReasoningVerifier._load_provider("not-a-provider") is None


def test_reasoning_verifier_has_no_provider_when_its_provider_has_no_model(monkeypatch, caplog):
    monkeypatch.setenv("ACTIVE_PROVIDER", "ollama")
    verifier = ReasoningVerifier(enable_cache=False)

    with caplog.at_level(logging.WARNING, logger="qwed_new.core.reasoning_verifier"):
        result = verifier.verify_understanding(
            query="Alice has 10 apples and gets 5 more. How many apples does she have?",
            primary_task=SimpleNamespace(expression="10 + 5", reasoning=""),
            enable_cross_validation=False,
        )

    assert not result.is_verified
    assert result.developer_fields["constraint_id"] == "reasoning_verifier.no_provider"
    assert "OLLAMA_MODEL" in caplog.text


def test_reasoning_trace_comes_only_from_the_providers_own_call():
    client = MagicMock()
    verifier = ReasoningVerifier(providers=["anthropic"], enable_cache=False)
    # A provider with a client but no complete(): QWED must not call the
    # client itself, with a model of its choosing.
    verifier._provider_loaders["anthropic"] = lambda: SimpleNamespace(client=client)

    trace = verifier._generate_reasoning_trace("What is 10 + 5?", SimpleNamespace(expression="10 + 5"))

    assert trace == ["Could not generate reasoning trace"]
    assert client.mock_calls == []


# --------------------------------------------------------------------------
# Server routing: the provider the user selected, and only that one
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "Write the sum of 2 and 3",
        "Compose x so that x > 5 and x < 3",
        "An essay question: what is 15% of 200?",
        "A creative way to compute 3 * 4",
        "A story problem: 7 - 2",
    ],
)
def test_the_wording_of_a_query_never_selects_a_provider(monkeypatch, query):
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "openai")

    assert Router().route(query) == "openai"


def test_an_unknown_active_provider_is_refused_not_switched_to_auto(monkeypatch):
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "openia")
    auto = MagicMock()
    monkeypatch.setattr("qwed_new.core.translator.AutoShiftProvider", auto)

    provider = Router().route("What is 2 + 2?")
    layer = TranslationLayer()
    with pytest.raises(ProviderConfigError, match="ACTIVE_PROVIDER is set to 'openia'"):
        layer.translate("What is 2 + 2?", provider=provider)

    assert provider == "openia"
    auto.assert_not_called()


@pytest.mark.parametrize("configured", ["", "   "], ids=["empty", "blank"])
def test_a_blank_active_provider_is_unset(monkeypatch, configured):
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", configured)

    assert Router().route("What is 2 + 2?") == ProviderType.OLLAMA.value
    assert TranslationLayer().default_provider == ProviderType.OLLAMA.value


class _LogicOnly:
    """A provider that translates one contradictory logic query."""

    def translate_logic(self, _user_query):
        return LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5", "x < 3"], goal="SATISFIABILITY")


def test_logic_verification_uses_the_configured_provider(monkeypatch):
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "ollama")
    monkeypatch.setattr("qwed_new.core.translator.OllamaProvider", _LogicOnly)

    result = DSLLogicVerifier().verify_from_natural_language("x is above 5 and below 3")

    assert result.provider_used == "ollama"
    assert result.status == "UNSAT"


def test_a_request_that_names_an_unknown_provider_is_refused(monkeypatch):
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "openai")
    configured = MagicMock()
    monkeypatch.setattr("qwed_new.core.translator.OpenAIDirectProvider", configured)

    provider = Router().route("What is 2 + 2?", "ollmaa")
    layer = TranslationLayer()
    with pytest.raises(ProviderConfigError, match="The request names a provider QWED does not know"):
        layer.translate("What is 2 + 2?", provider=provider)

    assert provider == "unknown"
    configured.assert_not_called()


def test_logic_verification_refuses_an_unknown_provider_without_echoing_it(monkeypatch):
    # The configured provider would answer; it must not stand in for the one named.
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "ollama")
    monkeypatch.setattr("qwed_new.core.translator.OllamaProvider", _LogicOnly)
    verifier = DSLLogicVerifier()

    result = verifier.verify_from_natural_language("x is above 5 and below 3", provider="ollmaa")

    assert result.status == "ERROR"
    assert "The request names a provider QWED does not know" in result.error
    assert result.provider_used == "unknown"


@pytest.mark.parametrize(
    "active_provider, setting_to_fix",
    [("openia", "ACTIVE_PROVIDER is set to 'openia'"), ("ollama", "Set OLLAMA_MODEL")],
    ids=["unknown-provider", "no-model"],
)
def test_logic_verification_names_the_setting_to_fix(monkeypatch, caplog, active_provider, setting_to_fix):
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", active_provider)
    verifier = DSLLogicVerifier()

    with caplog.at_level(logging.WARNING, logger="qwed_new.core.dsl_logic_verifier"):
        result = verifier.verify_from_natural_language("x is above 5 and below 3")

    assert result.status == "ERROR"
    assert setting_to_fix in result.error
    assert setting_to_fix in caplog.text


# --------------------------------------------------------------------------
# SDK: QWEDLocal, verify() and the LangChain tool
# --------------------------------------------------------------------------


@pytest.mark.parametrize("model", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_qwedlocal_without_a_model_raises(model):
    with pytest.raises(ValueError, match="QWEDLocal needs a model"):
        qwed_local_module.QWEDLocal(base_url="http://localhost:1/v1", model=model, cache=False)


def test_qwedlocal_sends_any_model_id_unchanged(monkeypatch):
    client = qwed_local_module.QWEDLocal(base_url="http://localhost:1/v1", model=ANY_MODEL, cache=False)
    sent = []
    monkeypatch.setattr(client.llm_client.chat.completions, "create", _recorder(sent, _chat_response))

    assert client._call_llm("What is 2 + 2?") == STATS_CODE
    assert sent == [ANY_MODEL]


def test_qwedlocal_anthropic_sends_any_model_id_unchanged(monkeypatch):
    client = qwed_local_module.QWEDLocal(provider="anthropic", api_key=FAKE_KEY, model=ANY_MODEL, cache=False)
    sent = []
    monkeypatch.setattr(client.llm_client.messages, "create", _recorder(sent, _text_response))

    assert client._call_llm("What is 2 + 2?") == STATS_CODE
    assert sent == [ANY_MODEL]


def test_verify_without_a_model_raises():
    with pytest.raises(ValueError, match="verify\\(\\) needs model="):
        qwed_local_module.verify("What is 2+2?")


def test_verify_uses_the_llm_the_caller_names(monkeypatch):
    built = []

    class Recorder:
        def __init__(self, **kwargs):
            built.append(kwargs)

        def verify(self, query):
            return f"verified {query}"

    monkeypatch.setattr(qwed_local_module, "QWEDLocal", Recorder)

    result = qwed_local_module.verify("2+2", provider="openai", api_key=FAKE_KEY, model=ANY_MODEL)

    assert result == "verified 2+2"
    assert built == [{"provider": "openai", "api_key": FAKE_KEY, "model": ANY_MODEL}]


def test_langchain_tool_needs_a_model_when_it_is_built():
    pytest.importorskip("langchain_core")
    from pydantic import ValidationError

    from qwed_sdk.integrations.langchain import QWEDTool

    # Refused when the tool is built, not when an agent first runs it.
    with pytest.raises(ValidationError, match="model"):
        QWEDTool()
    with pytest.raises(ValidationError, match="QWEDTool needs a model"):
        QWEDTool(model="   ")
    assert QWEDTool(model=ANY_MODEL).model == ANY_MODEL


# --------------------------------------------------------------------------
# CLI: qwed verify, qwed interactive and qwed init
# --------------------------------------------------------------------------


@pytest.fixture
def no_dotenv():
    """Keep a developer's .env from supplying the model `qwed verify` and
    `qwed interactive` load."""
    with patch("qwed_sdk.cli._load_saved_env", return_value=None):
        yield


def _verified():
    return SimpleNamespace(verified=True, value="4", error=None)


@pytest.mark.usefixtures("no_dotenv")
def test_qwed_verify_stops_without_a_model(monkeypatch):
    monkeypatch.setenv("ACTIVE_PROVIDER", "ollama")

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(verify, ["What is 2+2?"])

    assert result.exit_code == 1
    assert "No model is configured. Pass --model or set OLLAMA_MODEL." in result.output
    built.assert_not_called()


@pytest.mark.usefixtures("no_dotenv")
def test_qwed_verify_with_a_base_url_needs_model_flag():
    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(verify, ["What is 2+2?", "--base-url", "http://localhost:1/v1"])

    assert result.exit_code == 1
    assert "No model is configured. Pass --model." in result.output
    built.assert_not_called()


@pytest.mark.usefixtures("no_dotenv")
def test_qwed_verify_sends_the_selected_providers_model(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", ANY_MODEL)

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        built.return_value.verify.return_value = _verified()
        result = CliRunner().invoke(
            verify, ["What is 2+2?", "--provider", "anthropic", "--api-key", FAKE_KEY]
        )

    assert result.exit_code == 0
    assert built.call_args.kwargs["provider"] == "anthropic"
    assert built.call_args.kwargs["model"] == ANY_MODEL


@pytest.mark.usefixtures("no_dotenv")
def test_qwed_verify_reads_a_blank_model_flag_as_none(monkeypatch):
    with patch("qwed_sdk.cli.QWEDLocal") as built:
        stopped = CliRunner().invoke(
            verify, ["What is 2+2?", "--provider", "anthropic", "--api-key", FAKE_KEY, "--model", "   "]
        )
        monkeypatch.setenv("ANTHROPIC_MODEL", ANY_MODEL)
        built.return_value.verify.return_value = _verified()
        ran = CliRunner().invoke(
            verify, ["What is 2+2?", "--provider", "anthropic", "--api-key", FAKE_KEY, "--model", "   "]
        )

    assert stopped.exit_code == 1
    assert "No model is configured. Pass --model or set ANTHROPIC_MODEL." in stopped.output
    assert ran.exit_code == 0
    assert built.call_count == 1
    assert built.call_args.kwargs["model"] == ANY_MODEL


def test_qwed_verify_reads_the_model_qwed_init_saved_without_server_settings(monkeypatch, tmp_path):
    """`qwed verify` loads the .env `qwed init` writes, as `qwed interactive`
    does, without the server's settings: they raise without API_KEY_SECRET,
    which a command that calls the model provider directly does not use."""
    (tmp_path / ".env").write_text(f"OLLAMA_MODEL={ANY_MODEL}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # python-dotenv loads nothing while this is set in the shell.
    monkeypatch.delenv("PYTHON_DOTENV_DISABLED", raising=False)
    # With None in sys.modules, importing the server's settings fails.
    monkeypatch.setitem(sys.modules, "qwed_new.config", None)

    # patch.dict puts back the environment the .env load writes to.
    with patch.dict("os.environ"), patch("qwed_sdk.cli.QWEDLocal") as built:
        built.return_value.verify.return_value = _verified()
        result = CliRunner().invoke(verify, ["What is 2+2?"])

    assert result.exit_code == 0, result.output
    assert built.call_args.kwargs["model"] == ANY_MODEL


@pytest.mark.usefixtures("no_dotenv")
def test_qwed_interactive_stops_without_a_model():
    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(interactive, [], input="exit\n")

    assert result.exit_code == 1
    assert "No model is configured. Pass --model or set OLLAMA_MODEL." in result.output
    built.assert_not_called()


@pytest.mark.usefixtures("no_dotenv")
def test_qwed_interactive_sends_the_configured_model(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", ANY_MODEL)

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(interactive, [], input="exit\n")

    assert result.exit_code == 0
    assert built.call_args.kwargs["model"] == ANY_MODEL


def test_qwed_interactive_reads_the_model_qwed_init_saved(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text(f"OLLAMA_MODEL={ANY_MODEL}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # python-dotenv loads nothing while this is set in the shell.
    monkeypatch.delenv("PYTHON_DOTENV_DISABLED", raising=False)

    # patch.dict puts back the environment the .env load writes to.
    with patch.dict("os.environ"), patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(interactive, [], input="exit\n")

    assert result.exit_code == 0
    assert built.call_args.kwargs["model"] == ANY_MODEL


@pytest.mark.usefixtures("no_dotenv")
def test_qwed_interactive_runs_the_provider_qwed_init_saved(monkeypatch):
    monkeypatch.setenv("ACTIVE_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_MODEL", ANY_MODEL)
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(interactive, [], input="exit\n")

    assert result.exit_code == 0
    assert built.call_args.kwargs == {"provider": "openai", "api_key": FAKE_KEY, "model": ANY_MODEL}


@pytest.mark.usefixtures("no_dotenv")
@pytest.mark.parametrize(
    "saved, url_env, model_env",
    [("ollama", "OLLAMA_BASE_URL", "OLLAMA_MODEL"), ("openai-compatible", "CUSTOM_BASE_URL", "CUSTOM_MODEL")],
)
def test_qwed_interactive_uses_the_saved_endpoint(monkeypatch, saved, url_env, model_env):
    monkeypatch.setenv("ACTIVE_PROVIDER", saved)
    monkeypatch.setenv(url_env, "http://localhost:1/v1")
    monkeypatch.setenv(model_env, ANY_MODEL)

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(interactive, [], input="exit\n")

    assert result.exit_code == 0
    assert built.call_args.kwargs["base_url"] == "http://localhost:1/v1"
    assert built.call_args.kwargs["model"] == ANY_MODEL


@pytest.mark.parametrize(
    "saved, provider, url_env",
    [
        ("OpenAI", "openai", None),
        (" openai ", "openai", None),
        ("openai_direct", "openai", None),
        ("OPENAI-DIRECT", "openai", None),
        ("Anthropic", "anthropic", None),
        ("OpenAI-Compatible", None, "CUSTOM_BASE_URL"),
        ("openai_compatible", None, "CUSTOM_BASE_URL"),
        ("OLLAMA", None, "OLLAMA_BASE_URL"),
    ],
)
def test_the_cli_reads_a_saved_provider_as_the_server_does(monkeypatch, saved, provider, url_env):
    monkeypatch.setenv("ACTIVE_PROVIDER", saved)
    if url_env:
        monkeypatch.setenv(url_env, "http://localhost:1/v1")

    resolved = saved_provider()

    assert resolved.provider == provider
    assert resolved.base_url == ("http://localhost:1/v1" if url_env else None)


@pytest.mark.usefixtures("no_dotenv")
@pytest.mark.parametrize(
    "saved, settings",
    [
        ("openai-compatible", {"CUSTOM_BASE_URL": "http://localhost:1/v1", "CUSTOM_MODEL": ANY_MODEL}),
        ("openai", {"OPENAI_MODEL": ANY_MODEL}),
    ],
)
def test_the_qwed_key_never_reaches_the_saved_provider(monkeypatch, saved, settings):
    provider_key, qwed_key, flag_key = (f"{FAKE_KEY}-{name}" for name in ("provider", "qwed", "flag"))
    monkeypatch.setenv("ACTIVE_PROVIDER", saved)
    monkeypatch.setenv("QWED_API_KEY", qwed_key)
    monkeypatch.setenv("CUSTOM_API_KEY" if saved == "openai-compatible" else "OPENAI_API_KEY", provider_key)
    for name, value in settings.items():
        monkeypatch.setenv(name, value)

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        built.return_value.verify.return_value = _verified()
        from_env = CliRunner().invoke(verify, ["What is 2+2?"])
        sent_from_env = built.call_args.kwargs["api_key"]
        from_flag = CliRunner().invoke(verify, ["What is 2+2?", "--api-key", flag_key])

    assert from_env.exit_code == from_flag.exit_code == 0
    # QWED_API_KEY, which --api-key also reads, may be the QWED server's key.
    assert sent_from_env == provider_key
    assert built.call_args.kwargs["api_key"] == flag_key


@pytest.mark.usefixtures("no_dotenv")
@pytest.mark.parametrize(
    "saved, model_env, hint",
    [
        ("openai", "OPENAI_MODEL", "Set OPENAI_API_KEY or use --api-key"),
        ("gemini", "GEMINI_MODEL", "Set GOOGLE_API_KEY or GEMINI_API_KEY or use --api-key"),
    ],
)
def test_a_saved_provider_without_its_key_names_its_variable(monkeypatch, saved, model_env, hint):
    monkeypatch.setenv("ACTIVE_PROVIDER", saved)
    monkeypatch.setenv(model_env, ANY_MODEL)
    monkeypatch.setenv("QWED_API_KEY", f"{FAKE_KEY}-qwed")

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(verify, ["What is 2+2?"])

    assert result.exit_code == 1
    assert hint in result.output
    built.assert_not_called()


@pytest.mark.parametrize(
    "keys, sent",
    [({"GEMINI_API_KEY": "gemini"}, "gemini"), ({"GOOGLE_API_KEY": "google", "GEMINI_API_KEY": "gemini"}, "google")],
    ids=["gemini-only", "google-first"],
)
def test_a_saved_gemini_reads_its_key_as_the_server_does(monkeypatch, keys, sent):
    monkeypatch.setenv("ACTIVE_PROVIDER", "gemini")
    for name, value in keys.items():
        monkeypatch.setenv(name, f"{FAKE_KEY}-{value}")

    assert saved_provider().api_key == f"{FAKE_KEY}-{sent}"


@pytest.mark.usefixtures("no_dotenv")
@pytest.mark.parametrize("command, args", [(verify, ["What is 2+2?"]), (interactive, [])], ids=["verify", "interactive"])
def test_a_saved_anthropic_endpoint_is_never_bypassed(monkeypatch, command, args):
    # The CLI calls the Anthropic API directly; the key and the prompt must
    # not leave for it when another endpoint is configured.
    monkeypatch.setenv("ACTIVE_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_ENDPOINT", "http://localhost:1")
    monkeypatch.setenv("ANTHROPIC_MODEL", ANY_MODEL)
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(command, args, input="exit\n")

    assert result.exit_code == 1
    assert "ANTHROPIC_ENDPOINT is set, but the qwed CLI calls the Anthropic API directly" in result.output
    built.assert_not_called()


@pytest.mark.usefixtures("no_dotenv")
@pytest.mark.parametrize("command, args", [(verify, ["What is 2+2?"]), (interactive, [])], ids=["verify", "interactive"])
def test_a_provider_only_the_server_runs_stops_the_cli(monkeypatch, command, args):
    # No other provider, Ollama included, stands in for the one saved.
    monkeypatch.setenv("ACTIVE_PROVIDER", "azure_openai")

    with patch("qwed_sdk.cli.QWEDLocal") as built:
        result = CliRunner().invoke(command, args, input="exit\n")

    assert result.exit_code == 1
    assert "ACTIVE_PROVIDER is 'azure_openai', which the qwed CLI cannot run." in result.output
    built.assert_not_called()


@pytest.mark.parametrize("variable, expected", [(ANY_MODEL, ANY_MODEL), (None, "")], ids=["variable-set", "unset"])
def test_qwed_init_reads_a_blank_model_flag_as_none(monkeypatch, variable, expected):
    if variable:
        monkeypatch.setenv("OPENAI_MODEL", variable)

    assert _resolve_provider_model(OPENAI_PROFILE, "   ") == expected


def test_qwed_init_non_interactive_stops_without_a_model(monkeypatch):
    engines = [{"name": "SymPy", "ready": True, "detail": "math engine ready", "install_hint": "", "version": "1"}]
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    monkeypatch.setattr("qwed_sdk.cli._load_dotenv_if_available", lambda: None)
    monkeypatch.setattr("qwed_sdk.cli._required_engine_report", lambda: (True, engines))
    monkeypatch.setattr("qwed_sdk.cli._build_onboarding_provider_map", lambda _get_provider: {"openai": OPENAI_PROFILE})

    result = CliRunner().invoke(
        init,
        ["--provider", "openai", "--organization-name", "demo-org", "--non-interactive", "--skip-tests"],
    )

    assert result.exit_code == 1
    assert "OPENAI_MODEL is required for provider 'openai'. Pass --model or set OPENAI_MODEL." in result.output


def test_qwed_init_retry_stops_on_a_blank_model(monkeypatch):
    answers = iter([FAKE_KEY, "   "])  # the retry's API key, then its model
    monkeypatch.setattr("qwed_sdk.cli.click.prompt", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr("qwed_sdk.cli.click.confirm", lambda *_args, **_kwargs: True)
    connect = MagicMock(return_value=(False, "Connection refused"))

    with pytest.raises(RuntimeError, match="OPENAI_MODEL is required for provider 'openai'"):
        _test_provider_connection_loop(
            profile=OPENAI_PROFILE,
            resolved_key=FAKE_KEY,
            resolved_base_url="",
            resolved_model=ANY_MODEL,
            non_interactive=False,
            test_connection=connect,
        )

    # The blank model is never tested, so it can never be saved.
    assert connect.call_count == 1


# --------------------------------------------------------------------------
# Provider registry and imported provider YAML
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", registry_module.PROVIDER_REGISTRY)
def test_built_in_providers_name_no_model(slug):
    meta = registry_module.PROVIDER_REGISTRY[slug]
    model_vars = [env_var for env_var in meta.env_vars if env_var.name.endswith("_MODEL")]

    assert meta.default_model is None
    assert model_vars
    assert all(env_var.required and env_var.default is None for env_var in model_vars)


def _dynamic_provider(config):
    class Manager:
        def load_providers(self):
            return {"do": config}

    with patch("qwed_new.providers.config_manager.ProviderConfigManager", Manager):
        registry_module._get_dynamic_providers.cache_clear()
        try:
            return registry_module._get_dynamic_providers()["yaml-do"]
        finally:
            registry_module._get_dynamic_providers.cache_clear()


def test_a_provider_yaml_without_a_model_requires_one():
    meta = _dynamic_provider({"base_url": "https://inference.do-ai.run/v1", "api_key_env": "DO_API_KEY"})
    model_var = meta.env_vars[2]

    assert meta.default_model is None
    assert (model_var.name, model_var.required, model_var.default) == ("CUSTOM_MODEL", True, None)


def test_a_provider_yaml_keeps_the_model_it_names():
    meta = _dynamic_provider(
        {"base_url": "https://inference.do-ai.run/v1", "api_key_env": "DO_API_KEY", "default_model": ANY_MODEL}
    )
    model_var = meta.env_vars[2]

    assert meta.default_model == ANY_MODEL
    assert (model_var.required, model_var.default) == (False, ANY_MODEL)


# --------------------------------------------------------------------------
# No runtime code names a default model
# --------------------------------------------------------------------------

RUNTIME_PACKAGES = ("src/qwed_new", "qwed_sdk", "qwed")
MODEL_KEYS = ("model", "default_model", "model_name")
# Model names that are not a user's LLM: a cache label, and the local NLI
# classifier behind graph_fact_verifier's advisory check, with its unused
# model parameter.
NOT_A_USERS_LLM = {
    ("qwed_sdk/qwed_local.py", "a literal model='code_verifier' argument"),
    ("src/qwed_new/core/graph_fact_verifier.py", "a literal model='cross-encoder/nli-deberta-v3-small' argument"),
    ("src/qwed_new/core/graph_fact_verifier.py", "parameter model defaults to 'default'"),
}


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _is_text(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _names_a_model_variable(node):
    return _is_text(node) and node.value.endswith(("_MODEL", "_DEPLOYMENT"))


def _call_model_defaults(node):
    """A call that reads a model with a fallback, or passes a literal model."""
    func = _dotted(node.func)
    args = node.args
    reads_a_variable = func.endswith(("getenv", "environ.get")) and args and _names_a_model_variable(args[0])
    if reads_a_variable and len(args) > 1 and not (isinstance(args[1], ast.Constant) and args[1].value is None):
        yield "a model variable read with a fallback"
    if func.endswith(".get") and len(args) > 1 and _is_text(args[0]) and args[0].value in MODEL_KEYS:
        if _is_text(args[1]) and args[1].value:
            yield f"{args[0].value!r} looked up with a literal fallback"
    if func.endswith("EnvVar") and args and _names_a_model_variable(args[0]):
        if any(kw.arg == "default" and _is_text(kw.value) for kw in node.keywords):
            yield "a model variable spec with a literal default"
    for kw in node.keywords:
        if kw.arg in MODEL_KEYS and _is_text(kw.value):
            yield f"a literal {kw.arg}={kw.value.value!r} argument"
        values = kw.value.values if isinstance(kw.value, ast.BoolOp) else []
        if kw.arg in MODEL_KEYS and any(_is_text(value) for value in values):
            yield f"{kw.arg}= with a literal fallback"


def _target_name(node):
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _supplies_text(node):
    """A non-empty literal, or an `x or "<literal>"` fallback."""
    values = node.values if isinstance(node, ast.BoolOp) else [node]
    return any(_is_text(value) and value.value for value in values)


def _model_defaults(source):
    """Yield (line, what) for each place the code supplies a model itself."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            for what in _call_model_defaults(node):
                yield node.lineno, what
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = node.args.args + node.args.kwonlyargs
            defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + node.args.defaults
            defaults += node.args.kw_defaults
            for param, default in zip(params, defaults):
                if param.arg in MODEL_KEYS and default is not None and _is_text(default):
                    yield node.lineno, f"parameter {param.arg} defaults to {default.value!r}"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for name in map(_target_name, targets):
                if name in MODEL_KEYS and _supplies_text(node.value):
                    yield node.lineno, f"{name} is set to a literal"


def test_the_scan_finds_each_way_code_named_a_model():
    source = '''
import os
A = os.getenv("OLLAMA_MODEL", "llama3")
B = os.environ.get("ANTHROPIC_DEPLOYMENT", "claude-sonnet-4-5")
C = kwargs.get("model", "llama3")
D = EnvVar("OPENAI_MODEL", "Model name", required=False, default="gpt-4o-mini")
client.messages.create(model="claude-3-haiku-20240307")
QWEDLocal(model=model or "gpt-3.5-turbo")
def __init__(self, model: str = "gpt-3.5-turbo"): pass
class Tool:
    model: str = "gpt-4o-mini"
if not model:
    model = "llama3"
self.model_name = model_name or "gemini-1.5-pro"
'''
    assert len(list(_model_defaults(source))) == 10


def test_no_runtime_code_names_a_default_model():
    found = [
        f"{path.relative_to(ROOT).as_posix()}:{line}: {what}"
        for package in RUNTIME_PACKAGES
        for path in sorted((ROOT / package).rglob("*.py"))
        for line, what in _model_defaults(path.read_text(encoding="utf-8"))
        if (path.relative_to(ROOT).as_posix(), what) not in NOT_A_USERS_LLM
    ]

    assert found == []
