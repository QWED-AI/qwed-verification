"""#585 Part A: results name the model that translated.

The natural-language and logic routes record the provider beside each
verdict, but not the model, and the natural-language route dropped the
provider from its response and audit row. Now both name the provider and
the model, as ``provider_used`` and ``translation_model``.

The model is read from the provider's configuration, never from a model's
own answer, and it admits nothing: the verdict and the admission are the
same with and without it. Under auto-shift it is the side that answered the
call, kept per thread, since requests translate on worker threads at once.
"""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from qwed_new.api import main as api_main
from qwed_new.config import settings
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import LogicVerificationTask, MathVerificationTask
from qwed_new.core.translator import TranslationLayer
from qwed_new.providers import auto_shift
from qwed_new.providers.anthropic import AnthropicProvider
from qwed_new.providers.base import LLMProvider
from qwed_new.providers.azure_openai import AzureOpenAIProvider
from qwed_new.providers.gemini_provider import GeminiProvider
from qwed_new.providers.ollama_provider import OllamaProvider
from qwed_new.providers.openai_compat import OpenAICompatProvider
from qwed_new.providers.openai_direct import OpenAIDirectProvider
from tests.test_issue_320_logic_route_admission import (  # noqa: F401  (client is a fixture)
    MISTRANSLATED_CLAIM,
    MISTRANSLATION,
    QUESTION,
    _rows,
    client,
)

MATH_MODEL = "configured-math-model"
LOGIC_MODEL = "configured-logic-model"


@pytest.mark.parametrize(
    "provider_class, attribute",
    [
        (AnthropicProvider, "deployment"),
        (AzureOpenAIProvider, "deployment"),
        (GeminiProvider, "model_name"),
        (OllamaProvider, "model"),
        (OpenAICompatProvider, "model"),
        (OpenAIDirectProvider, "model"),
    ],
)
def test_a_provider_names_the_model_it_calls(provider_class, attribute):
    # The attribute each provider sends as the model in its requests.
    provider = provider_class.__new__(provider_class)
    provider.__dict__[attribute] = "configured-model"
    assert provider.model_id == "configured-model"


def test_a_configured_provider_names_its_configured_model():
    assert OllamaProvider(model="local-model").model_id == "local-model"


class _Provider(LLMProvider):
    """A provider QWED knows, with no network. It names no model of its own."""

    def translate(self, user_query):
        raise NotImplementedError

    def translate_logic(self, user_query):
        raise NotImplementedError

    def refine_logic(self, user_query, previous_error):
        raise NotImplementedError

    def translate_stats(self, query, columns):
        raise NotImplementedError

    def verify_fact(self, claim, context):
        raise NotImplementedError

    def verify_image(self, image_bytes, claim):
        raise NotImplementedError


class _Configured(_Provider):
    """A provider QWED knows, with a configured model."""

    def __init__(self, model):
        self._model = model

    @property
    def model_id(self):
        return self._model


def test_a_provider_that_overrides_nothing_names_no_model():
    assert _Provider().model_id is None


class _Side(_Configured):
    """One side of auto-shift: answers, or fails, with its configured model."""

    def __init__(self, model):
        super().__init__(model)
        self.fails = False
        self.calls = 0

    def translate(self, user_query):
        self.calls += 1
        if self.fails:
            raise RuntimeError("side down")
        return f"translated by {self.model_id}"


def _auto(monkeypatch, primary=None):
    primary = primary or _Side("azure-deployment")
    secondary = _Side("anthropic-model")
    monkeypatch.setattr(auto_shift, "AzureOpenAIProvider", lambda: primary)
    monkeypatch.setattr(auto_shift, "AnthropicProvider", lambda: secondary)
    return auto_shift.AutoShiftProvider(), primary, secondary


def test_auto_shift_names_the_primary_when_it_answers(monkeypatch):
    auto, _, _ = _auto(monkeypatch)
    auto.translate("q")
    assert auto.model_id == "azure-deployment"


def test_naming_the_model_never_sends_an_answered_call_to_the_other_side(monkeypatch):
    # A side that is not a provider QWED knows names no model. Reading it
    # comes after the call, so the primary's answer stands and the
    # secondary is never asked.
    class _Unnamed:
        def translate(self, user_query):
            return "translated by the primary"

    auto, _, secondary = _auto(monkeypatch, primary=_Unnamed())
    assert auto.translate("q") == "translated by the primary"
    assert secondary.calls == 0
    assert auto.model_id is None


def test_auto_shift_names_the_secondary_when_the_primary_fails(monkeypatch):
    auto, primary, _ = _auto(monkeypatch)
    primary.fails = True
    auto.translate("q")
    assert auto.model_id == "anthropic-model"


def test_auto_shift_names_no_model_when_neither_side_answers(monkeypatch):
    auto, primary, secondary = _auto(monkeypatch)
    auto.translate("q")
    primary.fails = secondary.fails = True
    with pytest.raises(RuntimeError):
        auto.translate("q")
    # The earlier call's model does not outlive this call.
    assert auto.model_id is None


def test_auto_shift_keeps_each_threads_answer_apart(monkeypatch):
    auto, primary, _ = _auto(monkeypatch)
    seen = {}
    first_answered = threading.Event()
    second_answered = threading.Event()

    def first():
        auto.translate("q")
        first_answered.set()
        # The second thread's call, answered by the other side, lands here.
        second_answered.wait(5)
        seen["first"] = auto.model_id

    def second():
        first_answered.wait(5)
        primary.fails = True
        auto.translate("q")
        seen["second"] = auto.model_id
        second_answered.set()

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert seen == {"first": "azure-deployment", "second": "anthropic-model"}
    # This thread made no call, so it names no model.
    assert auto.model_id is None


def test_the_translation_layer_names_only_a_provider_that_has_run():
    layer = TranslationLayer()
    assert layer.translation_model("openai") is None

    layer._providers["openai"] = _Side("gpt-configured")
    assert layer.translation_model("openai") == "gpt-configured"
    assert layer.translation_model("OpenAI") == "gpt-configured"

    layer._providers[layer.default_provider] = _Side("default-model")
    assert layer.translation_model(None) == "default-model"


def test_the_translation_layer_names_no_model_for_an_unknown_provider_object():
    # Not a provider QWED knows (a stand-in), so it names nothing, and
    # reading it cannot fail a translation that succeeded.
    layer = TranslationLayer()
    layer._providers["openai"] = MagicMock()
    assert layer.translation_model("openai") is None


def test_the_translation_layer_names_no_model_that_is_not_text():
    layer = TranslationLayer()
    layer._providers["openai"] = _Configured(MagicMock())
    assert layer.translation_model("openai") is None
    layer._providers["openai"] = _Configured("")
    assert layer.translation_model("openai") is None


class _MathProvider(_Configured):
    """A provider with a configured model that translates the question."""

    def translate(self, user_query):
        return MathVerificationTask(
            expression="0.15 * 200", claimed_answer=30.0, reasoning="15% of 200", confidence=0.95
        )


def _natural_language(client, model):  # noqa: F811
    control_plane = api_main.control_plane
    with (
        patch.object(control_plane.router, "route", return_value="openai"),
        patch.dict(control_plane.translator._providers, {"openai": _MathProvider(model)}),
    ):
        return client.post("/verify/natural_language", json={"query": "What is 15% of 200?"}).json()


def test_the_natural_language_route_names_the_provider_and_model(client, isolated_audit_chain):  # noqa: F811
    body = _natural_language(client, MATH_MODEL)

    fields = body["developer_fields"]
    assert fields["provider_used"] == "openai"
    assert fields["translation_model"] == MATH_MODEL
    (row,) = _rows(isolated_audit_chain)
    stored = json.loads(row.result)["developer_fields"]
    assert stored["provider_used"] == "openai"
    assert stored["translation_model"] == MATH_MODEL


def test_the_model_admits_nothing(client, isolated_audit_chain):  # noqa: F811
    named = _natural_language(client, MATH_MODEL)
    unnamed = _natural_language(client, None)

    assert named["status"] == unnamed["status"] == "VERIFIED"
    assert named["admission"] == unnamed["admission"] == "BLOCKED"
    assert unnamed["developer_fields"]["translation_model"] is None
    for row in _rows(isolated_audit_chain):
        assert row.is_verified is False


@pytest.mark.asyncio
async def test_the_control_plane_puts_the_model_in_the_trust_boundary():
    control_plane = api_main.control_plane
    with (
        patch.object(control_plane.router, "route", return_value="openai"),
        patch.dict(control_plane.translator._providers, {"openai": _MathProvider(MATH_MODEL)}),
    ):
        result = await control_plane.process_natural_language("What is 15% of 200?")

    assert result["trust_boundary"]["provider_used"] == "openai"
    assert result["trust_boundary"]["translation_model"] == MATH_MODEL
    assert result["trust_boundary"]["query_semantics_verified"] is False
    assert result["translation_model"] == MATH_MODEL


def test_the_logic_route_names_the_provider_and_model(client, isolated_audit_chain):  # noqa: F811
    translated = (MISTRANSLATION, None, "openai", None, MISTRANSLATED_CLAIM, LOGIC_MODEL)
    with patch.object(api_main.control_plane.logic_verifier, "translate_to_dsl", return_value=translated):
        body = client.post("/verify/logic", json={"query": QUESTION}).json()

    assert body["status"] == "VERIFIED"
    assert body["admission"] == "BLOCKED"
    fields = body["developer_fields"]
    assert fields["provider_used"] == "openai"
    assert fields["translation_model"] == LOGIC_MODEL
    (row,) = _rows(isolated_audit_chain)
    assert row.is_verified is False
    assert json.loads(row.result)["developer_fields"]["translation_model"] == LOGIC_MODEL


class _LogicProvider(_Configured):
    """The configured provider: answers, or fails, with its configured model."""

    fails = False

    def __init__(self):
        super().__init__(LOGIC_MODEL)

    def translate_logic(self, user_query):
        if self.fails:
            raise RuntimeError("provider down")
        return LogicVerificationTask(
            variables={"x": "Int"}, constraints=["x > 5"], claim="x > 3", goal="VALIDITY"
        )


def _configure(monkeypatch, provider_class):
    # The real TranslationLayer and DSL bridge run; only the provider stands in.
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "ollama")
    monkeypatch.setattr("qwed_new.core.translator.OllamaProvider", provider_class)


def test_the_dsl_bridge_returns_the_model_with_the_translation(monkeypatch):
    _configure(monkeypatch, _LogicProvider)
    dsl_code, _, provider, error, claim, model = DSLLogicVerifier().translate_to_dsl(QUESTION)

    assert dsl_code == "(GT x 5)"
    assert claim == "(GT x 3)"
    assert error is None
    assert provider == "ollama"
    assert model == LOGIC_MODEL


def test_the_dsl_bridge_names_the_model_asked_when_translation_fails(monkeypatch):
    class _Failing(_LogicProvider):
        fails = True

    _configure(monkeypatch, _Failing)
    dsl_code, _, provider, error, _, model = DSLLogicVerifier().translate_to_dsl(QUESTION)

    assert dsl_code is None
    assert error.status == "ERROR"
    assert error.error == "LLM translation failed"
    assert error.provider_used == "ollama"
    assert provider == "ollama"
    assert model == LOGIC_MODEL


def test_two_first_requests_at_once_use_one_provider(monkeypatch):
    # The second thread's provider is built and stored while the first
    # thread's is still being built (CodeAnt). Both threads must then use
    # the stored one, the instance translation_model reads (#585).
    first_building = threading.Event()
    second_stored = threading.Event()
    built = []

    class _Slow(_Configured):
        def __init__(self):
            super().__init__(f"model-{len(built) + 1}")
            built.append(self)
            if len(built) == 1:
                first_building.set()
                second_stored.wait(5)

    _configure(monkeypatch, _Slow)
    layer = TranslationLayer()
    got = {}

    def first():
        got["first"] = layer._get_provider("ollama")

    def second():
        first_building.wait(5)
        got["second"] = layer._get_provider("ollama")
        second_stored.set()

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert len(built) == 2
    assert got["first"] is got["second"]
    assert got["first"] is layer._providers["ollama"]
    assert layer.translation_model("ollama") == got["first"].model_id
