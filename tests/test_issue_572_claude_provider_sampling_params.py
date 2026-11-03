"""#572: every call of the Anthropic and Claude Opus providers failed on anthropic 1.x and later.

Each messages.create call passed temperature=0.0. The SDK has had no
temperature, top_p or top_k parameter since 1.0, so every call raised TypeError
before a request was sent: translations were refused with a sanitized error,
and verify_image returned its ERROR verdict. API version 2026-10-21, which the
2.x SDK sends, also refuses the three parameters with a 400.

Each provider method is driven here through a stand-in for messages.create that
binds its arguments to the installed SDK's own signature, so a parameter the SDK
does not take fails the test as it failed in production.
"""

import inspect
from types import SimpleNamespace

import pytest
from anthropic.resources.messages import Messages

from qwed_new.providers.anthropic import AnthropicProvider
from qwed_new.providers.claude_opus import ClaudeOpusProvider

SAMPLING_PARAMETERS = {"temperature", "top_p", "top_k"}
CREATE_SIGNATURE = inspect.signature(Messages.create)

PROVIDERS = {
    "anthropic": (
        AnthropicProvider,
        {"ANTHROPIC_ENDPOINT": "http://localhost:1", "ANTHROPIC_API_KEY": "test-sentinel"},
    ),
    "claude_opus": (
        ClaudeOpusProvider,
        {"CLAUDE_OPUS_ENDPOINT": "http://localhost:1", "CLAUDE_OPUS_API_KEY": "test-sentinel"},
    ),
}


def _tool_use(payload):
    return SimpleNamespace(content=[SimpleNamespace(type="tool_use", input=payload)])


def _text(text):
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


# The providers convert vars_map to variables in place, so each call gets a
# response of its own: a shared one would reach the second provider already
# converted.
def _logic():
    return _tool_use({"vars_map": {"x": "Int"}, "constraints": ["x > 1"], "goal": "SATISFIABILITY"})


# (id, providers with the method, call, response factory, check on the result)
CALLS = [
    (
        "translate",
        ("anthropic", "claude_opus"),
        lambda p: p.translate("What is 2 + 2?"),
        lambda: _tool_use({"expression": "2 + 2", "claimed_answer": 4.0, "reasoning": "r", "confidence": 1.0}),
        lambda r: r.expression == "2 + 2",
    ),
    (
        "translate_logic_dsl",
        ("anthropic",),
        lambda p: p.translate_logic_dsl("x is greater than 1"),
        lambda: _tool_use({"dsl_code": "(GT x 1)", "variables": []}),
        lambda r: r["dsl_code"] == "(GT x 1)",
    ),
    (
        "translate_logic",
        ("anthropic", "claude_opus"),
        lambda p: p.translate_logic("x is greater than 1"),
        _logic,
        lambda r: r.variables == {"x": "Int"} and r.constraints == ["x > 1"],
    ),
    (
        "refine_logic",
        ("anthropic", "claude_opus"),
        lambda p: p.refine_logic("x is greater than 1", "previous error"),
        _logic,
        lambda r: r.variables == {"x": "Int"} and r.constraints == ["x > 1"],
    ),
    (
        "translate_stats",
        ("anthropic", "claude_opus"),
        lambda p: p.translate_stats("mean of a", ["a"]),
        lambda: _text("result = df['a'].mean()"),
        lambda r: r == "result = df['a'].mean()",
    ),
    (
        "verify_fact",
        ("anthropic", "claude_opus"),
        lambda p: p.verify_fact("The sky is blue.", "The sky is blue."),
        lambda: _tool_use({"verdict": "SUPPORTED", "reasoning": "r", "citations": ["The sky is blue."]}),
        lambda r: r["verdict"] == "SUPPORTED",
    ),
    (
        "verify_image",
        ("anthropic", "claude_opus"),
        lambda p: p.verify_image(b"\xff\xd8\xff", "The chart shows growth."),
        lambda: _tool_use({"verdict": "SUPPORTED", "reasoning": "r", "confidence": 0.9}),
        lambda r: r["verdict"] == "SUPPORTED",
    ),
]

CASES = [
    pytest.param(provider, call, make_response, check, id=f"{provider}.{name}")
    for name, providers, call, make_response, check in CALLS
    for provider in providers
]


@pytest.mark.parametrize("provider_name, call, make_response, check", CASES)
def test_each_call_sends_only_parameters_the_sdk_takes(monkeypatch, provider_name, call, make_response, check):
    provider_cls, env = PROVIDERS[provider_name]
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    provider = provider_cls()
    sent = []

    def create(**kwargs):
        CREATE_SIGNATURE.bind(None, **kwargs)  # TypeError for a parameter this SDK does not take
        sent.append(kwargs)
        return make_response()

    monkeypatch.setattr(provider.client.messages, "create", create)

    result = call(provider)

    assert len(sent) == 1
    assert not SAMPLING_PARAMETERS & sent[0].keys()
    assert check(result)


@pytest.mark.parametrize("provider_name", PROVIDERS)
def test_every_messages_create_call_in_the_provider_is_driven(provider_name):
    provider_cls, _ = PROVIDERS[provider_name]
    source = inspect.getsource(inspect.getmodule(provider_cls))
    driven = sum(provider_name in providers for _, providers, *_ in CALLS)

    assert source.count("self.client.messages.create(") == driven
