"""QWEDLocal.verify_math and verify() no longer report a model's answer as verified (GHSA-r9hc).

The method asked the model for an answer and for a SymPy expression of the
question, evaluated that expression and reported ``verified=True`` with
confidence 1.0 whenever the two matched. Both came from the model, so "What
is 2 + 2?" answered 5 with ``sympy.simplify(2+3)`` was verified, and so was
the CLI's ``qwed verify``. Now the result is never verified; a mismatch still
shows the model contradicting its own expression, and results cached as
verified are not served.

The model is stubbed; nothing is sent anywhere.
"""

from types import SimpleNamespace

import pytest

from qwed_sdk import QWEDLocal
from qwed_sdk import qwed_local

pytest.importorskip("sympy")

ADVISORY = [
    ("verify_math", "What is 2 + 2?", "5", "sympy.simplify(2+3)", "5"),
    ("verify_math", "What is the derivative of x**2?", "3*x**2", "sympy.diff(x**3, x)", "3*x**2"),
    ("verify", "What is 10 / 4?", "3", "sympy.simplify(9/3)", "3"),
]


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setenv("QWED_QUIET", "1")
    return QWEDLocal(base_url="http://localhost:11434/v1", model="llama3", cache=False)


def _answer(local, replies):
    replies = iter(replies)
    local._call_llm = lambda prompt, system=None: next(replies)


@pytest.mark.parametrize("method, query, answer, expression, value", ADVISORY)
def test_the_models_agreement_with_itself_is_not_verified(local, method, query, answer, expression, value):
    _answer(local, [answer, expression])

    result = {"verify_math": local.verify_math, "verify": local.verify}[method](query)

    assert result.verified is False
    assert result.confidence == 0.0
    assert result.value == value
    assert result.evidence["consistent"] is True
    assert result.evidence["translation_verified"] is False
    assert result.error.startswith("Not verified")


def test_a_model_that_contradicts_its_own_expression_is_reported(local):
    _answer(local, ["5", "sympy.simplify(2+2)"])

    result = local.verify_math("What is 2 + 2?")

    assert result.verified is False
    assert result.value == "4"
    assert result.evidence["consistent"] is False
    assert result.error == "The model's answer does not match its own expression."


def test_the_module_level_verify_is_not_verified_either(monkeypatch):
    monkeypatch.setenv("QWED_QUIET", "1")
    replies = iter(["4", "sympy.simplify(2+2)"])
    monkeypatch.setattr(QWEDLocal, "_call_llm", lambda self, prompt, system=None: next(replies))

    result = qwed_local.verify(
        "What is 2 + 2?", base_url="http://localhost:11434/v1", model="llama3", cache=False
    )

    assert result.verified is False
    assert result.value == "4"


class _FakeCache:
    """A cache holding the verified result the old check stored under "v1"."""

    def __init__(self):
        self.stored = {}
        self.contexts = []

    def get(self, key, ctx):
        self.contexts.append(ctx)
        if ctx.policy_version == "v1":
            return {"verified": True, "value": "5", "confidence": 1.0, "evidence": {"method": "sympy_eval_safe"}}
        return self.stored.get((key, ctx.policy_version))

    def set(self, key, data, ctx):
        self.stored[(key, ctx.policy_version)] = data


def _with_cache(local):
    cache = _FakeCache()
    local._cache = cache
    local._cache_context_class = lambda **kwargs: SimpleNamespace(**kwargs)
    return cache


def test_a_result_the_old_check_cached_as_verified_is_not_served(local):
    cache = _with_cache(local)
    _answer(local, ["5", "sympy.simplify(2+3)"])

    result = local.verify_math("What is 2 + 2?")

    assert result.verified is False
    assert cache.contexts[0].policy_version == qwed_local.MATH_CACHE_POLICY_VERSION != "v1"


def test_a_result_cached_by_this_version_is_not_verified_either(local):
    cache = _with_cache(local)
    _answer(local, ["5", "sympy.simplify(2+3)"])

    first = local.verify_math("What is 2 + 2?")
    second = local.verify_math("What is 2 + 2?")

    assert len(cache.stored) == 1
    assert first.verified is second.verified is False
    assert second.error == first.error
