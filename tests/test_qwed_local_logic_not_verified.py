"""QWEDLocal.verify_logic no longer reports a model's answer as verified (GHSA-8fwp).

The method asked the model for TRUE or FALSE and for a Z3 expression of the
question, then reported ``verified=True`` with confidence 1.0 whenever Z3's
satisfiability of that expression matched the answer. Both came from the
model, so "Is 2 + 2 equal to 5?" answered TRUE with ``Bool('p')`` was
verified. Now the result is never verified; disagreement still shows the model
contradicting its own formula, and results cached as verified are not served.

The model is stubbed; nothing is sent anywhere.
"""

from types import SimpleNamespace

import pytest

from qwed_sdk import QWEDLocal
from qwed_sdk import qwed_local

pytest.importorskip("z3")

ADVISORY = [
    ("Is 2 + 2 equal to 5?", "TRUE", "Bool('p')"),
    ("Is every integer even?", "TRUE", "Bool('even')"),
    ("Is 2 + 2 equal to 4?", "FALSE", "And(Bool('p'), Not(Bool('p')))"),
]


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setenv("QWED_QUIET", "1")
    return QWEDLocal(base_url="http://localhost:11434/v1", model="llama3", cache=False)


def _answer(local, replies):
    replies = iter(replies)
    local._call_llm = lambda prompt, system=None: next(replies)


@pytest.mark.parametrize("query, answer, expression", ADVISORY)
def test_the_models_agreement_with_itself_is_not_verified(local, query, answer, expression):
    _answer(local, [answer, expression])

    result = local.verify_logic(query)

    assert result.verified is False
    assert result.confidence == 0.0
    assert result.evidence["consistent"] is True
    assert result.evidence["translation_verified"] is False
    assert result.error.startswith("Not verified")


def test_a_model_that_contradicts_its_own_formula_is_reported(local):
    _answer(local, ["TRUE", "And(Bool('p'), Not(Bool('p')))"])

    result = local.verify_logic("Is p and not p true?")

    assert result.verified is False
    assert result.value == "FALSE"
    assert result.evidence["consistent"] is False
    assert result.error == "The model's answer contradicts its own formula."


def test_what_z3_decided_is_still_reported(local):
    _answer(local, ["TRUE", "Or(Bool('p'), Not(Bool('p')))"])

    result = local.verify_logic("Is p or not p true?")

    assert result.value == "TRUE"
    assert result.evidence["z3_satisfiable"] is True
    assert result.evidence["z3_expr"] == "Or(Bool('p'), Not(Bool('p')))"


class _FakeCache:
    """A cache holding the verified result the old check stored under "v1"."""

    def __init__(self):
        self.stored = {}
        self.contexts = []

    def get(self, key, ctx):
        self.contexts.append(ctx)
        if ctx.policy_version == "v1":
            return {"verified": True, "value": "TRUE", "confidence": 1.0, "evidence": {"method": "z3_sat"}}
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
    _answer(local, ["TRUE", "Bool('p')"])

    result = local.verify_logic("Is 2 + 2 equal to 5?")

    assert result.verified is False
    assert cache.contexts[0].policy_version == qwed_local.LOGIC_CACHE_POLICY_VERSION != "v1"


def test_a_verified_result_the_old_policy_left_in_a_real_cache_is_not_served(local, tmp_path):
    from qwed_sdk.cache import CacheContext, VerificationCache

    query = "Is 2 + 2 equal to 5?"
    cache = VerificationCache(cache_dir=str(tmp_path))
    old = CacheContext(provider=local.provider or "local", model=local.model, policy_version="v1")
    cache.set(query, {"verified": True, "value": "TRUE", "confidence": 1.0, "evidence": {"method": "z3_sat"}}, old)
    assert cache.get(query, old)["verified"] is True
    local._cache, local._cache_context_class = cache, CacheContext
    _answer(local, ["TRUE", "Bool('p')"])

    result = local.verify_logic("  is 2 +   2 EQUAL to 5?\t")

    assert result.verified is False
    assert result.confidence == 0.0


def test_a_formula_z3_cannot_decide_is_neither_agreement_nor_contradiction(local, monkeypatch):
    z3 = pytest.importorskip("z3")
    monkeypatch.setattr(z3.Solver, "check", lambda self, *args: z3.unknown)
    _answer(local, ["FALSE", "Bool('p')"])

    result = local.verify_logic("Is p true?")

    assert result.verified is False
    assert result.value == "UNKNOWN"
    assert result.evidence["consistent"] is None
    assert result.evidence["z3_satisfiable"] is None
    assert result.error == "Not verified: Z3 could not decide the model's own formula."


def test_a_result_cached_by_this_version_is_not_verified_either(local):
    cache = _with_cache(local)
    _answer(local, ["TRUE", "Bool('p')"])

    first = local.verify_logic("Is 2 + 2 equal to 5?")
    second = local.verify_logic("Is 2 + 2 equal to 5?")

    assert len(cache.stored) == 1
    assert first.verified is second.verified is False
    assert second.evidence["translation_verified"] is False
    assert second.error == first.error
