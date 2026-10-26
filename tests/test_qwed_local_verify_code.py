"""QWEDLocal.verify_code takes CodeVerifier's verdict, not a blocklist (GHSA-v8qq-v427-qrqc).

The method flagged only bare calls to eval, exec, compile and __import__,
treated importing os, subprocess or sys as a warning, and called everything
else SAFE with confidence 1.0, so ``os.system(cmd)`` or ``subprocess.run(cmd,
shell=True)`` came back verified. Now it is CodeVerifier's verdict and
admission; without CodeVerifier it is UNVERIFIABLE, and results the old check
cached are not served.
"""

import sys
from types import SimpleNamespace

import pytest

from qwed_sdk import QWEDLocal
from qwed_sdk import qwed_local

UNSAFE = [
    "import os\nos.system('echo hello')",
    "import subprocess\nsubprocess.run('echo hello', shell=True)",
    "from os import system\nsystem('echo hello')",
    "getattr(__builtins__, 'ev' + 'al')('1+1')",
    "eval(user_input)",
]
SAFE = "def add(a, b):\n    return a + b\n"


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setenv("QWED_QUIET", "1")
    return QWEDLocal(base_url="http://localhost:11434/v1", model="llama3", cache=False)


@pytest.mark.parametrize("code", UNSAFE)
def test_the_advisorys_payloads_are_not_verified(local, code):
    result = local.verify_code(code)

    assert result.verified is False
    assert result.value == "UNSAFE"
    assert result.confidence == 0.0
    assert result.evidence["admission"] == "BLOCKED"
    assert result.evidence["method"] == "code_verifier"


def test_safe_code_is_verified_by_code_verifier(local):
    result = local.verify_code(SAFE)

    assert (result.verified, result.value) == (True, "SAFE")
    assert (result.evidence["status"], result.evidence["admission"]) == ("VERIFIED", "ADMIT")


def test_without_code_verifier_the_code_is_unverifiable(local, monkeypatch):
    monkeypatch.setitem(sys.modules, "qwed_new.core.code_verifier", None)

    result = local.verify_code(SAFE)

    assert (result.verified, result.value) == (False, "UNVERIFIABLE")
    assert "not verified" in result.error


def test_a_code_verifier_error_is_unverifiable(local, monkeypatch):
    from qwed_new.core import code_verifier

    def broken(self, code, language="python"):
        raise RuntimeError("engine failure")

    monkeypatch.setattr(code_verifier.CodeVerifier, "verify_code", broken)

    result = local.verify_code(SAFE)

    assert (result.verified, result.value) == (False, "UNVERIFIABLE")


class _FakeCache:
    """A cache holding a SAFE result the old AST check stored under "v1"."""

    def __init__(self):
        self.stored = {}
        self.contexts = []

    def get(self, key, ctx):
        self.contexts.append(ctx)
        if ctx.policy_version == "v1":
            return {"verified": True, "value": "SAFE", "confidence": 1.0, "evidence": {"method": "ast_analysis"}}
        return self.stored.get((key, ctx.policy_version))

    def set(self, key, data, ctx):
        self.stored[(key, ctx.policy_version)] = data


def test_a_result_the_old_check_cached_is_not_served(local):
    cache = _FakeCache()
    local._cache = cache
    local._cache_context_class = lambda **kwargs: SimpleNamespace(**kwargs)

    result = local.verify_code(UNSAFE[0])

    assert result.verified is False
    assert cache.contexts[0].policy_version == qwed_local.CODE_CACHE_POLICY_VERSION != "v1"
    assert cache.contexts[0].model == "code_verifier"


def test_a_cached_result_from_this_version_is_served(local):
    cache = _FakeCache()
    local._cache = cache
    local._cache_context_class = lambda **kwargs: SimpleNamespace(**kwargs)

    first = local.verify_code(SAFE)
    second = local.verify_code(SAFE)

    assert first.verified is second.verified is True
    assert len(cache.stored) == 1
