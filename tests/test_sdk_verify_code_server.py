"""QWEDClient.verify_code asks the server's CodeVerifier, never a local blocklist (GHSA-4rj3-8wqj-cqwc).

With ``qwed_new`` importable, ``verify_code`` ran the local ``CodeGuard`` (an
AST blocklist of a few names) and reported its pass as ``VERIFIED``, so code
the server's CodeVerifier blocks came back verified, without a request. Now
it always calls ``/verify/code`` and admits only what the server admits; a
server that cannot be reached is UNVERIFIABLE. ``CodeGuard`` stays a
pre-filter that refuses what it recognises and calls its pass advisory.
"""

import asyncio

import httpx
import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision, merge_diagnostic_result
from qwed_new.guards.code_guard import CodeGuard
from qwed_sdk.client import QWEDAsyncClient, QWEDClient

PAYLOADS = [
    "getattr(__builtins__, 'ev'+'al')('1')",
    "().__class__.__base__.__subclasses__()",
    "import importlib\nimportlib.import_module('o' + 's')",
    "import builtins\nbuiltins.exec('x = 1')",
    "from os import system\nsystem('echo hello')",
]
# Refused by the guard's dotted-import check; harmless, and the server admits it.
GUARD_ONLY = ["import os.path\nos.path.exists('x')"]


def _server_body(code):
    """What /verify/code returns for ``code``: the CodeVerifier's result and
    its admission."""
    dr = CodeVerifier().verify_code(code)
    body = merge_diagnostic_result(dr)
    body["admission"] = admission_decision(dr).value
    return body


def _client(monkeypatch, respond):
    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    calls = []

    def request(method, endpoint, **kwargs):
        calls.append((method, endpoint, kwargs.get("json")))
        return respond(kwargs["json"]["code"])

    monkeypatch.setattr(client, "_request", request)
    return client, calls


@pytest.mark.parametrize("code", PAYLOADS)
def test_the_client_admits_only_what_the_server_admits(monkeypatch, code):
    client, calls = _client(monkeypatch, _server_body)

    result = client.verify_code(code)

    assert calls == [("POST", "/verify/code", {"code": code, "language": "python"})]
    assert result.is_verified is (_server_body(code)["admission"] == "ADMIT")
    assert result.is_verified is False


def test_the_client_never_runs_the_local_guard(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("CodeGuard must not decide verify_code")

    monkeypatch.setattr(CodeGuard, "verify_safety", refuse)
    client, calls = _client(monkeypatch, lambda code: {"status": "VERIFIED", "is_valid": True, "admission": "ADMIT"})

    assert client.verify_code("x = 1").is_verified is True
    assert len(calls) == 1


@pytest.mark.parametrize("error", [httpx.ConnectError("refused"), httpx.TimeoutException("slow")])
def test_an_unreachable_server_is_unverifiable(monkeypatch, error):
    client = QWEDClient(api_key="k", base_url="http://qwed.test")

    def request(*args, **kwargs):
        raise error

    monkeypatch.setattr(client, "_request", request)

    result = client.verify_code("x = 1")

    assert (result.status, result.is_verified) == ("UNVERIFIABLE", False)


def test_the_async_client_is_unverifiable_without_the_server_too(monkeypatch):
    async def run():
        client = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")

        async def request(*args, **kwargs):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(client, "_request", request)
        return await client.verify_code("x = 1")

    result = asyncio.run(run())

    assert (result.status, result.is_verified) == ("UNVERIFIABLE", False)


def test_the_async_client_admits_only_what_the_server_admits(monkeypatch):
    async def run():
        client = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")

        async def request(method, endpoint, **kwargs):
            return _server_body(kwargs["json"]["code"])

        monkeypatch.setattr(client, "_request", request)
        return await client.verify_code(PAYLOADS[0])

    assert asyncio.run(run()).is_verified is False


# ---------------------------------------------------------------- CodeGuard

@pytest.mark.parametrize("code", PAYLOADS + GUARD_ONLY)
def test_the_guard_refuses_indirect_access(code):
    assert CodeGuard().verify_safety(code)["verified"] is False


@pytest.mark.parametrize("code", ["x = 1\nprint(x + 1)", "import math\nmath.sqrt(4)", "if __name__ == '__main__':\n    pass"])
def test_the_guard_calls_its_pass_advisory(code):
    result = CodeGuard().verify_safety(code)

    assert result["verified"] is True
    assert result["advisory"] is True
    assert "verified safe" not in result["message"]
    assert "not a verification" in result["message"]


def test_the_shell_guard_calls_its_pass_advisory():
    result = CodeGuard().verify_safety("echo hello", language="bash")

    assert result["advisory"] is True
    assert "verified safe" not in result["message"]
