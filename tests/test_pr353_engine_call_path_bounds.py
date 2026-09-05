"""#353 acceptance tests: no unbounded engine-call waits, pool capacity
never reduced by hung engines, breaker-excluded engines never submitted.

Acceptance (issue #353):
  1. A consensus request whose engine hangs forever cannot reduce the pool
     below capacity for more than one timeout window.
  2. Breaker-excluded engines are skipped without submitting work.
  3. No unbounded daemon or HTTP waits remain in the engine call path.

Coverage per criterion:
  1. TestPoolIsolationUnderHang — a second request right after a hung-engine
     request still gets full per-request capacity (per-call executors).
  2. TestBreakerOpenSubmitsNothing — spy on the pool's submit().
  3. TestSympyComputeBounds (the measured 9**9**9**9 evalf() hang),
     TestProviderClientBounds (5 clients carried the SDK's 600s read
     default x retries), TestStatsUploadCap (read_csv on uncapped upload).
"""

import io
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pytest

from qwed_new.core import consensus_verifier as cv
from qwed_new.core.consensus_verifier import ConsensusVerifier, EngineResult
from qwed_new.core.safe_parser import SafeParserError, safe_parse_expr
from qwed_new.core.verifier import VerificationEngine
from qwed_new.providers.anthropic import AnthropicProvider
from qwed_new.providers.azure_openai import AzureOpenAIProvider
from qwed_new.providers.claude_opus import ClaudeOpusProvider
from qwed_new.providers.ollama_provider import OllamaProvider
from qwed_new.providers.openai_compat import OpenAICompatProvider
from qwed_new.providers.openai_direct import OpenAIDirectProvider


def _verifier(max_workers=2):
    verifier = ConsensusVerifier(max_workers=max_workers, enable_circuit_breaker=False)
    verifier._is_engine_available = lambda engine_name: True
    return verifier


def _engine_result(name: str, status: str = "VERIFIED") -> EngineResult:
    return EngineResult(
        engine_name=name, method="mock", result="42", confidence=1.0,
        latency_ms=0, success=(status == "VERIFIED"), status=status,
    )


class TestSympyComputeBounds:
    """#353: SymPy expands exact Integer powers eagerly — a 10-character
    expression (9**9**9**9) hung evalf() past 20s. Every gate here must
    reject the bombs FAST and keep legitimate magnitudes parsing."""

    @pytest.mark.parametrize("bomb", [
        "9**9**9**9",
        "9**9**9",
        "2**(10**100)",
        "9**(-10**6)",
        "factorial(9**9)",
        "factorial(10**9)",
        "(9**9)**(9**9)",
        # ^ is left-assoc in the Python AST but convert_xor re-parses it as
        # right-assoc ** in sympy-land — 3 caret operands reassociate into
        # a power tower whose Python-AST nodes all look harmless
        "9^9^9",
    ])
    def test_magnitude_bombs_rejected_without_expanding(self, bomb):
        start = time.monotonic()
        with pytest.raises(SafeParserError):
            safe_parse_expr(bomb)
        # pre-fix these hung indefinitely; the guard must decide in ms
        assert time.monotonic() - start < 5

    def test_large_integer_literal_rejected(self):
        with pytest.raises(SafeParserError):
            safe_parse_expr("9" * 400)

    @pytest.mark.parametrize("expr", [
        "2**256",
        "2**10000",
        "2**(2**13)",
        "9**9",
        "(9**9)**9",
        "((9**9)**9)**9",
        "x**y",
        "x^2",
        "2^10",
        "factorial(10)",
        "sin(x)**2",
        "2**(3*4)",      # Mult inside the static exponent evaluator
        "2**(x*4)",      # BinOp over a name — not static, sympy handles it
        "2**-(x*4)",     # negation of a non-static subtree
    ])
    def test_legitimate_expressions_still_parse(self, expr):
        assert safe_parse_expr(expr) is not None

    @pytest.mark.parametrize("expr", [
        # every static-arithmetic operator must resolve inside the exponent
        # position without tripping the magnitude gate
        "2**(1+3)",
        "2**(10-6)",
        "2**(8/2)",
        "2**(9//2)",
        "2**(9%7)",
        "2**+4",
        "2**(-2)",
        "2**(-x)",       # symbolic operand — sympy handles it lazily
        "2^(2^3)",       # ^ reassociates to ** on the sympy side
        "2**((8/2)**2)",  # float pow inside the exponent position
    ])
    def test_static_exponent_arithmetic_still_parses(self, expr):
        assert safe_parse_expr(expr) is not None

    @pytest.mark.parametrize("expr", [
        "2**(1/0)",        # ZeroDivisionError inside the evaluator -> fail closed
        "2**(10.0**400)",  # float pow overflow inside the evaluator -> fail closed
    ])
    def test_unresolvable_exponent_magnitude_fails_closed(self, expr):
        with pytest.raises(SafeParserError):
            safe_parse_expr(expr)

    def test_verify_math_bomb_returns_error_without_hanging(self):
        engine = VerificationEngine()
        start = time.monotonic()
        result = engine.verify_math("9**9**9**9", 1)
        elapsed = time.monotonic() - start
        assert result["is_correct"] is False
        assert result["status"] == "SYNTAX_ERROR"
        assert elapsed < 5

    def test_verify_math_normal_query_still_verified(self):
        engine = VerificationEngine()
        result = engine.verify_math("2 * (5 + 10)", 30)
        assert result["status"] == "VERIFIED"
        assert result["is_correct"] is True


class TestProviderClientBounds:
    """#353: 5 of 7 LLM clients carried the SDK default read timeout
    (600s) x retries — a silently stalled endpoint occupied its engine
    worker for ~30 minutes. Every client must carry the openai_direct
    in-repo standard (timeout=30.0, max_retries=2). gemini_provider was
    already bounded (request_options={'timeout': 30.0})."""

    @pytest.mark.parametrize("provider_cls,env", [
        (OpenAIDirectProvider,
         {"OPENAI_API_KEY": "sk-" + "test-sentinel-key-value"}),
        (AzureOpenAIProvider,
         {"AZURE_OPENAI_ENDPOINT": "http://localhost:1",
          "AZURE_OPENAI_API_KEY": "test-sentinel",
          "AZURE_OPENAI_DEPLOYMENT": "test-deploy",
          "AZURE_OPENAI_API_VERSION": "2024-01-01"}),
        (OllamaProvider, {}),
        (OpenAICompatProvider,
         {"CUSTOM_BASE_URL": "http://localhost:1/v1"}),
        (AnthropicProvider,
         {"ANTHROPIC_ENDPOINT": "http://localhost:1",
          "ANTHROPIC_API_KEY": "test-sentinel"}),
        (ClaudeOpusProvider,
         {"CLAUDE_OPUS_ENDPOINT": "http://localhost:1",
          "CLAUDE_OPUS_API_KEY": "test-sentinel"}),
    ])
    def test_client_carries_explicit_timeout_and_retries(self, monkeypatch, provider_cls, env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        provider = provider_cls()
        assert provider.client.timeout == 30.0
        assert provider.client.max_retries == 2


class TestStatsUploadCap:
    """#353: read_csv on an uncapped upload is an unbounded CPU/memory wait
    inside the engine call path — the upload is read under a hard byte cap."""

    def _client(self, api_main):
        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = api_main.app.dependency_overrides.copy()
        api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: mock_tenant
        api_main.app.dependency_overrides[api_main.get_session] = lambda: MagicMock()
        return original

    def test_oversized_upload_rejected_before_parse(self):
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main

        original = self._client(api_main)
        try:
            with patch("qwed_new.api.main.check_rate_limit"), \
                 patch("qwed_new.api.main._safe_commit_log"):
                client = TestClient(api_main.app, raise_server_exceptions=False)
                response = client.post(
                    "/verify/stats",
                    files={"file": ("big.csv", b"x" * (api_main._MAX_STATS_UPLOAD_BYTES + 1))},
                    data={"query": "what is the mean"},
                )
        finally:
            api_main.app.dependency_overrides.clear()
            api_main.app.dependency_overrides.update(original)
        assert response.status_code == 413

    def test_small_upload_reaches_read_csv_via_bytesio(self):
        import pandas as pd
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main
        from qwed_new.core.diagnostics import DiagnosticResult

        dr = DiagnosticResult.unverifiable("no claim detected", developer_fields={"is_valid": False})
        captured = {}

        def fake_to_thread(fn, *args, **kwargs):
            if fn is pd.read_csv:
                captured["source"] = args[0]
                return "DF"
            if fn.__name__ == "verify_stats":
                return dr
            raise AssertionError(f"unexpected to_thread target: {fn}")

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = api_main.app.dependency_overrides.copy()
        api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: mock_tenant
        api_main.app.dependency_overrides[api_main.get_session] = lambda: MagicMock()
        patches = [
            patch("qwed_new.api.main.check_rate_limit"),
            patch("qwed_new.api.main._safe_commit_log"),
            patch("qwed_new.api.main._enforce_environment_integrity", return_value=None),
            patch("qwed_new.api.main.asyncio.to_thread", side_effect=fake_to_thread),
        ]
        try:
            for p in patches:
                p.start()
            client = TestClient(api_main.app, raise_server_exceptions=False)
            response = client.post(
                "/verify/stats",
                files={"file": ("small.csv", b"col\n1\n2\n")},
                data={"query": "what is the mean"},
            )
        finally:
            for p in patches:
                p.stop()
            api_main.app.dependency_overrides.clear()
            api_main.app.dependency_overrides.update(original)
        assert response.status_code == 200
        assert isinstance(captured.get("source"), io.BytesIO)


class TestPoolIsolationUnderHang:
    """#353 acceptance 1: a hung engine in request A must not reduce the
    capacity available to request B — per-call executors mean each request
    starts with a full-capacity pool regardless of still-running workers."""

    def test_hung_engine_does_not_starve_next_request(self):
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()

        def hung_engine(q):
            release.wait(timeout=15)

        def quick_engine(q):
            return _engine_result("Quick")

        verifier._select_engines = lambda query, mode: (
            [("Hung", hung_engine), ("Quick", quick_engine)]
            if query == "request-A" else [("Quick", quick_engine)]
        )
        try:
            result_a = asyncio_run_request(verifier, "request-A", timeout_seconds=0.4)
            # request B runs while A's hung worker is STILL blocked
            result_b = asyncio_run_request(verifier, "request-B", timeout_seconds=5)
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        by_name_a = {r.engine_name: r for r in result_a.verification_chain}
        assert by_name_a["Hung"].status == "BLOCKED"
        assert by_name_a["Quick"].status == "VERIFIED"
        by_name_b = {r.engine_name: r for r in result_b.verification_chain}
        assert by_name_b["Quick"].status == "VERIFIED"


def asyncio_run_request(verifier, query, timeout_seconds):
    import asyncio
    return asyncio.run(
        verifier.verify_async(query, mode=cv.VerificationMode.SINGLE, timeout_seconds=timeout_seconds)
    )


class TestBreakerOpenSubmitsNothing:
    """#353 acceptance 2: a breaker-excluded engine must surface as an
    explicit circuit_open BLOCKED result WITHOUT submitting work to the
    pool — no thread may start for it."""

    def test_circuit_open_engine_never_reaches_pool_submit(self, monkeypatch):
        submits = []

        class SpyPool(ThreadPoolExecutor):
            def submit(self, fn, *args, **kwargs):
                submits.append(fn)
                return super().submit(fn, *args, **kwargs)

        monkeypatch.setattr(cv, "ThreadPoolExecutor", SpyPool)
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()

        def ok_engine(q):
            return _engine_result("Open")

        def any_engine(q):
            raise AssertionError("closed engine must never run")

        verifier._select_engines = lambda query, mode: [
            ("Open", ok_engine), ("Closed", any_engine),
        ]
        verifier._is_engine_available = lambda engine_name: engine_name == "Open"

        result = asyncio_run_request(verifier, "q", timeout_seconds=5)

        by_name = {r.engine_name: r for r in result.verification_chain}
        assert by_name["Closed"].status == "BLOCKED"
        assert by_name["Closed"].method == "circuit_open"
        assert by_name["Open"].status == "VERIFIED"
        # exactly one submission — the available engine only
        assert submits == [ok_engine]
