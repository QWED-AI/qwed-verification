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

import asyncio
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



def _install_stats_overrides(api_main, mock_tenant):
    """FastAPI introspects the override callable's signature, so the
    overrides must be zero-arg defs (CodeQL on PR #354 flagged the lambdas;
    a MagicMock instance as the override breaks introspection -> 422)."""
    def _tenant():
        return mock_tenant

    def _session():
        return MagicMock()

    original = api_main.app.dependency_overrides.copy()
    api_main.app.dependency_overrides[api_main.get_current_tenant] = _tenant
    api_main.app.dependency_overrides[api_main.get_session] = _session
    return original


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
    def test_magnitude_bombs_rejected_without_expanding(self, bomb, monkeypatch):
        # deterministic guard (CodeRabbit on PR #354): the AST gate must
        # reject BEFORE sympy's parser runs — if parse_expr is ever reached,
        # the AssertionError is not a SafeParserError and the test fails
        monkeypatch.setattr(
            "qwed_new.core.safe_parser.parse_expr",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("parse_expr reached — compute-cost gate failed")),
        )
        with pytest.raises(SafeParserError):
            safe_parse_expr(bomb)

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
        "100000^x",   # symbolic right operand: sympy-side pow stays lazy
        "x^9^9",      # symbolic base: x**387420489 is created lazily
        "2^x^9",
    ])
    def test_caret_chain_with_symbolic_operand_stays_lazy(self, expr):
        # CodeAnt on PR #354: bounding every caret operand rejected valid
        # lazy expressions; only fully-static chains are bounded
        assert safe_parse_expr(expr) is not None

    @pytest.mark.parametrize("expr", [
        "2^(9^9)",      # explicit parens preserved by sympy: 2**(9**9)
        "100000^9^9",   # left-assoc AST, right-assoc sympy: 100000**(9**9)
    ])
    def test_static_caret_reassociation_bombs_rejected(self, expr):
        with pytest.raises(SafeParserError):
            safe_parse_expr(expr)

    @pytest.mark.parametrize("expr", [
        "Integer(10001)",
        "Rational(10001, 3)",
        "Float(20000)",
    ])
    def test_constructor_calls_accept_large_values(self, expr):
        # CodeAnt on PR #354: Integer/Float/Rational are cheap constructors;
        # explosive arguments are caught by their own Pow/factorial checks
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
    worker for ~30 minutes. Every client must carry timeout=30.0 with
    retries DISABLED (CodeRabbit on PR #354: SDK retries stack on top of
    the timeout with backoff — even one retry put worst-case worker
    occupancy at ~60s, past the 30s consensus deadline; the caller owns
    retry policy). gemini_provider was already bounded
    (request_options={'timeout': 30.0})."""

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
        assert provider.client.max_retries == 0


class TestStatsUploadCap:
    """#353: read_csv on an uncapped upload is an unbounded CPU/memory wait
    inside the engine call path — the upload is read under a hard byte cap."""


    def test_oversized_upload_rejected_before_parse(self):
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
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
            # the bounded reader runs for real (tiny input); intercept the
            # heavy verify_stats call only
            if fn.__name__ == "_read_bounded_csv":
                return fn(*args, **kwargs)
            if fn.__name__ == "verify_stats":
                captured["df"] = args[1] if len(args) > 1 else kwargs.get("df")
                return dr
            raise AssertionError(f"unexpected to_thread target: {fn}")

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
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
        assert isinstance(captured.get("df"), pd.DataFrame)


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


class TestStatsExpandedShapeCap:
    """#353 (CodeAnt on PR #354): the byte cap bounds TRANSFER, not pandas
    memory — a compact CSV can expand into a much larger in-memory frame.
    The expanded rows x columns count is bounded after the parse."""

    def test_oversized_expanded_frame_rejected_413(self):
        import pandas as pd
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main

        expanded = MagicMock()
        expanded.size = api_main._MAX_STATS_CELL_COUNT + 1

        def fake_to_thread(fn, *args, **kwargs):
            if fn.__name__ == "_read_bounded_csv":
                return fn(*args, **kwargs)
            raise AssertionError(f"unexpected to_thread target: {fn}")

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
        def fake_read_csv(source, nrows=None, chunksize=None, **kwargs):
            if nrows == 0:
                return pd.DataFrame(columns=["col"])
            return iter([expanded])

        patches = [
            patch("qwed_new.api.main.check_rate_limit"),
            patch("qwed_new.api.main._safe_commit_log"),
            patch("qwed_new.api.main._enforce_environment_integrity", return_value=None),
            patch("qwed_new.api.main.asyncio.to_thread", side_effect=fake_to_thread),
            patch("pandas.read_csv", side_effect=fake_read_csv),
        ]
        try:
            for p in patches:
                p.start()
            client = TestClient(api_main.app, raise_server_exceptions=False)
            response = client.post(
                "/verify/stats",
                files={"file": ("tiny.csv", b"col\n1\n")},
                data={"query": "what is the mean"},
            )
        finally:
            for p in patches:
                p.stop()
            api_main.app.dependency_overrides.clear()
            api_main.app.dependency_overrides.update(original)
        assert response.status_code == 413
        assert "cell limit" in response.json()["detail"]

    def test_frame_within_cell_budget_passes(self):
        import pandas as pd
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main
        from qwed_new.core.diagnostics import DiagnosticResult

        dr = DiagnosticResult.unverifiable("no claim detected", developer_fields={"is_valid": False})

        def fake_to_thread(fn, *args, **kwargs):
            if fn.__name__ == "_read_bounded_csv":
                return fn(*args, **kwargs)
            if fn.__name__ == "verify_stats":
                return dr
            raise AssertionError(f"unexpected to_thread target: {fn}")

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
        def fake_read_csv(source, nrows=None, chunksize=None, **kwargs):
            if nrows == 0:
                return pd.DataFrame(columns=["col"])
            return iter([pd.DataFrame({"col": [1, 2]})])

        patches = [
            patch("qwed_new.api.main.check_rate_limit"),
            patch("qwed_new.api.main._safe_commit_log"),
            patch("qwed_new.api.main._enforce_environment_integrity", return_value=None),
            patch("qwed_new.api.main.asyncio.to_thread", side_effect=fake_to_thread),
            patch("pandas.read_csv", side_effect=fake_read_csv),
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


class TestConcreteCallPropagation:
    """#354 review (Greptile P1 + CodeRabbit): allowlisted calls evaluate
    CONCRETE values that sympy expands eagerly — 2**abs(-100000) and
    2**factorial(10000) used to slip past the exponent bound as 'symbolic'.
    _static_value now evaluates them (bounded, fail-closed) so the bound
    sees the real magnitude."""

    @pytest.mark.parametrize("expr", [
        "2**abs(-100000)",
        "2**factorial(10000)",
        "2**binomial(10**9, 2)",
        "2**(1+abs(-100000))",
    ])
    def test_concrete_calls_in_exponent_position_rejected(self, expr):
        with pytest.raises(SafeParserError):
            safe_parse_expr(expr)

    @pytest.mark.parametrize("expr", [
        "2**factorial(5)",       # 120 — inside the bound
        "2**abs(-100)",          # 100
        "abs(-100000)",          # top-level value is not an expansion sink
        "2**sin(2)",             # symbolic-argument call stays lazy
        "2**abs(x)",             # allowlisted call over a symbolic arg
        "2**Rational(10001, 3)", # exact Fraction magnitude inside the bound
        "2**Rational(5000)",     # single-arg Rational constructor
    ])
    def test_bounded_or_symbolic_calls_still_parse(self, expr):
        assert safe_parse_expr(expr) is not None

    def test_decimal_pow_is_exact_at_the_boundary(self):
        # CodeRabbit on PR #354: binary float rounding must not decide the
        # bound. A COMPUTED value just over 10_000 is rejected...
        with pytest.raises(SafeParserError):
            safe_parse_expr("2**((100.0**2) + 2**(-20) + 1)")
        # ...while a literal float that Python itself rounds to 10000.0 at
        # parse time is genuinely 10000.0 (and a Float exponent means lazy
        # mpmath on the sympy side — no exact expansion either way)
        assert safe_parse_expr("2**(10000.0000000000001)") is not None


class TestStaticEvaluatorEdgePaths:
    """Edge paths of the #353 static evaluator (codecov patch coverage)."""

    @pytest.mark.parametrize("expr", [
        "2**((-1.0)**0.5)",    # Decimal pow -> complex -> InvalidOperation -> fail closed
        "2**factorial(10**9)", # bounded factorial reports astronomical magnitude
        "2**Rational(1, 2, 3)",  # arity error inside the evaluator -> fail closed
    ])
    def test_unresolvable_concrete_values_fail_closed(self, expr):
        with pytest.raises(SafeParserError):
            safe_parse_expr(expr)

    @pytest.mark.parametrize("expr", [
        "2**binomial(10, 3)",   # math.comb path: 120 — inside the bound
        "Rational(10001)",      # single-arg Rational constructor
        "2**sin(x)",            # symbolic-argument call stays exempt
    ])
    def test_resolvable_or_symbolic_calls_still_parse(self, expr):
        assert safe_parse_expr(expr) is not None

    def test_exact_comb_boundary_rejected(self):
        # comb(20, 10) = 184756 — a concrete value past the exponent bound
        with pytest.raises(SafeParserError):
            safe_parse_expr("2**binomial(20, 10)")


class TestNestedPowerExpansionBudget:
    """#354 review (CodeRabbit): sympy expands (Integer**Integer)**Integer
    STEPWISE, so nested powers multiply the base's magnitude into the cost —
    ((9**9)**9999)**9999 has every IMMEDIATE exponent inside the 10_000
    bound yet still expands to a ~400M-digit integer. The base's estimated
    expansion cost is bound to the same digit budget."""

    @pytest.mark.parametrize("expr", [
        "((9**9)**9999)**9999",  # every immediate exponent <= 10_000
        "(9**9**9)**2",          # the bomb lives in the base subtree
        "(10**60000)**2",        # 60001x2 digits > the 100k budget
    ])
    def test_nested_power_bombs_rejected(self, expr, monkeypatch):
        monkeypatch.setattr(
            "qwed_new.core.safe_parser.parse_expr",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("parse_expr reached — compute-cost gate failed")),
        )
        with pytest.raises(SafeParserError):
            safe_parse_expr(expr)

    @pytest.mark.parametrize("expr", [
        "((9**9)**9)**9",     # 9^729 — tiny
        "(10**9000)**2",      # 18002 digits — inside the budget
    ])
    def test_nested_powers_inside_budget_still_parse(self, expr):
        assert safe_parse_expr(expr) is not None


class TestWideCsvFirstChunkRegression:
    """#354 review (CodeRabbit): chunksize bounds ROWS, not columns — a
    compact-but-wide CSV can exceed the cell budget inside the FIRST chunk
    pandas materializes. The reader preflights the column count, derives
    rows-per-chunk from the cell budget, and aborts on the accumulated
    count."""

    def test_wide_csv_exceeding_budget_in_first_chunk_rejected_413(self):
        import pandas as pd
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main

        wide_chunk = MagicMock()
        wide_chunk.size = api_main._MAX_STATS_CELL_COUNT + 1

        def fake_read_csv(source, nrows=None, chunksize=None, **kwargs):
            if nrows == 0:
                # compact header: 25 columns — budget-derived chunksize is
                # large, but the materialized chunk blows the budget
                return pd.DataFrame(columns=[f"c{i}" for i in range(25)])
            assert chunksize == api_main._MAX_STATS_CELL_COUNT // 25
            return iter([wide_chunk])

        def fake_to_thread(fn, *args, **kwargs):
            if fn.__name__ == "_read_bounded_csv":
                return fn(*args, **kwargs)
            raise AssertionError(f"unexpected to_thread target: {fn}")

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
        patches = [
            patch("qwed_new.api.main.check_rate_limit"),
            patch("qwed_new.api.main._safe_commit_log"),
            patch("qwed_new.api.main._enforce_environment_integrity", return_value=None),
            patch("qwed_new.api.main.asyncio.to_thread", side_effect=fake_to_thread),
            patch("pandas.read_csv", side_effect=fake_read_csv),
        ]
        try:
            for p in patches:
                p.start()
            client = TestClient(api_main.app, raise_server_exceptions=False)
            response = client.post(
                "/verify/stats",
                files={"file": ("wide.csv", b"c0,c1\n1,2\n")},
                data={"query": "what is the mean"},
            )
        finally:
            for p in patches:
                p.stop()
            api_main.app.dependency_overrides.clear()
            api_main.app.dependency_overrides.update(original)
        assert response.status_code == 413
        assert "cell limit" in response.json()["detail"]


class TestCaretBaseMagnitudeBudget:
    """#354 review (Sentry CRITICAL): the caret chain's FIRST operand
    multiplies into the expansion cost exactly like a ** base —
    (9**9999)^9999 has a cheap 9543-digit inner power and an in-bound
    exponent, yet sympy eagerly expands the ~95M-digit result."""

    @pytest.mark.parametrize("expr", [
        "(9**9999)^9999",   # 9543-digit base x 9999 >> the digit budget
        "(9**9999)^99999",  # exponent itself over the bound
    ])
    def test_large_computed_caret_base_rejected(self, expr, monkeypatch):
        # deterministic: the AST gate must reject BEFORE sympy parsing
        monkeypatch.setattr(
            "qwed_new.core.safe_parser.parse_expr",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("parse_expr reached — compute-cost gate failed")),
        )
        with pytest.raises(SafeParserError):
            safe_parse_expr(expr)

    @pytest.mark.parametrize("expr", [
        "(2**10)^10",    # 4-digit base x 10 = 40 digits
        "(9**9999)^9",   # 9543 x 9 = ~86k digits — inside the budget
    ])
    def test_small_caret_expansions_still_parse(self, expr):
        assert safe_parse_expr(expr) is not None


class TestUploadConcurrencyCap:
    """#354 review (CodeRabbit): buffering happens before authentication,
    so concurrent unauthenticated uploads multiply the per-request memory
    cost. The middleware gates in-flight buffered uploads process-wide."""

    def test_over_concurrent_limit_rejected_without_buffering(self):
        from qwed_new.api import main as api_main

        async def scenario():
            received = []

            async def receive():
                received.append(True)
                return {"type": "http.request", "body": b"x", "more_body": False}

            sent = []

            async def send(message):
                sent.append(message)

            async def app(scope, receive, send):
                raise AssertionError("app must not see a rejected request")

            middleware = api_main._BodySizeLimitMiddleware(
                app, max_bytes=100, path="/verify/stats",
            )
            scope = {"type": "http", "path": "/verify/stats"}
            api_main._BodySizeLimitMiddleware._in_flight = (
                api_main._BodySizeLimitMiddleware._max_concurrent
            )
            try:
                await middleware(scope, receive, send)
            finally:
                api_main._BodySizeLimitMiddleware._in_flight = 0
            return received, sent

        received, sent = asyncio.run(scenario())
        assert received == []                      # body never buffered
        assert sent[0]["type"] == "http.response.start"
        assert sent[0]["status"] == 503            # capacity, not policy

    def test_in_flight_counter_released_after_request(self):
        from qwed_new.api import main as api_main

        async def scenario():
            async def receive():
                return {"type": "http.request", "body": b"col\n1\n", "more_body": False}

            async def send(message):
                pass

            async def app(scope, receive, send):
                await send({"type": "http.response.start", "status": 200})
                await send({"type": "http.response.body", "body": b""})

            middleware = api_main._BodySizeLimitMiddleware(
                app, max_bytes=100, path="/verify/stats",
            )
            scope = {"type": "http", "path": "/verify/stats"}
            await middleware(scope, receive, send)

        baseline = api_main._BodySizeLimitMiddleware._in_flight
        asyncio.run(scenario())
        assert api_main._BodySizeLimitMiddleware._in_flight == baseline


class TestBodyReadDeadline:
    """#354 review (Greptile P1): the capacity slot is reserved before
    authentication — a slow-loris upload must not hold it forever. The
    whole body read is bounded by one wall-clock deadline; on expiry the
    slot is released with a 408."""

    def test_stalled_body_times_out_and_releases_slot(self):
        from qwed_new.api import main as api_main

        async def scenario():
            async def slow_receive():
                await asyncio.sleep(5)
                return {"type": "http.request", "body": b"x", "more_body": False}

            sent = []

            async def send(message):
                sent.append(message)

            async def app(scope, receive, send):
                raise AssertionError("app must not see a timed-out request")

            middleware = api_main._BodySizeLimitMiddleware(
                app, max_bytes=100, path="/verify/stats",
                read_deadline_seconds=0.2,
            )
            scope = {"type": "http", "path": "/verify/stats"}
            await middleware(scope, slow_receive, send)
            return sent

        sent = asyncio.run(scenario())
        assert sent[0]["type"] == "http.response.start"
        assert sent[0]["status"] == 408
        assert api_main._BodySizeLimitMiddleware._in_flight == 0

    def test_fast_body_completes_within_deadline(self):
        from qwed_new.api import main as api_main

        async def scenario():
            async def fast_receive():
                return {"type": "http.request", "body": b"col\n1\n", "more_body": False}

            async def send(message):
                pass

            async def app(scope, receive, send):
                await send({"type": "http.response.start", "status": 200})
                await send({"type": "http.response.body", "body": b""})

            middleware = api_main._BodySizeLimitMiddleware(
                app, max_bytes=100, path="/verify/stats",
                read_deadline_seconds=5.0,
            )
            scope = {"type": "http", "path": "/verify/stats"}
            await middleware(scope, fast_receive, send)

        asyncio.run(scenario())
        assert api_main._BodySizeLimitMiddleware._in_flight == 0


class TestMiddlewareEdgeCases:
    """#354 review round 9 (Sentry): trailing-slash path normalization and
    the zero-column CSV guard."""

    def test_trailing_slash_path_still_limited(self):
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
        patches = [
            patch("qwed_new.api.main.check_rate_limit"),
            patch("qwed_new.api.main._safe_commit_log"),
        ]
        try:
            for p in patches:
                p.start()
            client = TestClient(api_main.app, raise_server_exceptions=False)
            response = client.post(
                "/verify/stats/",
                files={"file": ("big.csv", b"x" * (api_main._MAX_STATS_UPLOAD_BYTES + 1))},
                data={"query": "what is the mean"},
            )
        finally:
            for p in patches:
                p.stop()
            api_main.app.dependency_overrides.clear()
            api_main.app.dependency_overrides.update(original)
        assert response.status_code == 413

    def test_zero_column_csv_rejected_400(self):
        import pandas as pd
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main

        empty_columns = MagicMock()
        empty_columns.columns = []
        empty_columns.size = 0

        def fake_read_csv(source, nrows=None, chunksize=None, **kwargs):
            if nrows == 0:
                return empty_columns
            return iter([empty_columns])

        def fake_to_thread(fn, *args, **kwargs):
            if fn.__name__ == "_read_bounded_csv":
                return fn(*args, **kwargs)
            raise AssertionError(f"unexpected to_thread target: {fn}")

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
        patches = [
            patch("qwed_new.api.main.check_rate_limit"),
            patch("qwed_new.api.main._safe_commit_log"),
            patch("qwed_new.api.main._enforce_environment_integrity", return_value=None),
            patch("qwed_new.api.main.asyncio.to_thread", side_effect=fake_to_thread),
            patch("pandas.read_csv", side_effect=fake_read_csv),
        ]
        try:
            for p in patches:
                p.start()
            client = TestClient(api_main.app, raise_server_exceptions=False)
            response = client.post(
                "/verify/stats",
                files={"file": ("empty.csv", b"\n\n")},
                data={"query": "what is the mean"},
            )
        finally:
            for p in patches:
                p.stop()
            api_main.app.dependency_overrides.clear()
            api_main.app.dependency_overrides.update(original)
        assert response.status_code == 400
        assert "no columns" in response.json()["detail"]

    def test_empty_upload_rejected_400(self):
        # Greptile P2 on PR #354: empty and blank-only uploads raise
        # pandas EmptyDataError before the column guard — they must be a
        # 400, not the broad handler's generic BLOCKED 200
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-cap-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = _install_stats_overrides(api_main, mock_tenant)
        patches = [
            patch("qwed_new.api.main.check_rate_limit"),
            patch("qwed_new.api.main._safe_commit_log"),
        ]
        try:
            for p in patches:
                p.start()
            client = TestClient(api_main.app, raise_server_exceptions=False)
            for payload in (b"", b"\n\n\n"):
                response = client.post(
                    "/verify/stats",
                    files={"file": ("empty.csv", payload)},
                    data={"query": "what is the mean"},
                )
                assert response.status_code == 400, payload
                assert "no data" in response.json()["detail"]
        finally:
            for p in patches:
                p.stop()
            api_main.app.dependency_overrides.clear()
            api_main.app.dependency_overrides.update(original)


class TestAzureImageMimeDetection:
    """#354 review (Sentry HIGH): the Azure vision data URI hardcoded
    image/jpeg — PNG/WebP images routed to Azure were mislabeled.
    _detect_image_mime mirrors openai_direct's magic-byte detection."""

    @pytest.mark.parametrize("magic,want", [
        (bytes([0xff, 0xd8, 0xff]), "image/jpeg"),
        (bytes([0x89]) + b"PNG" + bytes([0x0d, 0x0a, 0x1a, 0x0a]), "image/png"),
        (b"RIFF" + b"1234" + b"WEBP", "image/webp"),
        (b"not-an-image", "image/jpeg"),  # unknown formats keep the legacy default
    ])
    def test_magic_byte_detection(self, magic, want):
        from qwed_new.providers.azure_openai import _detect_image_mime
        assert _detect_image_mime(magic + b"payload") == want
