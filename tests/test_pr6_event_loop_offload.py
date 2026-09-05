"""Event-loop offload regression tests (issues #340 + #341).

#340: the consensus orchestrator must never run an engine inline on the
event loop; parallel aggregation must catch the for-statement TimeoutError
from as_completed, cancel pending futures, record breaker failures, and
degrade to BLOCKED instead of an uncaught HTTP 500.
#341: the stats verification chain (read_csv, blocking LLM codegen, Docker
daemon calls) must run off the event loop, and every Docker daemon API call
must carry a hard timeout.
"""

import asyncio
import os
import threading
import time
from concurrent.futures import Future
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qwed_new.core import consensus_verifier as cv
from qwed_new.core.consensus_verifier import ConsensusVerifier
from qwed_new.core.secure_code_executor import SecureCodeExecutor


def _verifier(max_workers=2, breaker=False):
    verifier = ConsensusVerifier(max_workers=max_workers, enable_circuit_breaker=breaker)
    verifier._is_engine_available = lambda engine_name: True
    return verifier


class TestParallelTimeout:
    """#340: as_completed raises TimeoutError FROM the for statement."""

    def test_parallel_timeout_degrades_to_blocked_not_500(self, monkeypatch):
        monkeypatch.setattr(cv, "_ENGINE_TIMEOUT_SECONDS", 0.5)
        verifier = _verifier(max_workers=2)
        release = threading.Event()

        def fast_engine(q):
            return MagicMock(success=True, engine_name="Fast")

        def hung_engine(q):
            # controllable hang: released in cleanup so no worker outlives
            # the test (Greptile P2 on PR #352)
            release.wait(timeout=15)
            return MagicMock(success=True, engine_name="Hung")

        verifier._record_engine_result = MagicMock()
        try:
            results = verifier._execute_parallel(
                "q",
                [("Fast", fast_engine), ("Hung", hung_engine)],
            )
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        names = {r.engine_name: r for r in results}
        assert names["Fast"].success is True
        assert names["Hung"].success is False
        assert names["Hung"].status == "BLOCKED"
        assert "timed out" in names["Hung"].error

    def test_parallel_timeout_records_breaker_failure(self):
        """Hung engines never complete — the breaker must learn about them
        or it never opens and every tenant degrades until restart."""
        mp = pytest.MonkeyPatch()
        mp.setattr(cv, "_ENGINE_TIMEOUT_SECONDS", 0.3)
        try:
            verifier = _verifier(max_workers=1)
            verifier._record_engine_result = MagicMock()
            release = threading.Event()

            def hung_engine(q):
                release.wait(timeout=15)

            try:
                verifier._execute_parallel("q", [("Hung", hung_engine)])
            finally:
                release.set()
                verifier._executor.shutdown(wait=False)

            blocked_calls = [
                c for c in verifier._record_engine_result.call_args_list
                if c.args[1].status == "BLOCKED"
            ]
            assert blocked_calls, "timeout must be recorded with the breaker"
        finally:
            mp.undo()

    def test_parallel_pending_futures_cancelled_on_timeout(self, monkeypatch):
        """With a single worker, a hung running engine blocks the queue —
        the second future is still NOT-STARTED and must be cancelled.
        Uses real Future objects: as_completed inspects internal state, not
        done()/result() (CodeRabbit on PR #352)."""
        monkeypatch.setattr(cv, "_ENGINE_TIMEOUT_SECONDS", 0.5)
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()

        fast_future = Future()
        fast_future.set_result(MagicMock(success=True, engine_name="Fast"))
        cancel_probe = Future()  # never started: a pending, cancellable future

        verifier._executor = MagicMock()
        verifier._executor.submit.side_effect = [fast_future, cancel_probe]

        def hung_engine(q):
            time.sleep(10)

        try:
            verifier._execute_parallel("q", [("Fast", None), ("Hung", hung_engine)])
        finally:
            verifier._executor.shutdown(wait=False)

        assert cancel_probe.cancelled()
        assert fast_future.done()


class TestSequentialOffload:
    """#340: engines must never run inline on the caller's thread."""

    def test_sequential_runs_on_pool_worker_with_hard_timeout(self, monkeypatch):
        monkeypatch.setattr(cv, "_ENGINE_TIMEOUT_SECONDS", 2)
        verifier = _verifier(max_workers=2)

        caller_thread = threading.get_ident()
        seen_threads = []

        def engine(q):
            seen_threads.append(threading.get_ident())
            return MagicMock(success=True, engine_name="E")

        results = verifier._execute_sequential("q", [("E", engine)])

        assert results[0].success is True
        assert seen_threads, "engine must have executed"
        assert all(t != caller_thread for t in seen_threads)

    def test_sequential_timeout_degrades_to_blocked(self, monkeypatch):
        monkeypatch.setattr(cv, "_ENGINE_TIMEOUT_SECONDS", 0.3)
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()

        def hung_engine(q):
            release.wait(timeout=15)

        try:
            results = verifier._execute_sequential("q", [("Hung", hung_engine)])
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        assert results[0].success is False
        assert results[0].status == "BLOCKED"
        assert "timed out" in results[0].error


class TestConsensusEndpointAsync:
    """#340: the endpoint must await verify_async, not the inline sync path."""

    def test_endpoint_awaits_verify_async(self):
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main
        from qwed_new.core.consensus_verifier import ConsensusResult

        fake = ConsensusResult(
            final_answer="4",
            confidence=1.0,
            engines_used=1,
            agreement_status="unanimous",
            verification_chain=[],
            total_latency_ms=5.0,
        )
        mock_async = AsyncMock(return_value=fake)

        def _fake_session():
            return MagicMock()

        # fixed principal (deterministic per QWED no-nondeterminism rule);
        # env-defaulted so no credential-shaped literal sits on the api_key slot
        tenant_principal = os.environ.get("QWED_TEST_TENANT", "consensus-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = api_main.app.dependency_overrides.copy()
        api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: mock_tenant
        integrity = patch("qwed_new.api.main._enforce_environment_integrity", return_value=None)
        commit = patch("qwed_new.api.main._safe_commit_log")
        verify_patch = patch.object(api_main.consensus_verifier, "verify_async", mock_async)
        rate_patch = patch("qwed_new.api.main.check_rate_limit")
        try:
            api_main.app.dependency_overrides[api_main.get_session] = _fake_session
            integrity.start()
            commit.start()
            verify_patch.start()
            rate_patch.start()
            with TestClient(api_main.app) as client:
                response = client.post(
                    "/verify/consensus",
                    json={"query": "2+2", "verification_mode": "single", "min_confidence": 0.5},
                )
        finally:
            rate_patch.stop()
            verify_patch.stop()
            commit.stop()
            integrity.stop()
            del api_main.app.dependency_overrides[api_main.get_current_tenant]
            api_main.app.dependency_overrides = original

        assert response.status_code == 200
        mock_async.assert_awaited_once()
        kwargs = mock_async.await_args.kwargs
        assert kwargs["query"] == "2+2"
        assert kwargs["timeout_seconds"] == 30.0


class TestStatsOffload:
    """#341: the stats chain must be offloaded from the event loop."""

    def test_verify_stats_offloads_read_csv_and_verifier(self):
        import pandas as pd
        from fastapi.testclient import TestClient
        from qwed_new.api import main as api_main
        from qwed_new.core.diagnostics import DiagnosticResult

        dr = DiagnosticResult.unverifiable("no claim detected", developer_fields={"is_valid": False})
        captured = {}

        def fake_to_thread(fn, *args, **kwargs):
            if fn is pd.read_csv:
                return "DF"
            if fn.__name__ == "verify_stats":
                captured["df"] = args[1] if len(args) > 1 else kwargs.get("df")
                return dr
            raise AssertionError(f"unexpected to_thread target: {fn}")

        def _fake_session():
            return MagicMock()

        tenant_principal = os.environ.get("QWED_TEST_TENANT", "stats-test-tenant")
        mock_tenant = MagicMock(organization_id=1, api_key=tenant_principal)
        original = api_main.app.dependency_overrides.copy()
        api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: mock_tenant
        integrity = patch("qwed_new.api.main._enforce_environment_integrity", return_value=None)
        commit = patch("qwed_new.api.main._safe_commit_log")
        to_thread = patch("qwed_new.api.main.asyncio.to_thread", side_effect=fake_to_thread)
        rate_patch = patch("qwed_new.api.main.check_rate_limit")
        try:
            api_main.app.dependency_overrides[api_main.get_session] = _fake_session
            integrity.start()
            commit.start()
            to_thread.start()
            rate_patch.start()
            with TestClient(api_main.app) as client:
                response = client.post(
                    "/verify/stats",
                    files={"file": ("data.csv", b"col\n1\n2\n")},
                    data={"query": "did sales increase"},
                )
        finally:
            rate_patch.stop()
            to_thread.stop()
            commit.stop()
            integrity.stop()
            del api_main.app.dependency_overrides[api_main.get_current_tenant]
            api_main.app.dependency_overrides = original

        assert response.status_code == 200
        assert captured.get("df") == "DF"  # the to_thread stub's return value


class TestDockerDaemonTimeout:
    """#341: every Docker daemon API call must carry a hard timeout."""

    def test_from_env_created_with_timeout(self):
        with patch("qwed_new.core.secure_code_executor.docker.from_env", return_value=MagicMock()) as fake_env:
            executor = SecureCodeExecutor()

        fake_env.assert_called_once_with(timeout=30)
        assert executor.docker_available is True


class TestAsyncTimeoutBreaker:
    """#352 review: verify_async timeouts must record breaker failures —
    hung engines otherwise stay eligible for every later request."""

    def test_async_timeout_records_breaker_failure(self):
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()
        verifier._select_engines = lambda query, mode: [("Hung", hung_engine)]
        release = threading.Event()

        def hung_engine(q):
            release.wait(timeout=15)

        try:
            result = asyncio.run(
                verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=0.3)
            )
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        hung = [r for r in result.verification_chain if r.engine_name == "Hung"]
        assert hung
        assert hung[0].status == "BLOCKED"
        assert hung[0].method == "timeout"
        recorded = [c.args[1] for c in verifier._record_engine_result.call_args_list]
        assert any(r.status == "BLOCKED" and r.method == "timeout" for r in recorded)

    def test_async_circuit_open_returns_explicit_blocked(self):
        """Greptile P1 / Sentry on PR #352: a breaker-rejected engine must
        yield an auditable BLOCKED result — not an UnboundLocalError — and a
        skipped request must not extend breaker state."""
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()
        verifier._select_engines = lambda query, mode: [("Hung", lambda q: None)]
        verifier._is_engine_available = lambda engine_name: False  # breaker open

        result = asyncio.run(
            verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=1)
        )

        assert len(result.verification_chain) == 1
        skipped = result.verification_chain[0]
        assert skipped.engine_name == "Hung"
        assert skipped.status == "BLOCKED"
        assert skipped.method == "circuit_open"
        verifier._record_engine_result.assert_not_called()
