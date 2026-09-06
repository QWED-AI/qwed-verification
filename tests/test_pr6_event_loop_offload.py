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
from concurrent.futures import Future, ThreadPoolExecutor
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qwed_new.core import consensus_verifier as cv
from qwed_new.core.consensus_verifier import ConsensusVerifier, EngineResult
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
            # _read_bounded_csv runs for real (tiny input); intercept the
            # heavy verify_stats call only
            if fn.__name__ == "_read_bounded_csv":
                return fn(*args, **kwargs)
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
        # the df returned by the read_csv stub is what reaches verify_stats
        assert isinstance(captured.get("df"), pd.DataFrame)


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

    def test_engine_exception_records_engine_error_and_preserves_partial_results(self):
        """CodeRabbit on PR #352: an engine exception is an engine_error, not
        a timeout; already-harvested sibling results are preserved and the
        breaker receives the failure."""
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()

        def ok_engine(q):
            return EngineResult(
                engine_name="OK", method="mock", result=None, confidence=1.0,
                latency_ms=0, success=True, status="VERIFIED",
            )

        def broken_engine(q):
            raise RuntimeError("engine blew up")

        verifier._select_engines = lambda query, mode: [
            ("OK", ok_engine), ("Broken", broken_engine),
        ]
        verifier._is_engine_available = lambda engine_name: True

        try:
            result = asyncio.run(
                verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=2.0)
            )
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        by_name = {r.engine_name: r for r in result.verification_chain}
        assert by_name["OK"].success is True
        assert by_name["Broken"].status == "BLOCKED"
        assert by_name["Broken"].method == "engine_error"
        recorded_names = {
            c.args[1].engine_name for c in verifier._record_engine_result.call_args_list
        }
        assert {"OK", "Broken"} <= recorded_names

    def test_per_call_pool_is_sized_to_the_engine_list(self):
        """#352 round 8: verify_async uses a dedicated executor sized to the
        engine list — nothing ever queues, so no engine can be left
        un-started at expiry and falsely spared (or penalized)."""

        verifier = _verifier(max_workers=1)  # shared pool: 1 worker only
        verifier._record_engine_result = MagicMock()
        def fake_engine(q):
            return EngineResult(
                engine_name="E", method="mock", result=None, confidence=1.0,
                latency_ms=0, success=True, status="VERIFIED",
            )

        verifier._select_engines = lambda query, mode: [
            ("E1", fake_engine), ("E2", fake_engine), ("E3", fake_engine),
        ]
        verifier._is_engine_available = lambda engine_name: True

        with patch(
            "qwed_new.core.consensus_verifier.ThreadPoolExecutor",
            wraps=ThreadPoolExecutor,
        ) as pool_ctor:
            asyncio.run(
                verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=2)
            )

        pool_ctor.assert_called_once()
        assert pool_ctor.call_args.kwargs.get("max_workers") == 3

    def test_running_engine_recorded_even_when_wrapper_cancelled(self):
        """Greptile P1 on PR #352: cancelling the asyncio wrapper SUCCEEDS
        even while the worker thread runs — breaker recording must key on
        started evidence, not wrapper state. The per-call pool is sized to
        the engine list, so both engines start and both must be recorded."""
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()
        started = {"H1": threading.Event(), "H2": threading.Event()}

        def hung_h1(q):
            started["H1"].set()
            release.wait(timeout=15)

        def hung_h2(q):
            started["H2"].set()
            release.wait(timeout=15)

        verifier._select_engines = lambda query, mode: [
            ("H1", hung_h1), ("H2", hung_h2),
        ]
        verifier._is_engine_available = lambda engine_name: True

        try:
            asyncio.run(
                verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=2.0)
            )
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        # both engines genuinely started; both must advance the breaker
        assert started["H1"].is_set()
        assert started["H2"].is_set()
        recorded = [
            c.args[1].engine_name
            for c in verifier._record_engine_result.call_args_list
            if c.args[1].status == "BLOCKED" and c.args[1].method == "timeout"
        ]
        assert set(recorded) == {"H1", "H2"}

    def test_async_aggregate_deadline_bounds_all_engines(self):
        """CodeRabbit on PR #352: sequential per-engine waits would stack
        (N hung engines x 30s). One aggregate deadline bounds the whole
        request to a single timeout window."""
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()

        def hung_engine(q):
            release.wait(timeout=15)

        verifier._select_engines = lambda query, mode: [
            ("H1", hung_engine), ("H2", hung_engine), ("H3", hung_engine),
        ]
        verifier._is_engine_available = lambda engine_name: True

        start = time.monotonic()
        try:
            result = asyncio.run(
                verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=0.5)
            )
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        elapsed = time.monotonic() - start
        # aggregate = ~0.5s; stacked per-engine waits would be >= 1.5s — wide
        # margins on both sides keep the assertion CI-safe
        assert elapsed < 1.0
        blocked = [r for r in result.verification_chain if r.status == "BLOCKED"]
        assert len(blocked) == 3


class TestSyncCircuitOpen:
    """#352 review: circuit-open engines must stay explicit in the sync
    paths — a silent skip could let a remaining engine produce VERIFIED
    from incomplete evidence."""

    def test_parallel_circuit_open_yields_blocked_without_breaker_extension(self):
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()
        verifier._is_engine_available = lambda engine_name: False

        results = verifier._execute_parallel("q", [("E", lambda q: None)])

        assert len(results) == 1
        assert results[0].status == "BLOCKED"
        assert results[0].method == "circuit_open"
        verifier._record_engine_result.assert_not_called()

    def test_sequential_circuit_open_yields_blocked_without_breaker_extension(self):
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()
        verifier._is_engine_available = lambda engine_name: False

        results = verifier._execute_sequential("q", [("E", lambda q: None)])

        assert len(results) == 1
        assert results[0].status == "BLOCKED"
        assert results[0].method == "circuit_open"
        verifier._record_engine_result.assert_not_called()

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


class TestDeadlineSpentHarvest:
    """#352 Sonar coverage: _await_engine's deadline-spent branch — when the
    aggregate deadline expires while a sibling engine hangs, a task that
    already FINISHED must be harvested (result or exception), never wasted."""

    def test_deadline_spent_harvests_already_finished_engine(self):
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()

        def hung_engine(q):
            release.wait(timeout=15)

        def quick_engine(q):
            return EngineResult(
                engine_name="Quick", method="mock", result="42", confidence=1.0,
                latency_ms=0, success=True, status="VERIFIED",
            )

        # Hung is awaited first and consumes the whole deadline; Quick
        # finishes instantly but is only awaited after expiry.
        verifier._select_engines = lambda query, mode: [
            ("Hung", hung_engine), ("Quick", quick_engine),
        ]
        try:
            result = asyncio.run(
                verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=0.4)
            )
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        by_name = {r.engine_name: r for r in result.verification_chain}
        assert by_name["Hung"].status == "BLOCKED"
        assert by_name["Hung"].method == "timeout"
        assert by_name["Quick"].success is True
        assert by_name["Quick"].status == "VERIFIED"
        recorded_names = {
            c.args[1].engine_name for c in verifier._record_engine_result.call_args_list
        }
        assert "Quick" in recorded_names

    def test_deadline_spent_harvests_engine_exception(self):
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()

        def hung_engine(q):
            release.wait(timeout=15)

        def broken_quick_engine(q):
            raise RuntimeError("quick engine blew up")

        verifier._select_engines = lambda query, mode: [
            ("Hung", hung_engine), ("BrokenQuick", broken_quick_engine),
        ]
        try:
            result = asyncio.run(
                verifier.verify_async("q", mode=cv.VerificationMode.SINGLE, timeout_seconds=0.4)
            )
        finally:
            release.set()
            verifier._executor.shutdown(wait=False)

        by_name = {r.engine_name: r for r in result.verification_chain}
        assert by_name["Hung"].method == "timeout"
        assert by_name["BrokenQuick"].status == "BLOCKED"
        assert by_name["BrokenQuick"].method == "engine_error"


class TestSyncEngineExceptionPaths:
    """#352 Sonar coverage: the sync paths' engine-exception branch — an
    engine that RAISES (distinct from hanging) must degrade to an explicit
    BLOCKED result while sibling results are preserved."""

    def test_parallel_engine_exception_yields_blocked_and_preserves_siblings(self):
        verifier = _verifier(max_workers=2)
        verifier._record_engine_result = MagicMock()

        def ok_engine(q):
            return EngineResult(
                engine_name="OK", method="mock", result=None, confidence=1.0,
                latency_ms=0, success=True, status="VERIFIED",
            )

        def broken_engine(q):
            raise RuntimeError("boom")

        results = verifier._execute_parallel(
            "q", [("OK", ok_engine), ("Broken", broken_engine)],
        )

        by_name = {r.engine_name: r for r in results}
        assert by_name["OK"].success is True
        assert by_name["Broken"].status == "BLOCKED"
        assert by_name["Broken"].method == "parallel_execution"
        recorded_names = {
            c.args[1].engine_name for c in verifier._record_engine_result.call_args_list
        }
        assert {"OK", "Broken"} <= recorded_names

    def test_sequential_engine_exception_yields_blocked(self):
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()

        def ok_engine(q):
            return EngineResult(
                engine_name="OK", method="mock", result=None, confidence=1.0,
                latency_ms=0, success=True, status="VERIFIED",
            )

        def broken_engine(q):
            raise RuntimeError("boom")

        results = verifier._execute_sequential(
            "q", [("OK", ok_engine), ("Broken", broken_engine)],
        )

        by_name = {r.engine_name: r for r in results}
        assert by_name["OK"].success is True
        assert by_name["Broken"].status == "BLOCKED"
        assert by_name["Broken"].method == "sequential_execution"


class _FakeRaceTask:
    """Mimics the run_in_executor Future surface for the cancel race: done()
    reports False exactly once (so the deadline-spent branch takes the cancel
    path), and the task completes BEFORE cancel() is consulted."""

    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error
        self._done_checked = False

    def done(self):
        if not self._done_checked:
            self._done_checked = True
            return False
        return True

    def cancel(self):
        # a finished task can no longer be cancelled — the race signature
        return False

    def cancelled(self):
        return False

    def exception(self):
        return self._error

    def result(self):
        return self._result


class TestCancelRaceHarvest:
    """#352 round 11 (Sentry): a task that finishes in the window between
    the done() check and the cancel request must be harvested — discarding
    its result records a false breaker penalty against a healthy engine."""

    def test_cancel_race_harvests_result(self):
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()

        async def scenario():
            deadline_ns = time.monotonic_ns() - 1  # already spent
            return await verifier._await_engine(
                _FakeRaceTask(result="late-result"), deadline_ns,
            )

        result, failure, timed_out = asyncio.run(scenario())
        assert timed_out is False
        assert failure is None
        assert result == "late-result"

    def test_cancel_race_harvests_exception(self):
        verifier = _verifier(max_workers=1)

        async def scenario():
            deadline_ns = time.monotonic_ns() - 1
            return await verifier._await_engine(
                _FakeRaceTask(error=RuntimeError("finished, then blew up")),
                deadline_ns,
            )

        result, failure, timed_out = asyncio.run(scenario())
        assert timed_out is False
        assert result is None
        assert isinstance(failure, RuntimeError)

    def test_chained_future_drains_completion_tick_before_cancel(self):
        """run_in_executor wraps the concurrent future in a chained asyncio
        future — a worker that finished just before the deadline may still
        read done()==False until its completion callback is drained. The
        one-tick drain must harvest it, not cancel it."""
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()

        async def scenario():
            loop = asyncio.get_running_loop()
            fut = loop.run_in_executor(verifier._executor, lambda: "drained")
            deadline_ns = time.monotonic_ns() - 1  # already spent
            return await verifier._await_engine(fut, deadline_ns)

        result, failure, timed_out = asyncio.run(scenario())
        verifier._executor.shutdown(wait=False)
        assert timed_out is False
        assert failure is None
        assert result == "drained"

    def test_already_cancelled_task_reports_timeout(self):
        """A task that was already cancelled when the deadline-spent branch
        runs must surface as a timeout — task.exception() on a cancelled
        future raises CancelledError, so the cancelled() check guards it."""
        verifier = _verifier(max_workers=1)

        async def scenario():
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            fut.cancel()
            return await verifier._await_engine(fut, time.monotonic_ns() - 1)

        result, failure, timed_out = asyncio.run(scenario())
        assert timed_out is True
        assert result is None
        assert failure is None

    def test_pending_executor_future_is_never_harvested(self):
        """Sentry round-12 claim refuted: exception() is unreachable for a
        still-running task. The tasks here are the asyncio WRAPPER futures
        from run_in_executor, and asyncio.Future.cancel() returns False only
        when already done — the False-on-RUNNING behavior belongs to the
        wrapped concurrent.futures.Future, which _await_engine never cancels
        directly. A pending task at the deadline-spent branch therefore always
        takes the cancel/timeout path (no InvalidStateError)."""
        verifier = _verifier(max_workers=1)
        verifier._record_engine_result = MagicMock()
        release = threading.Event()

        async def scenario():
            loop = asyncio.get_running_loop()
            fut = loop.run_in_executor(
                verifier._executor, lambda: release.wait(timeout=15),
            )
            try:
                # deadline spent while the worker is genuinely still running
                return await verifier._await_engine(fut, time.monotonic_ns() - 1)
            finally:
                release.set()

        result, failure, timed_out = asyncio.run(scenario())
        verifier._executor.shutdown(wait=False)
        assert timed_out is True
        assert result is None
        assert failure is None

    def test_asyncio_future_cancel_returns_false_only_when_done(self):
        """Pins the stdlib invariant the harvest-after-cancel-false branch
        relies on: cancel() is False iff the future is already done."""
        async def scenario():
            loop = asyncio.get_running_loop()
            pending = loop.create_future()
            done = loop.create_future()
            done.set_result("x")
            cancelled = loop.create_future()
            cancelled.cancel()
            return pending.cancel(), done.cancel(), cancelled.cancel()

        pending_cancelled, done_cancelled, cancelled_cancelled = asyncio.run(scenario())
        assert pending_cancelled is True
        assert done_cancelled is False
        assert cancelled_cancelled is False
