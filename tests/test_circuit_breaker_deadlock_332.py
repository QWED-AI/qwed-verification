"""Regression test for Issue #332: CircuitBreaker self-deadlock fix."""
import threading

from qwed_new.core.consensus_verifier import CircuitBreaker, ConsensusVerifier, EngineState


def test_circuit_breaker_record_success_no_deadlock():
    """record_success acquires lock and calls get_health() which re-enters lock."""
    cb = CircuitBreaker()
    # Prior to fix with non-reentrant Lock, this deadlocks on the first call
    cb.record_success("SymPy", latency_ms=12.5)

    health = cb.get_health("SymPy")
    assert health.total_calls == 1
    assert health.consecutive_failures == 0
    assert health.avg_latency_ms == 12.5


def test_circuit_breaker_record_failure_no_deadlock(monkeypatch):
    """record_failure acquires lock and calls get_health() which re-enters lock."""
    clock = [100.0]
    monkeypatch.setattr(
        "qwed_new.core.consensus_verifier.time.time",
        lambda: clock[0],
    )
    cb = CircuitBreaker(failure_threshold=3, recovery_time_seconds=1.0)

    # 1st failure
    cb.record_failure("Z3")
    assert cb.get_health("Z3").consecutive_failures == 1
    assert cb.is_available("Z3") is True

    # 2nd failure
    cb.record_failure("Z3")
    assert cb.get_health("Z3").consecutive_failures == 2
    assert cb.is_available("Z3") is True

    # 3rd failure -> trips OPEN
    cb.record_failure("Z3")
    assert cb.get_health("Z3").state == EngineState.OPEN
    assert cb.is_available("Z3") is False

    # Advance clock past recovery threshold deterministically without time.sleep
    clock[0] = 102.0

    # is_available transitions to DEGRADED
    assert cb.is_available("Z3") is True
    assert cb.get_health("Z3").state == EngineState.DEGRADED

    # Success resets to HEALTHY
    cb.record_success("Z3", latency_ms=5.0)
    assert cb.get_health("Z3").state == EngineState.HEALTHY


def test_circuit_breaker_get_all_health_thread_safe():
    """get_all_health returns complete statistics without raising under concurrency."""
    cb = CircuitBreaker()
    cb.record_success("SymPy", 10.0)
    cb.record_failure("Python")

    stats = cb.get_all_health()
    assert "SymPy" in stats
    assert "Python" in stats
    assert stats["SymPy"]["calls"] == 1
    assert stats["Python"]["failures"] == 1


def test_circuit_breaker_reset_thread_safe():
    """reset() clears engine statistics under lock."""
    cb = CircuitBreaker()
    cb.record_success("SymPy", 10.0)
    assert len(cb.get_all_health()) == 1

    cb.reset()
    assert len(cb.get_all_health()) == 0

    verifier = ConsensusVerifier(enable_circuit_breaker=True)
    verifier.circuit_breaker.record_success("Z3", 5.0)
    assert len(verifier.get_engine_health()) == 1
    verifier.reset_circuit_breakers()
    assert len(verifier.get_engine_health()) == 0


def test_circuit_breaker_concurrent_access():
    """Verify concurrent threads recording success/failure do not deadlock."""
    cb = CircuitBreaker(failure_threshold=5, recovery_time_seconds=1.0)
    errors = []

    def worker(engine: str):
        try:
            for _ in range(50):
                cb.record_success(engine, 10.0)
                cb.record_failure(engine)
                cb.is_available(engine)
                cb.get_all_health()
                if engine.endswith("0"):
                    cb.reset()
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=worker, args=(f"Engine-{i % 3}",))
        for i in range(10)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive(), "Thread deadlocked in CircuitBreaker!"

    assert not errors, f"Errors encountered during concurrent execution: {errors}"
