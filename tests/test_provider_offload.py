"""#390 / PR #447: blocking provider calls run off the event loop under a
timeout, and the logic path splits translation (concurrent) from the z3 solve
(one dedicated thread), so neither blocks the shared loop."""
import asyncio
import threading

from qwed_new.core import control_plane as cp


def test_provider_call_is_offloaded_and_times_out(monkeypatch):
    # A short bound so the test is fast; the real default is 30s.
    monkeypatch.setattr(cp, "_PROVIDER_CALL_TIMEOUT_SECONDS", 0.3)
    release = threading.Event()

    def blocking(*args, **kwargs):
        # Outlasts the timeout, but returns once released so the orphaned worker
        # does not keep the test alive after the assertion.
        release.wait(5)

    async def heartbeat():
        ticks = 0
        for _ in range(20):
            await asyncio.sleep(0.02)
            ticks += 1
        return ticks

    async def call():
        try:
            await cp._run_provider_call(blocking, "arg")
            return None
        except asyncio.TimeoutError as exc:
            return exc
        finally:
            release.set()

    async def scenario():
        # If the provider call blocked the loop, the heartbeat could not tick.
        exc, ticks = await asyncio.gather(call(), heartbeat())
        return exc, ticks

    exc, ticks = asyncio.run(scenario())
    assert isinstance(exc, asyncio.TimeoutError)
    assert ticks > 5, "event loop was blocked during the provider call"


def test_z3_call_runs_on_the_single_z3_thread_and_is_correct():
    # The z3 solve runs off the loop, on one dedicated thread, and returns the
    # right verdicts; concurrent solves are serialized there without crashing.
    from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier

    verifier = DSLLogicVerifier()
    variables = [{"name": "x", "type": "Int"}]
    threads_seen = set()

    def tag_then_solve(dsl):
        threads_seen.add(threading.current_thread().name)
        return verifier.verify_from_dsl(dsl, variables)

    async def scenario():
        results = await asyncio.gather(*[
            cp._run_z3_call(tag_then_solve, dsl)
            for dsl in ["(AND (GT x 5) (LT x 10))", "(AND (GT x 10) (LT x 5))"] * 5
        ])
        return results

    results = asyncio.run(scenario())
    statuses = [r.status for r in results]
    assert statuses.count("SAT") == 5
    assert statuses.count("UNSAT") == 5
    # Every solve ran on the single z3 worker thread, never the loop thread.
    assert len(threads_seen) == 1
    assert next(iter(threads_seen)).startswith("qwed-z3")
