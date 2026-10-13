"""#390: a blocking provider call must run off the event loop under a timeout,
so a slow or hung upstream cannot stall the shared loop for every co-tenant."""
import asyncio
import time

import pytest

from qwed_new.core import control_plane as cp


def test_provider_call_does_not_block_the_loop_and_times_out(monkeypatch):
    # A short bound so the test is fast; the real default is 30s.
    monkeypatch.setattr(cp, "_PROVIDER_CALL_TIMEOUT_SECONDS", 0.3)

    async def scenario():
        ticks = 0

        async def heartbeat():
            nonlocal ticks
            # If the provider call blocked the loop, these ticks could not run.
            for _ in range(20):
                await asyncio.sleep(0.02)
                ticks += 1

        beat = asyncio.ensure_future(heartbeat())
        start = time.perf_counter()
        with pytest.raises(asyncio.TimeoutError):
            # A blocking call that outlasts the timeout.
            await cp._run_provider_call(time.sleep, 5)
        elapsed = time.perf_counter() - start
        await beat
        return elapsed, ticks

    elapsed, ticks = asyncio.run(scenario())
    assert elapsed < 1.0, f"timeout did not fire promptly ({elapsed:.2f}s)"
    assert ticks > 5, "event loop was blocked during the provider call"
