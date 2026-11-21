"""The one thread every z3 solve on a request path runs on.

z3py's default context is not thread safe, and its objects must be created and
freed on the same thread. A single-worker executor keeps every z3 solve on one
dedicated thread: off the event loop, never concurrent with another solve, and
never finalising z3 objects on a foreign thread. Only the fast solve runs here
(a provider translation runs elsewhere, concurrently), so the queue stays
short.

The control plane's logic route solves here from the event loop
(``run_z3_call``), and the consensus Z3 engine from its worker thread
(``run_z3_call_blocking``, #659).
"""

import asyncio
import concurrent.futures
import functools
import os

Z3_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="qwed-z3")
Z3_CALL_TIMEOUT_SECONDS = float(os.environ.get("QWED_Z3_TIMEOUT", "15"))


async def run_z3_call(func, *args, **kwargs):
    """Run a z3 solve on the z3 thread, bounded by a timeout, from the event
    loop."""
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(Z3_EXECUTOR, functools.partial(func, *args, **kwargs)),
        timeout=Z3_CALL_TIMEOUT_SECONDS,
    )


def run_z3_call_blocking(func, *args, **kwargs):
    """Run a z3 solve on the z3 thread from a worker thread, bounded by the
    same timeout, which raises TimeoutError.

    Not for the event loop, which it would block, nor for the z3 thread
    itself, which would wait on its own queue until the timeout.
    """
    future = Z3_EXECUTOR.submit(func, *args, **kwargs)
    try:
        return future.result(timeout=Z3_CALL_TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError as exc:
        # A solve that has not started is dropped; one that has finishes on
        # the z3 thread and its result is discarded. The built-in
        # TimeoutError, which this one is only from Python 3.11.
        future.cancel()
        raise TimeoutError(f"z3 call did not finish in {Z3_CALL_TIMEOUT_SECONDS}s") from exc
