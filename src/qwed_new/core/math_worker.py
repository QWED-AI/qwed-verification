"""Math verification in worker processes with a wall-clock limit.

SymPy can run for minutes, or without end, on input the static cost gates in
``safe_parser`` accept: a factor that cancels while parsing hides an exponent
from them, and ``simplify`` on a high-degree power is slow however it is
written. A thread cannot be stopped, so /verify/math and the math items of
/verify/batch run the SymPy work here, in a small pool of worker processes:

- each job has a wall-clock limit. A worker that passes it is killed and
  replaced, so the CPU it was using is freed, and the request gets an
  UNVERIFIABLE result (``math.timeout``), never ADMIT;
- the pool has a fixed number of workers and a bounded number of waiting
  requests. A request that finds both full is refused at once
  (``math.capacity``), so a queue cannot grow without bound;
- on Linux each worker has an address-space limit (``RLIMIT_AS``), so a job
  that builds a huge integer fails with MemoryError instead of exhausting the
  host. Windows has no such limit in the standard library; there the
  wall-clock limit still applies.

Settings (environment, read once at import):

- ``QWED_MATH_WORKERS``: worker processes, default 2.
- ``QWED_MATH_TIMEOUT_SECONDS``: wall-clock limit per job, default 10.
- ``QWED_MATH_MAX_WAITING``: requests that may wait for a free worker,
  default 32. A request waits at most its own time limit.
- ``QWED_MATH_WORKER_MEMORY_MB``: address-space limit per worker on Linux,
  default 2048; 0 turns it off.

A value the worker cannot use (not a number, not finite, out of range, a
fraction for a count, or a time limit over an hour) raises MathSettingError
at import, naming the setting, so the server does not start with it.

Attestation stays in the calling process: a worker returns the
DiagnosticResult, and the route signs it as before.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import contextvars
import logging
import math
import multiprocessing
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

from qwed_new.core.diagnostics import DiagnosticResult

logger = logging.getLogger(__name__)

MATH_TIMEOUT = "math.timeout"
MATH_CAPACITY = "math.capacity"
MATH_OUT_OF_MEMORY = "math.out_of_memory"
MATH_WORKER_ERROR = "math.worker_error"
MATH_NO_CLAIM = "math.no_claim"
INTERNAL_VERIFICATION_ERROR = "Internal verification error"


class MathSettingError(ValueError):
    """A math setting holds a value the math worker cannot use. It is raised
    at import, so the server does not start on a limit it would have to
    guess (QWED_RULES 6: no silent degradation)."""


def _setting(name: str, default: float, minimum: float, maximum: float = math.inf, whole: bool = False) -> float:
    """A numeric setting from the environment, *default* when it is unset or
    blank. A value that is not a number, not finite, outside *minimum* to
    *maximum* or, with *whole*, not a whole number raises MathSettingError
    naming the setting. ``float`` reads "inf" and "nan": an infinite limit
    would remove the limit, and an infinite count made ``int()`` raise."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not (math.isfinite(value) and minimum <= value <= maximum) or (whole and not value.is_integer()):
        kind = "a whole number" if whole else "a number"
        bound = f"from {minimum:g} to {maximum:g}" if math.isfinite(maximum) else f"of at least {minimum:g}"
        raise MathSettingError(f"{name} must be {kind} {bound}")
    return value


# A job waits for a worker, and then runs, for at most this limit each. An
# hour keeps it far below what the pipe and lock waits accept on every
# platform (about 24 days for poll()), where a larger value raised.
MAX_TIMEOUT_SECONDS = 3600.0

WORKERS = int(_setting("QWED_MATH_WORKERS", 2, 1, whole=True))
TIMEOUT_SECONDS = _setting("QWED_MATH_TIMEOUT_SECONDS", 10.0, 0.001, MAX_TIMEOUT_SECONDS)
MAX_WAITING = int(_setting("QWED_MATH_MAX_WAITING", 32, 0, whole=True))
MEMORY_MB = int(_setting("QWED_MATH_WORKER_MEMORY_MB", 2048, 0, whole=True))
# A new worker imports SymPy before it is ready; this bounds that start, not
# a job.
_START_SECONDS = 120.0


# ---------------------------------------------------------------- results


def timeout_result(seconds: float) -> DiagnosticResult:
    return DiagnosticResult.unverifiable(
        "Math verification did not finish within its time limit",
        {"constraint_id": MATH_TIMEOUT, "is_valid": False, "time_limit_seconds": seconds},
    )


def capacity_result() -> DiagnosticResult:
    return DiagnosticResult.blocked(
        "Math verification is at capacity; retry later",
        {"constraint_id": MATH_CAPACITY, "is_valid": False},
    )


def _out_of_memory_result() -> DiagnosticResult:
    return DiagnosticResult.blocked(
        "Math verification ran out of memory",
        {"constraint_id": MATH_OUT_OF_MEMORY, "is_valid": False},
    )


def _worker_error_result() -> DiagnosticResult:
    return DiagnosticResult.blocked(
        INTERNAL_VERIFICATION_ERROR,
        {"constraint_id": MATH_WORKER_ERROR, "is_valid": False},
    )


# ---------------------------------------------------------- jobs (worker side)


def verify_math_request(expression: str, context: Dict[str, Any]) -> DiagnosticResult:
    """The /verify/math verdict for *expression*, before attestation."""
    from qwed_new.core.math_identity import math_identity_result, math_parse_error_result
    from qwed_new.core.safe_parser import SafeParserError

    try:
        if "=" in expression:
            # Shared with batch math items (#530): proven false is VERIFIED
            # with is_valid False (#437), an undecided difference UNVERIFIABLE.
            return math_identity_result(expression)
        return _no_claim_result(expression, context or {})
    except SafeParserError as e:
        # Input the parser refused is the caller's to fix, not an internal
        # error (#522); SQL and schema use the same shape.
        return math_parse_error_result(e)


def _no_claim_result(expression: str, context: Dict[str, Any]) -> DiagnosticResult:
    """The verdict for an expression without "=", shared by /verify/math and
    batch math items so the two cannot disagree (#576): BLOCKED when the
    expression is undefined, outside the requested domain or ambiguous,
    otherwise UNVERIFIABLE with ``math.no_claim``. Raises SafeParserError
    for input the parser refuses."""
    import sympy
    from sympy import simplify

    from qwed_new.core.safe_parser import safe_parse_expr

    # "2(3)" is 2*(3). Only a number is rewritten, not a name that ends in
    # a digit: atan2(1, 1) became "atan2*(1, 1)", which does not parse, and
    # x2(3) stays a call, refused as an unknown function as it is with "=".
    expression_normalized = re.sub(r'\b(\d+)\(', r'\1*(', expression)
    is_ambiguous = "/" in expression and "(" in expression and bool(
        re.search(r'/\d+\(', expression.replace(" ", ""))
    )
    parsed = safe_parse_expr(expression_normalized)
    simplified = simplify(parsed)
    return _expression_result(sympy, parsed, simplified, is_ambiguous, context)


def _expression_result(sympy, parsed, simplified, is_ambiguous: bool, context: Dict[str, Any]) -> DiagnosticResult:
    if simplified.has(sympy.zoo) or simplified.has(sympy.nan):
        return DiagnosticResult.blocked(
            "Expression contains division by zero",
            developer_fields={"is_valid": False, "error": "Division by zero"},
        )
    if simplified.has(sympy.oo) or simplified.has(-sympy.oo):
        return DiagnosticResult.blocked(
            "Expression is undefined",
            developer_fields={"is_valid": False, "error": "undefined"},
        )
    if simplified.is_real is False and context.get("domain") == "real":
        return DiagnosticResult.blocked(
            "Expression is not real-valued in the requested real domain",
            developer_fields={"is_valid": False, "error": "domain error"},
        )
    if is_ambiguous:
        return DiagnosticResult.blocked(
            "Expression may be ambiguous due to implicit multiplication after division",
            developer_fields={"is_valid": False, "result": False, "status": "BLOCKED", "warning": "ambiguous", "simplified": str(simplified), "note": "Interpreted using standard order of operations", "original": str(parsed)},
        )
    # An expression without "=" states no claim, so there is nothing to
    # verify: the value SymPy computes is evidence for the caller, who can
    # send "expression = value" to have it checked (#576).
    if simplified.free_symbols != set():
        return DiagnosticResult.unverifiable(
            "Expression simplified, but no equality or proof claim was provided",
            developer_fields={
                "constraint_id": MATH_NO_CLAIM,
                "is_valid": False,
                "simplified": str(simplified),
                "original": str(parsed),
                "is_symbolic": True,
            },
        )
    try:
        exact = sympy.nsimplify(simplified)
        value = float(simplified)
    except (TypeError, ValueError, OverflowError):
        # A complex value such as I: still no claim to verify.
        return DiagnosticResult.unverifiable(
            "Expression is not numeric, and no equality or proof claim was provided",
            developer_fields={
                "constraint_id": MATH_NO_CLAIM,
                "is_valid": False,
                "simplified": str(simplified),
                "original": str(parsed),
            },
        )
    developer_fields = {
        "constraint_id": MATH_NO_CLAIM,
        "is_valid": False,
        "exact_value": str(exact),
        "simplified": str(simplified),
        "original": str(parsed),
    }
    # float() turns a finite value past the double range, such as 1e400,
    # into inf, and JSON cannot carry inf: the response failed, and in a
    # batch it failed for every item. The exact value stays, as a string.
    if math.isfinite(value):
        developer_fields["value"] = value
    return DiagnosticResult.unverifiable(
        "Expression evaluated, but no equality or proof claim was provided",
        developer_fields=developer_fields,
    )


def verify_batch_math(expression: str) -> DiagnosticResult:
    """The verdict for a /verify/batch math item, before attestation."""
    from qwed_new.core.math_identity import math_identity_result, math_parse_error_result
    from qwed_new.core.safe_parser import SafeParserError

    try:
        if "=" not in expression:
            # The verdict /verify/math gives (#576): division by zero,
            # undefined and ambiguous input is BLOCKED, as there, not
            # math.no_claim.
            dr = _no_claim_result(expression, {})
            dr.developer_fields.update({"query": expression, "type": "math"})
            return dr
        # The verdict /verify/math gives (#530): a claim proven false is
        # VERIFIED with is_valid False (#437), an undecided one UNVERIFIABLE.
        dr = math_identity_result(expression)
        dr.developer_fields.update({
            "query": expression,
            "type": "math",
            "diff": dr.developer_fields["simplified_difference"],
        })
        return dr
    except SafeParserError as exc:
        # As /verify/math (#522): refused input is BLOCKED with
        # math.parse_error, not a failed item carrying the parser's text.
        dr = math_parse_error_result(exc)
        dr.developer_fields.update({"query": expression, "type": "math"})
        return dr


_JOBS: Dict[str, Callable[..., DiagnosticResult]] = {
    "request": verify_math_request,
    "batch": verify_batch_math,
}


def _limit_memory(memory_mb: int) -> None:
    if memory_mb <= 0 or not sys.platform.startswith("linux"):
        return
    import resource

    limit = memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def _worker_main(conn, memory_mb: int) -> None:
    """Worker loop: import SymPy once, say ready, then run jobs until the
    parent closes the pipe. A job that runs out of memory ends the worker
    after its result is sent, so the next job gets a fresh process."""
    _limit_memory(memory_mb)
    import qwed_new.core.math_identity  # noqa: F401  (loads SymPy and the parser)

    conn.send("ready")
    while True:
        try:
            message = conn.recv()
        except (EOFError, OSError):
            return
        if message is None:
            return
        kind, args = message
        try:
            result = _JOBS[kind](*args)
        except MemoryError:
            conn.send(_out_of_memory_result())
            return
        except Exception as exc:  # any failure is a fail-closed result
            logger.error("Math worker job failed: %s", type(exc).__name__)
            result = _worker_error_result()
        conn.send(result)


# ---------------------------------------------------------- pool (parent side)


class _Worker:
    def __init__(self, process, conn):
        self.process = process
        self.conn = conn

    def stop(self) -> None:
        # The pipe may already be broken (the process died); closing it then
        # has nothing to release.
        with contextlib.suppress(OSError):
            self.conn.close()
        if self.process.is_alive():
            self.process.kill()
        self.process.join(timeout=5)


class MathWorkerPool:
    """A fixed number of worker processes; see the module docstring."""

    def __init__(self, workers: int = WORKERS, max_waiting: int = MAX_WAITING, memory_mb: int = MEMORY_MB):
        self._context = multiprocessing.get_context("spawn")
        self._memory_mb = memory_mb
        self._workers = workers
        # Requests inside run(): the running ones plus those waiting.
        self._max_admitted = workers + max_waiting
        self._slots = threading.BoundedSemaphore(workers)
        self._lock = threading.Lock()
        self._idle: List[_Worker] = []
        self._starters: List[threading.Thread] = []
        self._waiting = 0  # requests inside run()
        self._closed = False

    def run(self, kind: str, args: Tuple, time_limit: Optional[float] = None, deadline: Optional[float] = None) -> DiagnosticResult:
        """Run job *kind* in a worker. Waits at most *time_limit* seconds for a
        free worker, then at most *time_limit* seconds for the job. With a
        *deadline* (``time.monotonic()``), the wait and the job together end
        by it."""
        if not self.try_enter():
            return capacity_result()
        return self.run_entered(kind, args, time_limit, deadline)

    def try_enter(self) -> bool:
        """Admit one request, or refuse it when the workers and the wait list
        are full. An admitted request must end with run_entered (which
        releases it) or leave."""
        return self._enter_queue()

    def leave(self) -> None:
        with self._lock:
            self._waiting -= 1

    def run_entered(self, kind: str, args: Tuple, time_limit: Optional[float] = None, deadline: Optional[float] = None) -> DiagnosticResult:
        """``run`` for a request try_enter already admitted; releases it."""
        if time_limit is None:
            time_limit = TIMEOUT_SECONDS
        try:
            wait = time_limit if deadline is None else min(time_limit, deadline - time.monotonic())
            if wait <= 0 or not self._slots.acquire(timeout=wait):
                return capacity_result()
            try:
                if deadline is not None:
                    time_limit = min(time_limit, deadline - time.monotonic())
                    if time_limit <= 0:
                        return timeout_result(0.0)
                return self._run_in_worker(kind, args, time_limit)
            finally:
                self._slots.release()
        finally:
            self.leave()

    def _enter_queue(self) -> bool:
        with self._lock:
            if self._closed or self._waiting >= self._max_admitted:
                return False
            self._waiting += 1
            return True

    def _run_in_worker(self, kind: str, args: Tuple, time_limit: float) -> DiagnosticResult:
        try:
            worker = self._take_worker()
        except Exception as exc:  # the worker could not start
            logger.error("Math worker could not start: %s", type(exc).__name__)
            return _worker_error_result()
        try:
            worker.conn.send((kind, args))
            if not worker.conn.poll(time_limit):
                # Past its limit: kill it so the CPU is freed (GHSA-qgjc).
                logger.warning("Math job passed its %ss limit; worker replaced", time_limit)
                worker.stop()
                self._replace_in_background()
                return timeout_result(time_limit)
            result = worker.conn.recv()
        except (EOFError, OSError):
            # The worker died mid-job (for example killed by the kernel).
            worker.stop()
            return _worker_error_result()
        if result.developer_fields.get("constraint_id") == MATH_OUT_OF_MEMORY:
            # The worker ends after an out-of-memory job; never reuse it.
            worker.stop()
        else:
            self._keep_idle(worker)
        return result

    def _keep_idle(self, worker: _Worker) -> None:
        """Return *worker* to the idle list, unless it has ended, the pool is
        closed, or the list is full (a background replacement may have filled
        it), so the pool never holds more than its number of workers idle."""
        with self._lock:
            if worker.process.is_alive() and not self._closed and len(self._idle) < self._workers:
                self._idle.append(worker)
                return
        worker.stop()

    def _replace_in_background(self) -> None:
        """Start a worker for the idle list, so the next request does not
        wait for SymPy to load."""
        def start() -> None:
            try:
                worker = self._start_worker()
            except Exception as exc:  # the next request starts one instead
                logger.warning("Math worker could not be replaced: %s", type(exc).__name__)
                return
            self._keep_idle(worker)

        starter = threading.Thread(target=start, name="qwed-math-worker-start", daemon=True)
        with self._lock:
            self._starters = [t for t in self._starters if t.is_alive()] + [starter]
        starter.start()

    def _take_worker(self) -> _Worker:
        with self._lock:
            while self._idle:
                worker = self._idle.pop()
                if worker.process.is_alive():
                    return worker
                worker.stop()
        return self._start_worker()

    def _start_worker(self) -> _Worker:
        parent, child = self._context.Pipe()
        process = self._context.Process(
            target=_worker_main, args=(child, self._memory_mb), daemon=True, name="qwed-math-worker"
        )
        process.start()
        child.close()
        worker = _Worker(process, parent)
        if not parent.poll(_START_SECONDS) or parent.recv() != "ready":
            worker.stop()
            raise RuntimeError("math worker did not start")
        return worker

    def close(self) -> None:
        with self._lock:
            self._closed = True
            starters = list(self._starters)
        # A worker still starting stops itself once it sees the pool closed.
        for starter in starters:
            starter.join(timeout=_START_SECONDS)
        with self._lock:
            idle, self._idle = self._idle, []
        for worker in idle:
            # Ask it to exit; a worker that already died is stopped anyway.
            with contextlib.suppress(OSError):
                worker.conn.send(None)
            worker.stop()


_pool: Optional[MathWorkerPool] = None
_pool_lock = threading.Lock()


def get_pool() -> MathWorkerPool:
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = MathWorkerPool()
            atexit.register(_pool.close)
        return _pool


def run_math(kind: str, args: Tuple, time_limit: Optional[float] = None, deadline: Optional[float] = None) -> DiagnosticResult:
    return get_pool().run(kind, args, time_limit=time_limit, deadline=deadline)


# Threads that wait on the math workers. Not asyncio's default executor: a
# math request can hold its thread for its wait plus its run, and on the
# shared executor that queued every other route's to_thread call (audit
# commits, code verification) behind math. Sized to what the pool admits,
# so an admitted request never waits for a thread.
_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()


def _math_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(max_workers=WORKERS + MAX_WAITING, thread_name_prefix="qwed-math")
        return _executor


async def run_in_math_thread(func: Callable[..., Any], *args: Any, on_not_started: Optional[Callable[[], None]] = None) -> Any:
    """Run ``func(*args)`` on a math thread, with this context (so a batch's
    math deadline carries over). If the caller is cancelled before the call
    starts, it never starts and ``on_not_started`` runs instead."""
    context = contextvars.copy_context()
    future = _math_executor().submit(context.run, func, *args)
    try:
        return await asyncio.wrap_future(future)
    except asyncio.CancelledError:
        if future.cancel() and on_not_started is not None:
            on_not_started()
        raise


async def run_math_async(kind: str, args: Tuple, time_limit: Optional[float] = None) -> DiagnosticResult:
    """``run_math`` off the event loop: the request waits, the loop does not.
    Admission is decided here, on the loop, so a request the pool cannot take
    is refused at once and never holds a thread."""
    pool = get_pool()
    if not pool.try_enter():
        return capacity_result()
    return await run_in_math_thread(pool.run_entered, kind, args, time_limit, None, on_not_started=pool.leave)
