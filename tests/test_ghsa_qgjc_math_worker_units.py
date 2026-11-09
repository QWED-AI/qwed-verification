"""GHSA-qgjc-92m3-fcr6: the math worker's code, run in this process.

The jobs normally run in spawned worker processes, where test coverage does
not reach; here they and the pool's edge paths (a worker that dies, a start
that fails, a deadline that passes, a cancelled request) are exercised with
stand-ins, so no process is started.
"""
import asyncio
import importlib.util
import threading
import time

import pytest

from qwed_new.core import math_worker as mw
from qwed_new.core.diagnostics import admission_decision


# ------------------------------------------------------------------ settings


_SETTING = "QWED_TEST_MATH_SETTING"
_MATH_SETTINGS = ("QWED_MATH_WORKERS", "QWED_MATH_TIMEOUT_SECONDS", "QWED_MATH_MAX_WAITING", "QWED_MATH_WORKER_MEMORY_MB")


@pytest.mark.parametrize(("raw", "expected"), [(None, 2.0), ("", 2.0), ("  ", 2.0), ("1", 1.0), ("3", 3.0)])
def test_an_unset_setting_uses_its_default_and_a_valid_one_its_value(monkeypatch, raw, expected):
    """An unset or blank setting takes its default; a valid one is read as written."""
    if raw is None:
        monkeypatch.delenv(_SETTING, raising=False)
    else:
        monkeypatch.setenv(_SETTING, raw)
    assert mw._setting(_SETTING, 2.0, 1) == pytest.approx(expected)


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "nan", "NaN", "inf", "-inf", "Infinity", "1e999"])
def test_a_setting_it_cannot_use_stops_with_its_name(monkeypatch, raw):
    # float() reads "inf" and "nan", and an infinite limit would remove the
    # limit. Nothing is guessed in its place (QWED_RULES 6).
    monkeypatch.setenv(_SETTING, raw)
    with pytest.raises(mw.MathSettingError, match=_SETTING):
        mw._setting(_SETTING, 2.0, 1)


def test_a_setting_above_its_maximum_stops(monkeypatch):
    monkeypatch.setenv(_SETTING, "3601")
    with pytest.raises(mw.MathSettingError, match=r"from 0\.001 to 3600"):
        mw._setting(_SETTING, 10.0, 0.001, mw.MAX_TIMEOUT_SECONDS)


def test_a_count_must_be_a_whole_number(monkeypatch):
    monkeypatch.setenv(_SETTING, "2.5")
    with pytest.raises(mw.MathSettingError, match="whole number"):
        mw._setting(_SETTING, 2, 1, whole=True)


def test_a_count_written_with_a_zero_fraction_is_whole(monkeypatch):
    monkeypatch.setenv(_SETTING, "4.0")
    assert mw._setting(_SETTING, 2, 1, whole=True) == pytest.approx(4.0)


def _fresh_copy(module, name):
    """A new copy of *module*, run with the environment as it is now. Both
    modules read their settings at import; the copy is not put in
    sys.modules, so the imported module keeps its state."""
    spec = importlib.util.spec_from_file_location(name, module.__file__)
    copy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copy)
    return copy


def _clear_math_settings(monkeypatch):
    """Unset the four math worker settings, so a fresh copy reads only the one a test sets."""
    for name in _MATH_SETTINGS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("name", "raw"),
    [(name, "inf") for name in _MATH_SETTINGS] + [("QWED_MATH_TIMEOUT_SECONDS", "1e7"), ("QWED_MATH_WORKERS", "0")],
)
def test_the_math_worker_does_not_import_with_a_setting_it_cannot_use(monkeypatch, name, raw):
    # An infinite count made int() raise OverflowError at import, an infinite
    # time limit removed the limit, and one past what poll() takes raised in
    # every job. Each now stops the import with an error naming the setting.
    _clear_math_settings(monkeypatch)
    monkeypatch.setenv(name, raw)
    with pytest.raises(ValueError, match=name):
        _fresh_copy(mw, "qwed_math_worker_settings_copy")


def test_the_math_worker_stores_valid_settings(monkeypatch):
    _clear_math_settings(monkeypatch)
    monkeypatch.setenv("QWED_MATH_WORKERS", "3")
    monkeypatch.setenv("QWED_MATH_TIMEOUT_SECONDS", "3600")
    fresh = _fresh_copy(mw, "qwed_math_worker_settings_copy")
    assert fresh.WORKERS == 3
    assert fresh.TIMEOUT_SECONDS == pytest.approx(3600.0)
    assert fresh.MAX_WAITING == 32
    assert fresh.MEMORY_MB == 2048


@pytest.mark.parametrize("raw", ["inf", "-inf", "nan", "-1", "abc"])
def test_the_batch_service_does_not_import_with_a_budget_it_cannot_use(monkeypatch, raw):
    from qwed_new.core import batch

    # An infinite budget removed the bound, and a negative one is no budget:
    # neither is replaced by a guess.
    monkeypatch.setenv("QWED_BATCH_MATH_BUDGET_SECONDS", raw)
    with pytest.raises(ValueError, match="QWED_BATCH_MATH_BUDGET_SECONDS"):
        _fresh_copy(batch, "qwed_batch_budget_copy")


@pytest.mark.parametrize(("raw", "expected"), [(None, 120.0), ("0", 0.0), ("30", 30.0)])
def test_the_batch_service_stores_its_math_budget(monkeypatch, raw, expected):
    """Unset, the batch math budget is 120 seconds; 0 and 30 are kept as given."""
    from qwed_new.core import batch

    if raw is None:
        monkeypatch.delenv("QWED_BATCH_MATH_BUDGET_SECONDS", raising=False)
    else:
        monkeypatch.setenv("QWED_BATCH_MATH_BUDGET_SECONDS", raw)
    fresh = _fresh_copy(batch, "qwed_batch_budget_copy")
    assert fresh.BatchVerificationService._MATH_BUDGET_SECONDS == pytest.approx(expected)


# ---------------------------------------------------------------------- jobs


@pytest.mark.parametrize(
    ("expression", "context", "status", "field", "value"),
    [
        ("1/0", {}, "BLOCKED", "error", "Division by zero"),
        ("oo", {}, "BLOCKED", "error", "undefined"),
        ("sqrt(-1)", {"domain": "real"}, "BLOCKED", "error", "domain error"),
        ("1/2(3)", {}, "BLOCKED", "warning", "ambiguous"),
        # Without "=" there is no claim: the value is evidence only (#576).
        ("x + x", {}, "UNVERIFIABLE", "simplified", "2*x"),
        ("2 + 2", {}, "UNVERIFIABLE", "value", 4.0),
        ("I", {}, "UNVERIFIABLE", "simplified", "I"),
        ("x + 1 = 1 + x", {}, "VERIFIED", "is_valid", True),
        ("sinc(0)", {}, "BLOCKED", "constraint_id", "math.parse_error"),
    ],
)
def test_the_request_job_gives_the_route_verdicts(expression, context, status, field, value):
    result = mw.verify_math_request(expression, context)
    assert result.status.value == status, result.developer_fields
    assert result.developer_fields[field] == value


@pytest.mark.parametrize(
    ("expression", "status", "field", "value"),
    [
        ("x + x", "UNVERIFIABLE", "simplified", "2*x"),
        ("x + 1 = 1 + x", "VERIFIED", "is_valid", True),
        ("sinc(0) = 0", "BLOCKED", "constraint_id", "math.parse_error"),
    ],
)
def test_the_batch_job_gives_the_batch_verdicts(expression, status, field, value):
    result = mw.verify_batch_math(expression)
    assert result.status.value == status, result.developer_fields
    assert result.developer_fields[field] == value
    assert result.developer_fields["query"] == expression


# ------------------------------------------------------------ worker process


def test_the_memory_limit_is_set_only_on_linux_and_when_asked(monkeypatch):
    calls = []

    class Resource:
        RLIMIT_AS = "as"

        @staticmethod
        def setrlimit(kind, limits):
            calls.append((kind, limits))

    monkeypatch.setitem(__import__("sys").modules, "resource", Resource)
    monkeypatch.setattr(mw.sys, "platform", "linux")
    mw._limit_memory(0)
    mw._limit_memory(16)
    monkeypatch.setattr(mw.sys, "platform", "win32")
    mw._limit_memory(16)

    assert calls == [("as", (16 * 1024 * 1024, 16 * 1024 * 1024))]


class _Pipe:
    def __init__(self, *messages, fail_with=None):
        self.messages = list(messages)
        self.fail_with = fail_with
        self.sent = []

    def recv(self):
        if not self.messages:
            raise self.fail_with or EOFError()
        return self.messages.pop(0)

    def send(self, message):
        self.sent.append(message)


def test_the_worker_stops_when_its_pipe_closes(monkeypatch):
    monkeypatch.setattr(mw, "_limit_memory", lambda memory_mb: None)
    pipe = _Pipe(fail_with=EOFError())
    mw._worker_main(pipe, 0)
    assert pipe.sent == ["ready"]


def test_a_job_out_of_memory_is_reported_and_ends_the_worker(monkeypatch):
    def exhausted(*args):
        raise MemoryError()

    monkeypatch.setattr(mw, "_limit_memory", lambda memory_mb: None)
    monkeypatch.setitem(mw._JOBS, "exhausted", exhausted)
    pipe = _Pipe(("exhausted", ()), ("request", ("1+1", {})))
    mw._worker_main(pipe, 0)

    ready, result = pipe.sent
    assert result.developer_fields["constraint_id"] == mw.MATH_OUT_OF_MEMORY
    assert admission_decision(result).value == "BLOCKED"
    assert len(pipe.messages) == 1  # the next job was not taken


# ----------------------------------------------------------------- pool paths


class _Process:
    def __init__(self, alive=True):
        self.alive = alive
        self.killed = False

    def is_alive(self):
        return self.alive

    def kill(self):
        self.killed = True
        self.alive = False

    def join(self, timeout=None):
        pass


class _Conn:
    def __init__(self, result=None, fail=None):
        self.result = result
        self.fail = fail
        self.closed = False

    def send(self, message):
        if self.fail:
            raise self.fail

    def poll(self, timeout):
        return True

    def recv(self):
        return self.result

    def close(self):
        self.closed = True


def _pool_with(worker, workers=1):
    pool = mw.MathWorkerPool(workers=workers, max_waiting=0)
    pool._idle.append(worker)
    return pool


def test_a_worker_that_dies_mid_job_is_stopped_and_the_job_fails_closed():
    worker = mw._Worker(_Process(), _Conn(fail=EOFError()))
    result = _pool_with(worker).run("request", ("1+1", {}), time_limit=5)
    assert result.developer_fields["constraint_id"] == mw.MATH_WORKER_ERROR
    assert worker.conn.closed


def test_a_worker_that_ran_out_of_memory_is_not_reused():
    worker = mw._Worker(_Process(), _Conn(result=mw._out_of_memory_result()))
    pool = _pool_with(worker)
    result = pool.run("request", ("1+1", {}), time_limit=5)
    assert result.developer_fields["constraint_id"] == mw.MATH_OUT_OF_MEMORY
    assert pool._idle == []


def test_a_dead_idle_worker_is_replaced_before_a_job(monkeypatch):
    dead = mw._Worker(_Process(alive=False), _Conn())
    fresh = mw._Worker(_Process(), _Conn(result=mw.capacity_result()))
    pool = _pool_with(dead)
    monkeypatch.setattr(pool, "_start_worker", lambda: fresh)
    pool.run("request", ("1+1", {}), time_limit=5)
    assert dead.conn.closed
    assert pool._idle == [fresh]


def test_a_worker_that_cannot_start_fails_the_job_closed(monkeypatch):
    pool = mw.MathWorkerPool(workers=1, max_waiting=0)

    def broken():
        raise RuntimeError("no worker")

    monkeypatch.setattr(pool, "_start_worker", broken)
    result = pool.run("request", ("1+1", {}), time_limit=5)
    assert result.developer_fields["constraint_id"] == mw.MATH_WORKER_ERROR
    assert admission_decision(result).value == "BLOCKED"


def test_a_replacement_that_cannot_start_leaves_the_pool_empty(monkeypatch):
    pool = mw.MathWorkerPool(workers=1, max_waiting=0)

    def broken():
        raise RuntimeError("no worker")

    monkeypatch.setattr(pool, "_start_worker", broken)
    pool._replace_in_background()
    for starter in pool._starters:
        starter.join(timeout=10)
    assert pool._idle == []


def test_a_worker_is_not_kept_once_the_pool_is_closed():
    pool = mw.MathWorkerPool(workers=1, max_waiting=0)
    pool.close()
    worker = mw._Worker(_Process(), _Conn())
    pool._keep_idle(worker)
    assert pool._idle == []
    assert worker.conn.closed


def test_a_deadline_that_passes_while_waiting_for_a_slot_is_a_timeout(monkeypatch):
    pool = mw.MathWorkerPool(workers=1, max_waiting=0)

    class SlowSlots:
        def acquire(self, timeout):
            time.sleep(0.3)
            return True

        def release(self):
            pass

    pool._slots = SlowSlots()
    result = pool.run("request", ("1+1", {}), time_limit=5, deadline=time.monotonic() + 0.1)
    assert result.developer_fields["constraint_id"] == mw.MATH_TIMEOUT


def test_a_request_the_pool_cannot_admit_is_refused_on_the_event_loop(monkeypatch):
    pool = mw.MathWorkerPool(workers=1, max_waiting=0)
    pool._waiting = 1  # one request already inside
    monkeypatch.setattr(mw, "get_pool", lambda: pool)
    result = asyncio.run(mw.run_math_async("request", ("1+1", {})))
    assert result.developer_fields["constraint_id"] == mw.MATH_CAPACITY


def test_a_request_cancelled_before_its_thread_starts_is_released(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    executor = ThreadPoolExecutor(max_workers=1)
    gate = threading.Event()
    executor.submit(gate.wait)  # the only thread is busy
    monkeypatch.setattr(mw, "_math_executor", lambda: executor)
    released = []

    async def scenario():
        task = asyncio.create_task(mw.run_in_math_thread(lambda: "ran", on_not_started=lambda: released.append(True)))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(scenario())
    finally:
        gate.set()
        executor.shutdown(wait=True)
    assert released == [True]


def test_a_worker_that_never_says_ready_is_stopped(monkeypatch):
    class SilentConn(_Conn):
        def poll(self, timeout):
            return False

    class Context:
        def Pipe(self):
            return SilentConn(), _Conn()

        def Process(self, **kwargs):
            process = _Process()
            process.start = lambda: None
            return process

    pool = mw.MathWorkerPool(workers=1, max_waiting=0)
    pool._context = Context()
    monkeypatch.setattr(mw, "_START_SECONDS", 0.01)
    with pytest.raises(RuntimeError):
        pool._start_worker()
