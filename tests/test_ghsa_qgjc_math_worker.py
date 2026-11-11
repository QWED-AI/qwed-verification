"""GHSA-qgjc-92m3-fcr6: /verify/math and the math items of /verify/batch ran
SymPy on the event loop or in a thread, with no wall-clock limit. Input the
static cost gates accept could still run for minutes: a factor that cancels
while parsing hid an exponent from the gates, and simplify on a high-degree
power is slow however it is written. The cost gate also parsed with SymPy's
default namespace.

SymPy now runs in worker processes (core/math_worker.py). A job past its limit
is UNVERIFIABLE (math.timeout) and its worker is killed; a full pool refuses at
once (math.capacity); a batch has a math budget; the cost gate parses with the
parser's own restricted namespace.
"""
import asyncio
import sys
import time

import pytest

from qwed_new.core import math_worker as mw
from qwed_new.core.batch import BATCH_MATH_BUDGET, BatchItem, BatchJob, BatchVerificationService, VerificationType
from qwed_new.core.diagnostics import admission_decision

# simplify() on these runs far past a one-second limit.
SLOW = "(x+1)**3000"
SLOW_IDENTITY = "(x+1)**2000 - x = 1"
# A factor that cancels while parsing (x/x) hides the exponent from the
# static gates.
CANCELLING = ["2**((10000*x/x)**9)", "(9**9999*x)**9999", "(x/x*9**9999)**9999"]


@pytest.fixture(scope="module")
def pool():
    pool = mw.MathWorkerPool(workers=1, max_waiting=0)
    # Warm the worker, so later limits measure jobs, not SymPy's import.
    assert pool.run("request", ("1+1 = 2", {}), time_limit=120).status.value == "VERIFIED"
    yield pool
    pool.close()


def _assert_timed_out(result):
    assert result.status.value == "UNVERIFIABLE", result
    assert result.developer_fields["constraint_id"] == mw.MATH_TIMEOUT
    assert result.developer_fields["is_valid"] is False
    assert admission_decision(result).value == "BLOCKED"


@pytest.mark.parametrize("expression", [SLOW, SLOW_IDENTITY, *CANCELLING])
def test_a_job_past_its_limit_is_unverifiable_and_its_worker_is_killed(pool, expression):
    started = time.monotonic()

    result = pool.run("request", (expression, {}), time_limit=1)

    # The limit plus process teardown; never the minutes the job would take.
    assert time.monotonic() - started < 15
    _assert_timed_out(result)


def test_the_killed_worker_is_gone_and_a_new_one_serves_the_next_request(pool):
    pool.run("request", ("2+2", {}), time_limit=120)
    (before,) = pool._idle
    _assert_timed_out(pool.run("request", (SLOW, {}), time_limit=1))

    before.process.join(timeout=10)
    assert not before.process.is_alive()
    result = pool.run("request", ("3*4", {}), time_limit=120)
    # No "=", so no claim (#576): UNVERIFIABLE, with the value still computed.
    assert result.status.value == "UNVERIFIABLE"
    assert result.developer_fields["value"] == 12.0


@pytest.mark.serial
def test_a_full_pool_refuses_at_once(pool):
    results = []

    def slow():
        results.append(pool.run("request", (SLOW, {}), time_limit=3))

    import threading

    runner = threading.Thread(target=slow)
    runner.start()
    time.sleep(0.5)
    started = time.monotonic()
    refused = pool.run("request", ("1+1", {}), time_limit=3)
    elapsed = time.monotonic() - started
    runner.join()

    assert elapsed < 1
    assert refused.status.value == "BLOCKED"
    assert refused.developer_fields["constraint_id"] == mw.MATH_CAPACITY
    assert admission_decision(refused).value == "BLOCKED"
    _assert_timed_out(results[0])


def test_ordinary_requests_still_get_their_verdicts(pool):
    identity = pool.run("request", ("x**2 + 2*x + 1 = (x+1)**2", {}), time_limit=60)
    false_identity = pool.run("request", ("x + 1 = x + 2", {}), time_limit=60)
    value = pool.run("request", ("2+2", {}), time_limit=60)
    refused = pool.run("request", ("sinc(0) = 0", {}), time_limit=60)

    assert (identity.status.value, admission_decision(identity).value) == ("VERIFIED", "ADMIT")
    assert identity.developer_fields["is_valid"] is True
    assert false_identity.developer_fields["is_valid"] is False
    assert admission_decision(false_identity).value == "BLOCKED"
    assert value.developer_fields["value"] == 4.0
    assert refused.developer_fields["constraint_id"] == "math.parse_error"


def test_a_deadline_bounds_the_wait_and_the_job(pool):
    started = time.monotonic()
    result = pool.run("request", (SLOW, {}), time_limit=60, deadline=time.monotonic() + 1)
    assert time.monotonic() - started < 15
    _assert_timed_out(result)


def test_the_request_does_not_block_the_event_loop(monkeypatch, pool):
    monkeypatch.setattr(mw, "get_pool", lambda: pool)

    async def scenario():
        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(10):
                await asyncio.sleep(0.05)
                ticks += 1

        result, _ = await asyncio.gather(mw.run_math_async("request", (SLOW, {}), time_limit=1), ticker())
        return result, ticks

    result, ticks = asyncio.run(scenario())
    assert ticks == 10
    _assert_timed_out(result)


def test_a_batch_item_with_no_budget_left_is_not_run(monkeypatch):
    service = BatchVerificationService()
    monkeypatch.setattr(service, "_MATH_BUDGET_SECONDS", 0)
    calls = []
    monkeypatch.setattr(mw, "run_math", lambda *a, **k: calls.append(a))
    job = BatchJob(
        job_id="job-qgjc",
        organization_id=1,
        items=[BatchItem(id="i-0", query="1+1 = 2", verification_type=VerificationType.MATH, params={})],
    )

    asyncio.run(service.process_job(job))

    (item,) = job.items
    assert calls == []
    assert item.result["constraint_id"] == BATCH_MATH_BUDGET
    assert item.result["admission"] == "BLOCKED"


def test_batch_items_share_the_job_budget(monkeypatch, pool):
    monkeypatch.setattr(mw, "get_pool", lambda: pool)
    service = BatchVerificationService(max_concurrency=1)
    monkeypatch.setattr(service, "_MATH_BUDGET_SECONDS", 2)
    job = BatchJob(
        job_id="job-qgjc-budget",
        organization_id=1,
        items=[
            BatchItem(id=f"i-{n}", query=SLOW_IDENTITY, verification_type=VerificationType.MATH, params={})
            for n in range(3)
        ],
    )

    started = time.monotonic()
    asyncio.run(service.process_job(job))

    # Three slow items, one at a time, within the 2 s budget plus teardown.
    assert time.monotonic() - started < 30
    constraints = sorted(item.result["constraint_id"] for item in job.items)
    assert set(constraints) <= {mw.MATH_TIMEOUT, BATCH_MATH_BUDGET}
    assert all(item.result["admission"] == "BLOCKED" for item in job.items)


def test_a_full_pool_and_a_timeout_never_admit(pool):
    for result in (mw.capacity_result(), mw.timeout_result(1.0)):
        assert admission_decision(result).value == "BLOCKED"
        assert result.developer_fields["is_valid"] is False


def _address_space_peak_mb(pool):
    """The most address space the pool's one idle worker has mapped."""
    (worker,) = pool._idle
    with open(f"/proc/{worker.process.pid}/status", encoding="ascii") as status:
        for line in status:
            if line.startswith("VmPeak:"):
                return int(line.split()[1]) // 1024 + 1
    raise AssertionError("no VmPeak line for the worker")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is Linux only")
def test_a_job_past_the_memory_limit_is_out_of_memory_and_its_worker_ends():
    # The limit sits 64 MB above what a warm worker has mapped, so this job
    # passes it within seconds. A fixed 600 MB limit let the job run into its
    # 60 s time limit first, and the result did not say which limit ended it.
    unlimited = mw.MathWorkerPool(workers=1, max_waiting=0, memory_mb=0)
    try:
        assert unlimited.run("request", ("1+1 = 2", {}), time_limit=120).status.value == "VERIFIED"
        limit_mb = _address_space_peak_mb(unlimited) + 64
    finally:
        unlimited.close()

    pool = mw.MathWorkerPool(workers=1, max_waiting=0, memory_mb=limit_mb)
    try:
        assert pool.run("request", ("1+1 = 2", {}), time_limit=120).status.value == "VERIFIED"
        (before,) = pool._idle
        # 2**(2**30), a 128 MB integer, once 2*x/x cancels.
        result = pool.run("request", ("2**((2*x/x)**30)", {}), time_limit=60)
        assert result.developer_fields["constraint_id"] == mw.MATH_OUT_OF_MEMORY
        assert result.developer_fields["is_valid"] is False
        assert admission_decision(result).value == "BLOCKED"

        before.process.join(timeout=10)
        assert not before.process.is_alive()
        assert pool.run("request", ("1+1 = 2", {}), time_limit=120).status.value == "VERIFIED"
    finally:
        pool.close()


# ------------------------------------------------------------ cost gate namespace


def test_the_cost_gate_namespace_holds_only_the_classes_it_needs():
    from qwed_new.core.safe_parser import _COST_GATE_GLOBAL_DICT_TEMPLATE

    assert _COST_GATE_GLOBAL_DICT_TEMPLATE["__builtins__"] == {}
    assert set(_COST_GATE_GLOBAL_DICT_TEMPLATE) == {
        "__builtins__", "Symbol", "Function", "Integer", "Float", "Rational", "Add", "Mul", "Pow",
    }


def test_the_cost_gate_does_not_run_sympy_functions_outside_the_parser(monkeypatch):
    # The gate parsed implicit-multiplication input with SymPy's default
    # namespace, so a SymPy function the parser does not offer ran there.
    import sympy

    from qwed_new.core import safe_parser

    calls = []
    real_expand = sympy.expand

    def recording_expand(*args, **kwargs):
        calls.append(args)
        return real_expand(*args, **kwargs)

    monkeypatch.setattr(sympy, "expand", recording_expand)
    safe_parser._check_unevaluated_sympy_cost("expand((x+1)**2) y")
    assert calls == []


def test_the_cost_gate_reads_names_as_the_parser_does():
    # The gate split unknown names into letters (split_symbols) while the
    # parser no longer does.
    from sympy.parsing.sympy_parser import split_symbols

    from qwed_new.core.safe_parser import _PARSER_TRANSFORMATIONS

    assert split_symbols not in _PARSER_TRANSFORMATIONS


def test_a_job_that_raises_in_the_worker_is_blocked_without_its_text(monkeypatch):
    # The worker loop, run in this process with a stand-in pipe.
    import sympy

    monkeypatch.setattr(sympy, "simplify", lambda *a, **k: (_ for _ in ()).throw(ValueError("SENSITIVE DETAIL")))
    sent = []

    class Pipe:
        def __init__(self):
            self.messages = [("request", ("1+1", {})), None]

        def recv(self):
            return self.messages.pop(0)

        def send(self, message):
            sent.append(message)

    monkeypatch.setattr(mw, "_limit_memory", lambda memory_mb: None)
    mw._worker_main(Pipe(), 0)

    assert sent[0] == "ready"
    result = sent[1]
    assert result.status.value == "BLOCKED"
    assert result.agent_message == mw.INTERNAL_VERIFICATION_ERROR
    assert result.developer_fields["constraint_id"] == mw.MATH_WORKER_ERROR
    assert "SENSITIVE DETAIL" not in str(result)


def test_the_pool_never_keeps_more_idle_workers_than_it_has(pool):
    for _ in range(3):
        _assert_timed_out(pool.run("request", (SLOW, {}), time_limit=1))
        pool.run("request", ("1+1", {}), time_limit=120)
    for starter in list(pool._starters):
        starter.join(timeout=120)
    assert len(pool._idle) <= 1


def test_math_waits_do_not_hold_the_shared_thread_pool(monkeypatch):
    # Every route's asyncio.to_thread call (audit commits, code verification)
    # shares asyncio's default executor; math waits run on their own threads.
    from concurrent.futures import ThreadPoolExecutor

    pool = mw.MathWorkerPool(workers=1, max_waiting=8)
    try:
        assert pool.run("request", ("1+1 = 2", {}), time_limit=120).status.value == "VERIFIED"
        monkeypatch.setattr(mw, "get_pool", lambda: pool)

        async def scenario():
            asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=2))
            slow = [asyncio.create_task(mw.run_math_async("request", (SLOW, {}), time_limit=2)) for _ in range(4)]
            await asyncio.sleep(0.3)
            started = time.monotonic()
            await asyncio.to_thread(lambda: None)
            waited = time.monotonic() - started
            await asyncio.gather(*slow)
            return waited

        assert asyncio.run(scenario()) < 1
    finally:
        pool.close()
