"""#446: the sandbox has a process-wide bound on how many containers run at
once, shared across every executor instance. A request that cannot get a slot is
rejected instead of starting another container, and a container that could not be
removed keeps its slot (fail closed). Docker is not needed — the container run is
stubbed at the gate."""
import math
import threading
from types import SimpleNamespace

from qwed_new.core import secure_code_executor as sce
from qwed_new.core.secure_code_executor import SecureCodeExecutor


def _make_executor(monkeypatch):
    executor = SecureCodeExecutor()
    monkeypatch.setattr(executor, "is_available", lambda: True)
    monkeypatch.setattr(
        executor, "_is_safe_code",
        lambda code: SimpleNamespace(is_verified=True, developer_fields={"is_valid": True}, agent_message=""),
    )
    return executor


def test_request_beyond_the_bound_is_rejected(monkeypatch):
    monkeypatch.setattr(sce, "_sandbox_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(sce, "_SANDBOX_ACQUIRE_TIMEOUT_SECONDS", 0.3)
    executor = _make_executor(monkeypatch)

    in_container = threading.Event()
    hold = threading.Event()

    def blocking_run(tmpdir, execution_id, cleanup_status=None):
        in_container.set()
        hold.wait(5)

    monkeypatch.setattr(executor, "_run_in_container", blocking_run)

    holder = threading.Thread(target=lambda: executor.execute("result = 1", {}))
    holder.start()
    assert in_container.wait(2), "the first execution never entered the container"

    success, error, _ = executor.execute("result = 2", {})
    assert success is False
    assert error == sce.SANDBOX_CAPACITY_REACHED

    hold.set()
    holder.join(5)


def test_slot_is_shared_across_executor_instances(monkeypatch):
    # Consensus creates a separate SecureCodeExecutor per request, so the bound
    # must be process-wide, not per instance.
    monkeypatch.setattr(sce, "_sandbox_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(sce, "_SANDBOX_ACQUIRE_TIMEOUT_SECONDS", 0.3)
    executor_a = _make_executor(monkeypatch)
    executor_b = _make_executor(monkeypatch)

    in_container = threading.Event()
    hold = threading.Event()

    def blocking_run(tmpdir, execution_id, cleanup_status=None):
        in_container.set()
        hold.wait(5)

    monkeypatch.setattr(executor_a, "_run_in_container", blocking_run)

    holder = threading.Thread(target=lambda: executor_a.execute("result = 1", {}))
    holder.start()
    assert in_container.wait(2)

    # A different executor instance cannot get the one slot held by executor_a.
    success, error, _ = executor_b.execute("result = 2", {})
    assert success is False
    assert error == sce.SANDBOX_CAPACITY_REACHED

    hold.set()
    holder.join(5)


def test_slot_is_released_after_a_run_completes(monkeypatch):
    monkeypatch.setattr(sce, "_sandbox_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(sce, "_SANDBOX_ACQUIRE_TIMEOUT_SECONDS", 0.3)
    executor = _make_executor(monkeypatch)

    runs = []
    monkeypatch.setattr(executor, "_run_in_container", lambda tmpdir, eid, cleanup_status=None: runs.append(eid))

    # No result.json is produced, so each call returns a benign failure — but it
    # must reach _run_in_container both times, i.e. the slot was released.
    executor.execute("result = 1", {})
    executor.execute("result = 2", {})
    assert len(runs) == 2


def test_leaked_container_keeps_its_slot(monkeypatch):
    # If a container cannot be removed, the slot is held (fail closed), because a
    # leaked container still consumes host resources.
    monkeypatch.setattr(sce, "_sandbox_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(sce, "_SANDBOX_ACQUIRE_TIMEOUT_SECONDS", 0.3)
    executor = _make_executor(monkeypatch)

    def leaking_run(tmpdir, execution_id, cleanup_status=None):
        if cleanup_status is not None:
            cleanup_status["leaked"] = True  # removal failed

    monkeypatch.setattr(executor, "_run_in_container", leaking_run)

    executor.execute("result = 1", {})  # leaks, so the one slot is not released
    success, error, _ = executor.execute("result = 2", {})
    assert success is False
    assert error == sce.SANDBOX_CAPACITY_REACHED


def test_invalid_acquire_timeout_falls_back_to_default(monkeypatch):
    for value in ("nan", "inf", "-5", "abc"):
        monkeypatch.setenv("QWED_SANDBOX_ACQUIRE_TIMEOUT", value)
        resolved = sce._env_timeout("QWED_SANDBOX_ACQUIRE_TIMEOUT", 30.0)
        assert math.isfinite(resolved) and resolved > 0
        assert resolved == 30.0
