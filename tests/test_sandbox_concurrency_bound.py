"""#446: the sandbox has a process-wide bound on how many containers run at
once. A request that cannot get a slot is rejected instead of starting another
container. Docker is not needed — the container run is stubbed at the gate."""
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
    # One slot, a short wait, and a container run that blocks until released.
    monkeypatch.setattr(sce, "_sandbox_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(sce, "_SANDBOX_ACQUIRE_TIMEOUT_SECONDS", 0.3)
    executor = _make_executor(monkeypatch)

    in_container = threading.Event()
    hold = threading.Event()

    def blocking_run(tmpdir, execution_id):
        in_container.set()
        hold.wait(5)

    monkeypatch.setattr(executor, "_run_in_container", blocking_run)

    first_result = {}

    def hold_the_slot():
        first_result["value"] = executor.execute("result = 1", {})

    holder = threading.Thread(target=hold_the_slot)
    holder.start()
    assert in_container.wait(2), "the first execution never entered the container"

    # The one slot is taken; a second request cannot get it within the timeout.
    success, error, _ = executor.execute("result = 2", {})
    assert success is False
    assert error == sce.SANDBOX_CAPACITY_REACHED

    hold.set()
    holder.join(5)


def test_slot_is_released_after_the_container_finishes(monkeypatch):
    # After a run completes, the slot is free for the next request.
    monkeypatch.setattr(sce, "_sandbox_slots", threading.BoundedSemaphore(1))
    monkeypatch.setattr(sce, "_SANDBOX_ACQUIRE_TIMEOUT_SECONDS", 0.3)
    executor = _make_executor(monkeypatch)

    runs = []
    monkeypatch.setattr(executor, "_run_in_container", lambda tmpdir, eid: runs.append(eid))

    # No result.json is produced, so each call returns a benign failure — but it
    # must reach _run_in_container, i.e. it got a slot both times.
    executor.execute("result = 1", {})
    executor.execute("result = 2", {})
    assert len(runs) == 2
