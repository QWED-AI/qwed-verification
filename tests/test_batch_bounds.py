"""#391: the batch job store is bounded, finished jobs are evicted first, a
still-running job is never evicted, and a MATH item runs off the event loop."""
import asyncio

import pytest

from qwed_new.core.batch import (
    BatchCapacityError,
    BatchStatus,
    BatchVerificationService,
    VerificationType,
)


def test_finished_jobs_are_evicted_oldest_first(monkeypatch):
    monkeypatch.setattr(BatchVerificationService, "_MAX_JOBS", 5)
    processor = BatchVerificationService()
    created = []
    for _ in range(20):
        job = processor.create_job(organization_id=1, items=[{"query": "2+2=4", "type": "math"}])
        job.status = BatchStatus.COMPLETED  # finished, so evictable
        created.append(job.job_id)
    assert len(processor._jobs) == 5
    assert set(processor._jobs.keys()) == set(created[-5:])
    for evicted in created[:-5]:
        assert processor.get_job(evicted) is None


def test_running_jobs_are_not_evicted_and_full_store_rejects(monkeypatch):
    monkeypatch.setattr(BatchVerificationService, "_MAX_JOBS", 3)
    processor = BatchVerificationService()
    running = []
    for _ in range(3):
        job = processor.create_job(organization_id=1, items=[{"query": "2+2=4", "type": "math"}])
        job.status = BatchStatus.PROCESSING  # still running
        running.append(job.job_id)
    # The store is full of active jobs; a new admission is rejected, not swapped in.
    with pytest.raises(BatchCapacityError):
        processor.create_job(organization_id=1, items=[{"query": "1+1=2", "type": "math"}])
    for job_id in running:
        assert processor.get_job(job_id) is not None


def test_math_item_runs_off_the_event_loop(monkeypatch):
    processor = BatchVerificationService()

    called = {"thread": None}

    def fake_math(item):
        import threading
        called["thread"] = threading.current_thread().name
        return {"status": "VERIFIED"}

    monkeypatch.setattr(processor, "_verify_batch_math", fake_math)

    async def scenario():
        import threading
        from qwed_new.core.batch import BatchItem
        item = BatchItem(id="j-0", query="2+2=4", verification_type=VerificationType.MATH, params={})
        main_thread = threading.current_thread().name
        result = await processor._verify_item(item, organization_id=1)
        return main_thread, result

    main_thread, result = asyncio.run(scenario())
    assert result["status"] == "VERIFIED"
    # The sympy work ran in a worker thread, not the loop thread.
    assert called["thread"] is not None
    assert called["thread"] != main_thread
