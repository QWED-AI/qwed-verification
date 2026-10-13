"""#391: the batch job store is bounded, and a MATH item runs off the event
loop so a batch does not freeze the shared loop per item."""
import asyncio

from qwed_new.core.batch import BatchVerificationService, VerificationType


def test_job_store_is_bounded(monkeypatch):
    monkeypatch.setattr(BatchVerificationService, "_MAX_JOBS", 5)
    processor = BatchVerificationService()
    created = [processor.create_job(organization_id=1, items=[{"query": "2+2=4", "type": "math"}]).job_id
               for _ in range(20)]
    assert len(processor._jobs) == 5
    # Only the five most recent jobs are retained; older ones are evicted.
    assert set(processor._jobs.keys()) == set(created[-5:])
    for evicted in created[:-5]:
        assert processor.get_job(evicted) is None


def test_math_item_runs_off_the_event_loop(monkeypatch):
    processor = BatchVerificationService()

    called = {"thread": None}

    def fake_math(item):
        import threading
        called["thread"] = threading.current_thread().name
        return {"status": "VERIFIED"}

    monkeypatch.setattr(processor, "_verify_batch_math", fake_math)

    async def scenario():
        from qwed_new.core.batch import BatchItem
        item = BatchItem(id="j-0", query="2+2=4", verification_type=VerificationType.MATH, params={})
        main_thread = __import__("threading").current_thread().name
        result = await processor._verify_item(item, organization_id=1)
        return main_thread, result

    main_thread, result = asyncio.run(scenario())
    assert result["status"] == "VERIFIED"
    # The sympy work ran in a worker thread, not the loop thread.
    assert called["thread"] is not None and called["thread"] != main_thread
