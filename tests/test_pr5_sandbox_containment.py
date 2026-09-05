"""Sandbox containment regression tests (issues #338 + #339).

#338: sandbox containers must cap their stdout log on the daemon host, cap
host PID allocation, and leave no container behind after any execution.
#339: the result.json read-back must be size-capped at every hop — inside
the container wrapper, at the host read-back, in the stats verifier's
observed_result evidence, and in the VerificationLog audit row.
"""

import docker
import json
import os

import pytest
from unittest.mock import MagicMock

from qwed_new.core.secure_code_executor import ExecutionError, SecureCodeExecutor
from qwed_new.core.stats_verifier import _cap_observed_result, _MAX_OBSERVED_RESULT_JSON_CHARS
from qwed_new.api.main import _cap_log_result, _MAX_LOG_RESULT_CHARS


def _executor_with_mock_docker():
    executor = SecureCodeExecutor()
    executor.docker_available = True
    executor.client = MagicMock()
    return executor


class TestContainerContainment:
    """#338: log_config, pids_limit, and guaranteed container removal."""

    def test_create_sets_log_rotation_and_pids_limit(self):
        executor = _executor_with_mock_docker()
        executor.client.containers.create.return_value = MagicMock()

        executor._run_in_container("/tmp/does-not-matter", "exec_1")

        kwargs = executor.client.containers.create.call_args.kwargs
        log_config = kwargs["log_config"]
        assert log_config.config == {"max-size": "10m", "max-file": "1"}
        assert kwargs["pids_limit"] == executor.pids_limit == 128
        # create-then-start (#351 review): the finally must cover start
        container = executor.client.containers.create.return_value
        container.start.assert_called_once()
        container.remove.assert_called_once_with(force=True)

    def test_container_removed_after_successful_wait(self):
        executor = _executor_with_mock_docker()
        container = MagicMock()
        executor.client.containers.create.return_value = container

        executor._run_in_container("/tmp", "exec_1")

        container.start.assert_called_once()
        container.wait.assert_called_once_with(timeout=executor.timeout)
        container.remove.assert_called_once_with(force=True)
        container.kill.assert_not_called()

    def test_container_removed_after_timeout_kill(self):
        executor = _executor_with_mock_docker()
        container = MagicMock()
        container.wait.side_effect = Exception("read timeout")
        executor.client.containers.create.return_value = container

        with pytest.raises(ExecutionError):
            executor._run_in_container("/tmp", "exec_1")

        container.start.assert_called_once()
        container.kill.assert_called_once()
        container.remove.assert_called_once_with(force=True)

    def test_container_removed_when_start_fails(self):
        """#351 review: run() would create-then-start, leaking the container
        when start() raises after creation. create() + start() must not."""
        executor = _executor_with_mock_docker()
        container = MagicMock()
        container.start.side_effect = docker.errors.APIError("start failed")
        executor.client.containers.create.return_value = container

        with pytest.raises(docker.errors.APIError):
            executor._run_in_container("/tmp", "exec_1")

        container.remove.assert_called_once_with(force=True)

    def test_missing_image_is_pulled_then_retried(self):
        """containers.run() auto-pulled a missing image; create() does not.
        The create path must preserve that behavior (CI regression)."""
        executor = _executor_with_mock_docker()
        container = MagicMock()
        executor.client.containers.create.side_effect = [
            docker.errors.ImageNotFound("missing"),
            container,
        ]

        result = executor._run_in_container("/tmp", "exec_1")

        assert result is container
        executor.client.images.pull.assert_called_once_with(executor.image)
        assert executor.client.containers.create.call_count == 2

    def test_removal_failure_is_warn_only(self):
        """Conflict resolution between review bots (PR #351): a removal
        failure must not discard a validly computed verification result —
        failing the result would not remove the leaked container either way.
        One automatic retry absorbs transient daemon races; the warning log
        is the operator signal if both attempts fail."""
        executor = _executor_with_mock_docker()
        container = MagicMock()
        # first attempt fails, retry succeeds
        container.remove.side_effect = [Exception("daemon race"), None]
        executor.client.containers.create.return_value = container

        result = executor._run_in_container("/tmp", "exec_1")

        assert result is container
        assert container.remove.call_count == 2

    def test_removal_retry_exhaustion_is_warn_only(self):
        executor = _executor_with_mock_docker()
        container = MagicMock()
        container.remove.side_effect = Exception("daemon down")
        executor.client.containers.create.return_value = container

        result = executor._run_in_container("/tmp", "exec_1")

        assert result is container
        assert container.remove.call_count == 2


class TestHostReadbackCap:
    """#339: no unbounded json.load on the host."""

    def test_oversized_result_file_rejected_before_parse(self):
        executor = _executor_with_mock_docker()
        executor.max_result_bytes = 100  # shrink cap for the test

        def fake_run(tmpdir, execution_id):
            with open(os.path.join(tmpdir, "result.json"), "w") as f:
                f.write("A" * 200)

        executor._run_in_container = fake_run

        success, error, result = executor.execute("result = 1", {})

        assert success is False
        assert error == "Result exceeds maximum allowed size"
        assert result is None

    def test_normal_result_still_parses(self):
        executor = _executor_with_docker_and_runner({"result": 4})

        success, error, result = executor.execute("result = 2 + 2", {})

        assert success is True
        assert result == 4


def _executor_with_docker_and_runner(payload):
    executor = _executor_with_mock_docker()

    def fake_run(tmpdir, execution_id):
        with open(os.path.join(tmpdir, "result.json"), "w") as f:
            json.dump(payload, f)

    executor._run_in_container = fake_run
    return executor


class TestWrapperCap:
    """#339: the in-container wrapper rejects oversized results before write."""

    def _run_wrapper(self, executor, user_code):
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            # the wrapper hardcodes /workspace; retarget to a portable dir and
            # run it as a real subprocess — same shape as the container run
            workspace = tmpdir.replace("\\", "/")
            with open(os.path.join(tmpdir, "context.json"), "w") as f:
                json.dump({}, f)
            wrapped = executor._wrap_code(user_code).replace("/workspace", workspace)
            script = os.path.join(tmpdir, "script.py")
            with open(script, "w") as f:
                f.write(wrapped)
            proc = subprocess.run(
                [sys.executable, script],
                capture_output=True,
                text=True,
                timeout=60,
            )
            with open(os.path.join(tmpdir, "result.json")) as f:
                return json.load(f), proc.returncode

    def test_oversized_result_rejected_inside_container(self):
        executor = SecureCodeExecutor()
        executor.max_result_bytes = 1000

        payload, returncode = self._run_wrapper(executor, "result = 'A' * 5000")

        assert returncode == 1
        assert payload == {"error": "Result exceeds maximum allowed size"}

    def test_small_result_passes_through(self):
        executor = SecureCodeExecutor()
        executor.max_result_bytes = 1000

        payload, returncode = self._run_wrapper(executor, "result = 2 + 2")

        assert returncode == 0
        assert payload == {"result": 4}


class TestObservedResultCap:
    """#339: stats evidence is capped at the source."""

    def test_small_value_passes_through_unchanged(self):
        value = {"mean": 314, "rows": [1, 2, 3]}
        assert _cap_observed_result(value) is value

    def test_large_value_replaced_with_bounded_preview(self):
        value = ["A" * 50_000] * 5
        capped = _cap_observed_result(value)

        assert capped["truncated"] is True
        assert len(capped["preview"]) <= 10_000
        assert len(json.dumps(capped)) < 20_000

    def test_unserializable_value_falls_back_to_marker(self):
        assert _cap_observed_result({"bad": object()}) == "<unserializable result>"

    def test_aggregate_traversal_budget_stops_cloning(self):
        """Greptile P1 on PR #351: many small values must not drive unbounded
        traversal of the aggregate on the event loop."""
        value = [{"m": "A" * 100} for _ in range(10_000)]  # ~1 MB raw
        capped = _cap_observed_result(value)

        assert len(json.dumps(capped)) < _MAX_OBSERVED_RESULT_JSON_CHARS * 3


class TestLogResultCap:
    """#339: audit rows cannot persist an unbounded serialized result.

    The audit integrity verifier decodes this field with json.loads, so the
    output must be VALID JSON in both paths (CodeAnt on PR #351).
    """

    def test_small_result_is_valid_json(self):
        dr = {"status": "VERIFIED", "developer_fields": {"a": 1}}
        capped = _cap_log_result(dr)

        assert json.loads(capped) == dr

    def test_large_string_value_bounded_inline(self):
        """Greptile P2 on PR #351: a string value is a single iterencode
        token — it must be truncated BEFORE encoding, not after. The output
        keeps the document structure with the value bounded inline."""
        dr = {"status": "UNVERIFIABLE", "blob": "A" * (_MAX_LOG_RESULT_CHARS + 1000)}
        capped = _cap_log_result(dr)

        parsed = json.loads(capped)
        assert parsed["blob"].endswith("...[truncated]")
        assert len(parsed["blob"]) <= 1100
        assert len(capped) < 2000

    def test_aggregate_size_still_hits_the_truncated_document(self):
        """Many individually-bounded strings summing past the cap produce
        the bounded preview document."""
        dr = {f"k{i}": "A" * 1000 for i in range(100)}
        capped = _cap_log_result(dr)

        parsed = json.loads(capped)
        assert parsed["truncated"] is True
        # envelope length reserved before slicing: strictly inside the cap
        assert len(capped) <= _MAX_LOG_RESULT_CHARS

    def test_aggregate_traversal_budget_stops_cloning(self):
        """Greptile P1 on PR #351: many small values must not drive unbounded
        traversal of the aggregate — the bounder stops at the budget."""
        dr = {f"k{i}": "A" * 200 for i in range(20_000)}  # ~4 MB raw
        capped = _cap_log_result(dr)

        assert len(capped) < _MAX_LOG_RESULT_CHARS * 3
        json.loads(capped)  # parseability

    def test_printable_non_ascii_stays_bounded(self):
        """CodeRabbit envelope follow-up: printable non-ASCII (emoji) escapes
        to 12 chars under ensure_ascii — the fallback must still hold the
        cap, so it encodes with ensure_ascii=False after sanitization."""
        dr = {f"k{i}": "😀" * 2000 for i in range(100)}
        capped = _cap_log_result(dr)

        parsed = json.loads(capped)
        assert parsed["truncated"] is True
        assert len(capped) <= _MAX_LOG_RESULT_CHARS

    def test_non_string_dict_key_does_not_discard_payload(self):
        """CodeRabbit shared-helper note: a non-string key must not TypeError
        the whole payload into the unserializable fallback."""
        dr = {"status": "VERIFIED", 42: "answer"}
        capped = _cap_log_result(dr)

        parsed = json.loads(capped)
        assert parsed["42"] == "answer"

    def test_oversized_output_stays_bounded(self):
        """The truncated-document path must stay bounded even when the
        content is quote-heavy or control-character-heavy (CodeRabbit on
        PR #351: escaping would otherwise expand the payload past the cap)."""
        dr = {f"k{i}": '"' * 1000 for i in range(100)}
        capped = _cap_log_result(dr)
        assert len(capped) < _MAX_LOG_RESULT_CHARS + 500
        json.loads(capped)

        dr = {f"k{i}": "\n" * 1000 for i in range(100)}
        capped = _cap_log_result(dr)
        parsed = json.loads(capped)
        assert parsed["truncated"] is True
        assert "\n" not in parsed["preview"]
        assert len(capped) < _MAX_LOG_RESULT_CHARS + 500

    def test_circular_reference_yields_bounded_json(self):
        """The bounder breaks the cycle inline; output stays small valid JSON."""
        dr = {"status": "VERIFIED"}
        dr["self"] = dr
        capped = _cap_log_result(dr)

        parsed = json.loads(capped)
        assert parsed["self"] == "...[circular]"
        assert len(capped) < 500

    def test_circular_list_reference_yields_bounded_json(self):
        """Sentry on PR #351: lists must get the same cycle handling as dicts."""
        dr = {"status": "VERIFIED", "rows": []}
        dr["rows"].append(dr["rows"])
        capped = _cap_log_result(dr)

        parsed = json.loads(capped)
        assert parsed["rows"] == ["...[circular]"]
        assert len(capped) < 500
