"""Sandbox containment regression tests (issues #338 + #339).

#338: sandbox containers must cap their stdout log on the daemon host, cap
host PID allocation, and leave no container behind after any execution.
#339: the result.json read-back must be size-capped at every hop — inside
the container wrapper, at the host read-back, in the stats verifier's
observed_result evidence, and in the VerificationLog audit row.
"""

import json
import os

import pytest
from unittest.mock import MagicMock

from qwed_new.core.secure_code_executor import ExecutionError, SecureCodeExecutor
from qwed_new.core.stats_verifier import _cap_observed_result
from qwed_new.api.main import _cap_log_result, _MAX_LOG_RESULT_CHARS


def _executor_with_mock_docker():
    executor = SecureCodeExecutor()
    executor.docker_available = True
    executor.client = MagicMock()
    return executor


class TestContainerContainment:
    """#338: log_config, pids_limit, and guaranteed container removal."""

    def test_run_sets_log_rotation_and_pids_limit(self):
        executor = _executor_with_mock_docker()
        executor.client.containers.run.return_value = MagicMock()

        executor._run_in_container("/tmp/does-not-matter", "exec_1")

        kwargs = executor.client.containers.run.call_args.kwargs
        log_config = kwargs["log_config"]
        assert log_config.config == {"max-size": "10m", "max-file": "1"}
        assert kwargs["pids_limit"] == executor.pids_limit == 128
        # removal is explicit in the finally, not delegated to the daemon
        assert kwargs["remove"] is False

    def test_container_removed_after_successful_wait(self):
        executor = _executor_with_mock_docker()
        container = MagicMock()
        executor.client.containers.run.return_value = container

        executor._run_in_container("/tmp", "exec_1")

        container.wait.assert_called_once_with(timeout=executor.timeout)
        container.remove.assert_called_once_with(force=True)
        container.kill.assert_not_called()

    def test_container_removed_after_timeout_kill(self):
        executor = _executor_with_mock_docker()
        container = MagicMock()
        container.wait.side_effect = Exception("read timeout")
        executor.client.containers.run.return_value = container

        with pytest.raises(ExecutionError):
            executor._run_in_container("/tmp", "exec_1")

        container.kill.assert_called_once()
        container.remove.assert_called_once_with(force=True)

    def test_removal_failure_does_not_mask_successful_execution(self):
        executor = _executor_with_mock_docker()
        container = MagicMock()
        container.remove.side_effect = Exception("daemon hiccup")
        executor.client.containers.run.return_value = container

        result = executor._run_in_container("/tmp", "exec_1")

        assert result is container


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
        value = {"mean": 3.14, "rows": [1, 2, 3]}
        assert _cap_observed_result(value) is value

    def test_large_value_replaced_with_bounded_preview(self):
        value = ["A" * 50_000] * 5
        capped = _cap_observed_result(value)

        assert capped["truncated"] is True
        assert capped["serialized_chars"] > 10_000
        assert len(capped["preview"]) <= 10_000
        assert len(json.dumps(capped)) < 20_000


class TestLogResultCap:
    """#339: audit rows cannot persist an unbounded serialized result."""

    def test_small_result_unchanged(self):
        dr = {"status": "VERIFIED", "developer_fields": {"a": 1}}
        assert _cap_log_result(dr) == str(dr)

    def test_large_result_truncated_with_marker(self):
        dr = {"status": "UNVERIFIABLE", "blob": "A" * (_MAX_LOG_RESULT_CHARS + 1000)}
        capped = _cap_log_result(dr)

        assert len(capped) < _MAX_LOG_RESULT_CHARS + 200
        assert "truncated" in capped
