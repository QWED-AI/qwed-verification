"""#431: CrossHair imports, and so executes, the code it analyses.

SymbolicVerifier used to run ``python -m crosshair check`` as a plain host
subprocess on a temp file holding the caller's code. Every CrossHair run now
goes through SecureCodeExecutor.run_isolated (no network, read-only root, no
host mounts, no capabilities, unprivileged user, resource limits). When the
sandbox cannot run it, the result is BLOCKED and the code is never imported
on the host.
"""

import ast
import os
import re
import subprocess
import sys
from unittest.mock import MagicMock, patch

import docker
import pytest
import requests
import urllib3

from qwed_new.core import secure_code_executor as sce
from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.secure_code_executor import (
    MAX_ISOLATED_ENV_VALUE_BYTES,
    ExecutionError,
    SandboxUnavailable,
    SecureCodeExecutor,
)
from qwed_new.core.symbolic_verifier import (
    CONSTRAINT_INPUT_TOO_LARGE,
    CONSTRAINT_RUNTIME_UNAVAILABLE,
    CROSSHAIR_IMAGE_ENV,
    DEFAULT_CROSSHAIR_IMAGE,
    SymbolicVerifier,
    _CONTAINER_STARTUP_SECONDS,
    _CROSSHAIR_CHILD,
    _CROSSHAIR_CRASH_EXIT,
    _CROSSHAIR_MISSING_EXIT,
    _CROSSHAIR_RUNNER,
    _CROSSHAIR_UNPROTECTED_EXIT,
    _NONCE_ENV,
    _RESULT_MARKER,
    _SOURCE_ENV,
    _reported_code,
)

TYPED = "def add(x: int, y: int) -> int:\n    return x + y\n"
DIV = 'def div(a: int, b: int) -> float:\n    """\n    post: True\n    """\n    return a / b\n'


class _Sandbox:
    """Stands in for run_isolated. Like the real runner, it writes the result
    line for this run's nonce to stdout unless ``marker`` is False."""

    def __init__(self, available=True, returncode=0, output="", error=None, marker=True):
        self.available, self.returncode, self.output, self.error = available, returncode, output, error
        self.marker = marker
        self.calls = []

    def is_available(self):
        return self.available

    def run_isolated(self, command, **kwargs):
        self.calls.append({"command": command, **kwargs})
        if self.error is not None:
            raise self.error
        stdout = ""
        if self.marker:
            nonce = kwargs["environment"][_NONCE_ENV]
            stdout = f"{_RESULT_MARKER} {nonce} {self.returncode}\n"
        return self.returncode, stdout, self.output


def _marker_code(marker):
    # Top-level code that would leave a file behind if it ever ran on the host.
    return f"open({str(marker)!r}, 'w').write('ran')\n\n" + TYPED


def _no_host_subprocess(*args, **kwargs):
    raise AssertionError("CrossHair must never run as a host subprocess")


# ---------------------------------------------------------------------------
# The supplied code never runs on the host
# ---------------------------------------------------------------------------

def test_code_is_not_executed_on_the_host(tmp_path):
    marker = tmp_path / "imported_on_host"
    sandbox = _Sandbox(returncode=0)
    verifier = SymbolicVerifier(timeout_seconds=5, sandbox=sandbox)

    with patch.object(subprocess, "run", _no_host_subprocess):
        result = verifier.verify_code(_marker_code(marker))

    assert not marker.exists()
    # The code went to the sandbox, untouched, in its environment.
    environment = sandbox.calls[0]["environment"]
    assert environment[_SOURCE_ENV] == _marker_code(marker)
    assert re.fullmatch(r"[0-9a-f]{32}", environment[_NONCE_ENV])
    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields["constraint_id"] == "symbolic_verifier.no_counterexample_found"


def test_without_docker_the_result_is_blocked_and_nothing_runs(tmp_path):
    marker = tmp_path / "imported_on_host"
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    executor.client = None  # no Docker daemon
    verifier = SymbolicVerifier(timeout_seconds=5, sandbox=executor)

    with patch.object(subprocess, "run", _no_host_subprocess):
        result = verifier.verify_code(_marker_code(marker))

    assert not marker.exists()
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.developer_fields["constraint_id"] == CONSTRAINT_RUNTIME_UNAVAILABLE


@pytest.mark.parametrize(
    "sandbox",
    [
        _Sandbox(available=False),
        _Sandbox(error=SandboxUnavailable("Sandbox capacity reached — retry shortly.")),
        _Sandbox(error=SandboxUnavailable("Sandbox image 'x' is not available on the Docker daemon")),
        # Image without CrossHair: the runner exits before any result line.
        _Sandbox(returncode=_CROSSHAIR_MISSING_EXIT, marker=False),
    ],
    ids=["no-docker", "no-slot", "no-image", "no-crosshair-in-image"],
)
def test_sandbox_failures_are_blocked_not_unverifiable(sandbox):
    result = SymbolicVerifier(timeout_seconds=5, sandbox=sandbox).verify_code(TYPED)

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.is_verified is False
    assert result.proof_ref is None
    assert result.developer_fields["constraint_id"] == CONSTRAINT_RUNTIME_UNAVAILABLE
    assert result.developer_fields["reason"]


def test_a_sandbox_failure_on_a_later_function_blocks_the_whole_request():
    sandbox = _Sandbox(returncode=0)
    calls = iter([None, SandboxUnavailable("Sandbox capacity reached — retry shortly.")])

    def run_isolated(command, **kwargs):
        outcome = next(calls)
        if isinstance(outcome, Exception):
            raise outcome
        return 0, f"{_RESULT_MARKER} {kwargs['environment'][_NONCE_ENV]} 0\n", ""

    sandbox.run_isolated = run_isolated
    code = TYPED + "\n\ndef sub(x: int, y: int) -> int:\n    return x - y\n"
    result = SymbolicVerifier(timeout_seconds=5, sandbox=sandbox).verify_code(code)

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == CONSTRAINT_RUNTIME_UNAVAILABLE


def test_syntax_errors_are_reported_without_the_sandbox():
    sandbox = _Sandbox(available=False)
    result = SymbolicVerifier(sandbox=sandbox).verify_code("def broken(\n")

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == "symbolic_verifier.syntax_error"


def test_code_too_large_for_the_sandbox_is_blocked_before_any_run():
    sandbox = _Sandbox(returncode=0)
    code = TYPED + "# " + "x" * MAX_ISOLATED_ENV_VALUE_BYTES + "\n"
    result = SymbolicVerifier(sandbox=sandbox).verify_code(code)

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == CONSTRAINT_INPUT_TOO_LARGE
    assert sandbox.calls == []


# ---------------------------------------------------------------------------
# What the verifier asks the sandbox to run
# ---------------------------------------------------------------------------

def test_crosshair_command_names_the_function_by_qualname():
    sandbox = _Sandbox(returncode=0)
    SymbolicVerifier(timeout_seconds=7, sandbox=sandbox, image="img:1").verify_code(TYPED)

    (call,) = sandbox.calls
    assert call["command"] == ["python", "-c", _CROSSHAIR_RUNNER, "add", "7"]
    assert call["image"] == "img:1"
    assert call["timeout"] == 7 * 2 + _CONTAINER_STARTUP_SECONDS
    assert call["environment"][_SOURCE_ENV] == TYPED
    assert set(call["environment"]) == {_SOURCE_ENV, _NONCE_ENV}
    assert call["max_output_bytes"] > 0


def test_runner_uses_the_exit_code_constants():
    assert f"sys.exit({_CROSSHAIR_MISSING_EXIT})" in _CROSSHAIR_RUNNER
    assert f"sys.exit({_CROSSHAIR_UNPROTECTED_EXIT})" in _CROSSHAIR_RUNNER
    assert f"code = {_CROSSHAIR_CRASH_EXIT}" in _CROSSHAIR_CHILD
    codes = {0, 1, 2, _CROSSHAIR_UNPROTECTED_EXIT, _CROSSHAIR_MISSING_EXIT, _CROSSHAIR_CRASH_EXIT}
    assert len(codes) == 6


def test_runner_keeps_the_nonce_and_result_line_out_of_the_child():
    # The child gets neither secret, and cannot write the runner's stdout.
    assert "stdout=2" in _CROSSHAIR_RUNNER
    assert "env=dict(os.environ)" in _CROSSHAIR_RUNNER
    assert _RESULT_MARKER not in _CROSSHAIR_CHILD
    assert _NONCE_ENV not in _CROSSHAIR_CHILD
    assert _SOURCE_ENV not in _CROSSHAIR_CHILD
    pop_nonce = _CROSSHAIR_RUNNER.index(f'os.environ.pop("{_NONCE_ENV}"')
    pop_source = _CROSSHAIR_RUNNER.index(f'os.environ.pop("{_SOURCE_ENV}"')
    spawn = _CROSSHAIR_RUNNER.index("subprocess.run(")
    assert pop_nonce < spawn
    assert pop_source < spawn
    # The parent is made non-dumpable before the child exists.
    assert _CROSSHAIR_RUNNER.index("prctl(") < spawn


def test_image_comes_from_the_environment_or_the_default(monkeypatch):
    monkeypatch.delenv(CROSSHAIR_IMAGE_ENV, raising=False)
    assert SymbolicVerifier().image == DEFAULT_CROSSHAIR_IMAGE

    monkeypatch.setenv(CROSSHAIR_IMAGE_ENV, "registry.local/crosshair:7")
    assert SymbolicVerifier().image == "registry.local/crosshair:7"
    assert SymbolicVerifier(image="explicit:1").image == "explicit:1"


def test_methods_get_a_class_qualname_and_nested_functions_none():
    code = (
        "class Account:\n"
        "    def deposit(self, amount: int) -> int:\n"
        "        def helper(x: int) -> int:\n"
        "            return x\n"
        "        return helper(amount)\n"
        "\n"
        "def top(x: int) -> int:\n"
        "    return x\n"
    )
    functions = SymbolicVerifier()._extract_functions(ast.parse(code))

    assert {f["name"]: f["qualname"] for f in functions} == {
        "deposit": "Account.deposit",
        "helper": None,
        "top": "top",
    }


def test_nested_function_is_unverifiable_without_a_sandbox_call():
    sandbox = _Sandbox(returncode=0)
    verifier = SymbolicVerifier(sandbox=sandbox)
    result = verifier._verify_function("", {"name": "helper", "qualname": None, "has_types": True})

    assert result["verified"] is False
    assert result["unverifiable"] is True
    assert result["issues"][0]["type"] == "unverifiable"
    assert sandbox.calls == []


linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the runner needs prctl(PR_SET_DUMPABLE), which is Linux-only",
)


def _run_real_runner(tmp_path, func, source):
    """The real runner on the host, only against harmless fixtures. Returns
    (exit code, the code its result line reported for this nonce, stdout,
    stderr)."""
    pytest.importorskip("crosshair")
    run = subprocess.run(
        [sys.executable, "-c", _CROSSHAIR_RUNNER, func, "5"],
        capture_output=True, text=True, timeout=180, cwd=tmp_path,
        env={**os.environ, _SOURCE_ENV: source, _NONCE_ENV: "n0nce"},
    )
    return run.returncode, _reported_code(run.stdout, "n0nce"), run.stdout, run.stderr


@linux_only
def test_runner_reports_a_counterexample(tmp_path):
    code, reported, stdout, stderr = _run_real_runner(tmp_path, "div", DIV)

    assert code == 1
    assert reported == 1
    assert "div(0, 0)" in stderr
    # Only the parent writes to stdout: one result line.
    assert stdout == f"{_RESULT_MARKER} n0nce 1\n"


@linux_only
def test_runner_keeps_crashes_apart_from_counterexamples(tmp_path):
    code, reported, _, _ = _run_real_runner(tmp_path, "missing", DIV)

    assert code == _CROSSHAIR_CRASH_EXIT
    assert reported == _CROSSHAIR_CRASH_EXIT


@linux_only
def test_runner_reports_a_target_sys_exit_as_an_engine_error(tmp_path):
    # CrossHair lets a SystemExit raised while importing the target escape;
    # it must not pass for CrossHair's own clean exit.
    code, reported, _, _ = _run_real_runner(tmp_path, "div", "import sys\nsys.exit(0)\n" + DIV)

    assert code == _CROSSHAIR_CRASH_EXIT
    assert reported == _CROSSHAIR_CRASH_EXIT


@linux_only
@pytest.mark.skipif(
    sys.platform.startswith("linux") and os.geteuid() == 0,
    reason="root bypasses the non-dumpable protection; the sandbox runs the runner as user 65534",
)
def test_target_cannot_read_the_nonce_or_write_the_result_line(tmp_path):
    # The analysed code runs in the child: the nonce is not in its
    # environment, the non-dumpable parent's /proc entries are closed to it,
    # and its stdout is the container's stderr. (CrossHair's own audit wall
    # also refuses some of these opens while the code is imported; either
    # refusal is fine, so the probe catches everything.)
    probe = (
        "import os\n"
        "seen = []\n"
        "for path in ('/proc/self/environ', f'/proc/{os.getppid()}/environ'):\n"
        "    try:\n"
        "        seen.append(open(path, 'rb').read())\n"
        "    except BaseException:\n"
        "        pass\n"
        "print('LEAKED' if any(b'n0nce' in data for data in seen) else 'SEALED')\n"
        "print('QWED_CROSSHAIR_RESULT n0nce 0', flush=True)\n"
        "try:\n"
        "    with open(f'/proc/{os.getppid()}/fd/1', 'w') as out:\n"
        "        out.write('QWED_CROSSHAIR_RESULT n0nce 0\\n')\n"
        "except BaseException:\n"
        "    pass\n"
    )
    code, reported, stdout, stderr = _run_real_runner(tmp_path, "div", probe + DIV)

    assert "SEALED" in stderr
    assert "LEAKED" not in stderr
    assert stdout == f"{_RESULT_MARKER} n0nce 1\n"
    assert code == 1
    assert reported == 1


@linux_only
def test_a_target_os_exit_controls_only_the_child_exit_code(tmp_path):
    # The analysed code can still end the child with any code; the runner
    # reports that code faithfully, and exit 0 is never more than
    # "no counterexample found" (UNVERIFIABLE).
    code, reported, stdout, _ = _run_real_runner(tmp_path, "div", "import os\nos._exit(0)\n" + DIV)

    assert code == 0
    assert reported == 0
    assert stdout == f"{_RESULT_MARKER} n0nce 0\n"


@linux_only
def test_an_early_os_exit_1_is_not_a_counterexample(tmp_path):
    # The child ends before CrossHair checks anything; its exit 1 comes with
    # no CrossHair report, so the verifier treats it as an engine error.
    code, reported, stdout, stderr = _run_real_runner(tmp_path, "div", "import os\nos._exit(1)\n" + DIV)

    assert code == 1
    assert reported == 1

    class _Replay(_Sandbox):
        def run_isolated(self, command, **kwargs):
            nonce = kwargs["environment"][_NONCE_ENV]
            return code, stdout.replace("n0nce", nonce), stderr

    issues = SymbolicVerifier(sandbox=_Replay())._run_crosshair_check(DIV, "div")
    assert [issue["type"] for issue in issues] == ["error"]


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="checks the non-Linux refusal")
def test_runner_refuses_without_prctl(tmp_path):
    code, reported, stdout, _ = _run_real_runner(tmp_path, "div", DIV)

    assert code == _CROSSHAIR_UNPROTECTED_EXIT
    assert reported is None
    assert stdout == ""


@pytest.mark.parametrize(
    "stdout, expected",
    [
        (f"{_RESULT_MARKER} n0nce 1\n", 1),
        (f"{_RESULT_MARKER} n0nce 0", 0),
        (f"\n{_RESULT_MARKER} n0nce 0\n\n", 0),
        (f"{_RESULT_MARKER} n0nce -1\n", -1),
        (f"{_RESULT_MARKER} other 0\n", None),
        (f"{_RESULT_MARKER} n0nce zero\n", None),
        (f"{_RESULT_MARKER} n0nce --1\n", None),
        (f"{_RESULT_MARKER} n0nce 0\nlater\n", None),
        (f"{_RESULT_MARKER}  n0nce\n", None),
        ("", None),
    ],
)
def test_reported_code(stdout, expected):
    assert _reported_code(stdout, "n0nce") == expected


@pytest.mark.parametrize(
    "output",
    ["", "error: something", "a counterexample was found", "Traceback (most recent call last):"],
)
def test_exit_1_without_a_crosshair_report_is_an_engine_error(output):
    issues = SymbolicVerifier(sandbox=_Sandbox(returncode=1, output=output))._run_crosshair_check(TYPED, "add")

    assert [issue["type"] for issue in issues] == ["error"]


def test_a_child_exit_97_is_an_engine_error_not_a_missing_crosshair():
    # The runner's own 97 (no CrossHair in the image) never has a result line;
    # with one, 97 is the child's exit code, chosen by the analysed code.
    sandbox = _Sandbox(returncode=_CROSSHAIR_MISSING_EXIT, marker=True)
    result = SymbolicVerifier(sandbox=sandbox).verify_code(TYPED)

    # An engine error for the function, as for exit 2, not a missing runtime.
    assert result.developer_fields["constraint_id"] == "symbolic_verifier.verification_error"
    assert result.developer_fields["issues"][0]["type"] == "error"
    assert "97" in result.developer_fields["issues"][0]["description"]


def test_exit_1_with_crosshair_reports_lists_each_counterexample():
    output = (
        "/workspace/target.py:5: error: ZeroDivisionError:  when calling div(0, 0)\n"
        "noise\n"
        "/workspace/target.py:9: error: false when calling g(-1)\n"
    )
    issues = SymbolicVerifier(sandbox=_Sandbox(returncode=1, output=output))._run_crosshair_check(TYPED, "add")

    assert [issue["type"] for issue in issues] == ["counterexample", "counterexample"]
    assert "div(0, 0)" in issues[0]["description"]
    assert "g(-1)" in issues[1]["description"]


def test_reported_code_needs_a_nonce():
    assert _reported_code(f"{_RESULT_MARKER}  0\n", "") is None


@pytest.mark.parametrize(
    "sandbox",
    [
        _Sandbox(returncode=1, marker=False),  # e.g. os._exit(1) in the target
        _Sandbox(returncode=0, marker=False),
    ],
    ids=["exit-1-without-marker", "exit-0-without-marker"],
)
def test_an_unreported_outcome_is_an_engine_error(sandbox):
    issues = SymbolicVerifier(timeout_seconds=5, sandbox=sandbox)._run_crosshair_check(TYPED, "add")

    assert [issue["type"] for issue in issues] == ["error"]
    assert "did not report a result" in issues[0]["description"]


def test_a_marker_that_disagrees_with_the_exit_code_is_an_engine_error():
    class _Mismatch(_Sandbox):
        def run_isolated(self, command, **kwargs):
            nonce = kwargs["environment"][_NONCE_ENV]
            return 1, f"{_RESULT_MARKER} {nonce} 0\n", ""

    issues = SymbolicVerifier(sandbox=_Mismatch())._run_crosshair_check(TYPED, "add")

    assert [issue["type"] for issue in issues] == ["error"]


def test_symbolic_verifier_imports_without_the_docker_package():
    # docker is an optional dependency; without it the engine is BLOCKED, it
    # does not fail to import.
    script = (
        "import sys; sys.modules['docker'] = None\n"
        "from qwed_new.core.symbolic_verifier import SymbolicVerifier\n"
        "r = SymbolicVerifier().verify_code('def f(x: int) -> int:\\n    return x\\n')\n"
        "print(r.status.value, r.developer_fields['constraint_id'])\n"
    )
    run = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)

    assert run.returncode == 0, run.stderr
    assert run.stdout.split() == ["BLOCKED", CONSTRAINT_RUNTIME_UNAVAILABLE]


# ---------------------------------------------------------------------------
# SecureCodeExecutor.run_isolated
# ---------------------------------------------------------------------------

def _executor(logs=(), status=0, wait_error=None, stdout_logs=()):
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    executor.client = MagicMock()
    executor.docker_available = True
    executor.cpu_limit, executor.memory_limit, executor.pids_limit = 0.5, "512m", 128
    executor.execution_count = 0
    container = MagicMock()
    container.logs.side_effect = lambda **kwargs: iter(list(stdout_logs if kwargs["stdout"] else logs))
    if wait_error is not None:
        container.wait.side_effect = wait_error
    else:
        container.wait.return_value = {"StatusCode": status}
    executor.client.containers.create.return_value = container
    return executor, container


def test_run_isolated_hardens_the_container():
    executor, container = _executor(logs=[b"o", b"k"], stdout_logs=[b"out"], status=1)

    code, stdout, stderr = executor.run_isolated(
        ["python", "-c", "print(1)"], image="img:1", timeout=5, environment={"QWED_X": "payload"}
    )

    assert code == 1
    assert stdout == "out"
    assert stderr == "ok"
    kwargs = executor.client.containers.create.call_args.kwargs
    assert kwargs["image"] == "img:1"
    assert kwargs["network_mode"] == "none"
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["user"] == "65534:65534"
    assert kwargs["pids_limit"] == 128
    assert kwargs["mem_limit"] == "512m"
    # Nothing on the host is mounted; the only writable path is a private
    # tmpfs owned by the container user.
    assert "volumes" not in kwargs
    assert kwargs["working_dir"] == "/workspace"
    scratch = kwargs["tmpfs"]["/workspace"]
    assert "uid=65534" in scratch
    assert "mode=0700" in scratch
    assert "noexec" in scratch
    assert kwargs["environment"]["QWED_X"] == "payload"
    assert kwargs["environment"]["HOME"] == "/workspace"
    container.remove.assert_called_once_with(force=True)
    # The image is never pulled.
    executor.client.images.pull.assert_not_called()


def test_run_isolated_writes_nothing_on_the_host(tmp_path, monkeypatch):
    import tempfile

    scratch = tmp_path / "host_temp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    executor, _ = _executor()

    executor.run_isolated(["true"], image="i", timeout=5, environment={"QWED_X": "payload"})

    assert list(scratch.iterdir()) == []


def test_run_isolated_rejects_an_oversized_input():
    executor, _ = _executor()

    with pytest.raises(ValueError):
        executor.run_isolated(
            ["true"], image="i", timeout=5, environment={"QWED_X": "x" * (MAX_ISOLATED_ENV_VALUE_BYTES + 1)}
        )

    executor.client.containers.create.assert_not_called()


def test_run_isolated_caps_the_output():
    pulled = []

    def chunks():
        for _ in range(1000):
            pulled.append(1)
            yield b"A" * 40

    executor, container = _executor()
    container.logs.side_effect = lambda **kwargs: chunks() if kwargs["stderr"] else iter([b"done"])

    _, stdout, stderr = executor.run_isolated(["true"], image="i", timeout=5, max_output_bytes=100)

    assert stderr == "A" * 100 + "\n[output truncated]"
    # stdout is read on its own, so a flood on stderr cannot push it out.
    assert stdout == "done"
    # The log is streamed and reading stops at the cap.
    assert container.logs.call_args.kwargs["stream"] is True
    assert len(pulled) == 3


def test_run_isolated_output_at_exactly_the_cap_is_not_truncated():
    executor, _ = _executor(logs=[b"A" * 50, b"B" * 50])

    _, _, stderr = executor.run_isolated(["true"], image="i", timeout=5, max_output_bytes=100)

    assert stderr == "A" * 50 + "B" * 50


def test_run_isolated_unknown_wait_result_is_not_a_success():
    executor, container = _executor()
    container.wait.return_value = None

    code, _, _ = executor.run_isolated(["true"], image="i", timeout=5)

    assert code == -1


def test_run_isolated_timeout_kills_and_removes():
    executor, container = _executor(wait_error=requests.exceptions.ReadTimeout("read timed out"))

    with pytest.raises(ExecutionError):
        executor.run_isolated(["sleep", "99"], image="i", timeout=1)

    container.kill.assert_called_once()
    container.remove.assert_called_once_with(force=True)


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ReadTimeout("read timed out"),
        requests.exceptions.ConnectionError(
            urllib3.exceptions.ReadTimeoutError(None, None, "Read timed out.")
        ),
        requests.exceptions.ConnectionError(
            urllib3.exceptions.MaxRetryError(
                None, "/wait", urllib3.exceptions.ReadTimeoutError(None, None, "Read timed out.")
            )
        ),
        requests.exceptions.ConnectionError("UnixHTTPConnectionPool(host='localhost'): Read timed out."),
    ],
    ids=["read-timeout", "unix-socket-read-timeout", "retry-read-timeout", "untyped-read-timeout"],
)
def test_run_isolated_wait_timeouts_are_timeouts(error):
    executor, container = _executor(wait_error=error)

    with pytest.raises(ExecutionError):
        executor.run_isolated(["sleep", "99"], image="i", timeout=1)

    container.remove.assert_called_once_with(force=True)


@pytest.mark.parametrize(
    "error",
    [
        docker.errors.APIError("500 Server Error"),
        requests.exceptions.ConnectionError("Connection aborted: daemon went away"),
    ],
    ids=["daemon-api-error", "daemon-connection-lost"],
)
def test_run_isolated_wait_daemon_errors_are_not_timeouts(error):
    executor, container = _executor(wait_error=error)
    container.kill.side_effect = docker.errors.APIError("kill failed")

    with pytest.raises(SandboxUnavailable):
        executor.run_isolated(["sleep", "99"], image="i", timeout=1)

    container.remove.assert_called_once_with(force=True)


def test_run_isolated_missing_image_is_unavailable_and_not_pulled():
    executor, _ = _executor()
    executor.client.containers.create.side_effect = docker.errors.ImageNotFound("no such image")

    with pytest.raises(SandboxUnavailable, match="not available"):
        executor.run_isolated(["true"], image="missing:1", timeout=5)

    executor.client.images.pull.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        docker.errors.APIError("500 Server Error"),
        requests.exceptions.ConnectionError("daemon socket dropped"),
    ],
    ids=["api-error", "connection-dropped"],
)
def test_run_isolated_daemon_failures_are_unavailable(error):
    executor, _ = _executor()
    executor.client.containers.create.side_effect = error

    with pytest.raises(SandboxUnavailable, match="Sandbox runtime error"):
        executor.run_isolated(["true"], image="i", timeout=5)


def test_dropped_daemon_connection_blocks_symbolic_verification():
    executor, _ = _executor()
    executor.client.containers.create.side_effect = requests.exceptions.ConnectionError("dropped")

    result = SymbolicVerifier(timeout_seconds=5, sandbox=executor).verify_code(TYPED)

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == CONSTRAINT_RUNTIME_UNAVAILABLE


def test_run_isolated_without_docker_is_unavailable():
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    executor.client = None

    with pytest.raises(SandboxUnavailable):
        executor.run_isolated(["true"], image="i", timeout=5)


def test_run_isolated_without_a_slot_is_unavailable(monkeypatch):
    executor, _ = _executor()
    slots = MagicMock()
    slots.acquire.return_value = False
    monkeypatch.setattr(sce, "_sandbox_slots", slots)

    with pytest.raises(SandboxUnavailable, match="capacity"):
        executor.run_isolated(["true"], image="i", timeout=5)

    executor.client.containers.create.assert_not_called()
    slots.release.assert_not_called()


def test_run_isolated_releases_its_slot(monkeypatch):
    executor, _ = _executor()
    slots = MagicMock()
    slots.acquire.return_value = True
    monkeypatch.setattr(sce, "_sandbox_slots", slots)

    executor.run_isolated(["true"], image="i", timeout=5)

    slots.release.assert_called_once()


# ---------------------------------------------------------------------------
# End to end, in the real sandbox
# ---------------------------------------------------------------------------

def _crosshair_image_ready():
    try:
        executor = SecureCodeExecutor()
        if not executor.is_available():
            return False
        executor.client.images.get(SymbolicVerifier().image)
        return True
    except Exception:
        return False


def test_end_to_end_in_the_real_sandbox(tmp_path):
    if not _crosshair_image_ready():
        if os.environ.get("QWED_REQUIRE_CROSSHAIR_SANDBOX"):
            pytest.fail("Docker and the CrossHair sandbox image are required here")
        pytest.skip("Docker or the CrossHair sandbox image is not available")
    verifier = SymbolicVerifier(timeout_seconds=10)

    # Code with a host side effect: it runs only in the container, where the
    # host path does not exist, so nothing appears on the host.
    marker = tmp_path / "imported_on_host"
    side_effect = verifier.verify_code(_marker_code(marker))
    assert not marker.exists()
    assert side_effect.status is not DiagnosticStatus.VERIFIED

    divide = verifier.verify_code(DIV)
    assert divide.developer_fields["constraint_id"] == "symbolic_verifier.counterexample_found"
    assert "div(0, 0)" in str(divide.developer_fields["issues"])

    clean = verifier.verify_code(
        'def inc(a: int) -> int:\n    """\n    post: __return__ == a + 1\n    """\n    return a + 1\n'
    )
    assert clean.developer_fields["constraint_id"] == "symbolic_verifier.no_counterexample_found"


def test_run_isolated_holds_its_slot_when_the_container_is_not_removed(monkeypatch):
    executor, container = _executor()
    container.remove.side_effect = docker.errors.APIError("remove failed")
    monkeypatch.setattr(sce.time, "sleep", lambda seconds: None)
    slots = MagicMock()
    slots.acquire.return_value = True
    monkeypatch.setattr(sce, "_sandbox_slots", slots)

    executor.run_isolated(["true"], image="i", timeout=5)

    # A container that may still run keeps consuming resources (#446).
    slots.release.assert_not_called()


def test_a_sandbox_whose_availability_check_raises_is_unavailable():
    class _Broken(_Sandbox):
        def is_available(self):
            raise RuntimeError("daemon probe exploded")

    result = SymbolicVerifier(sandbox=_Broken()).verify_code(TYPED)

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == CONSTRAINT_RUNTIME_UNAVAILABLE


def test_an_unexpected_sandbox_error_is_an_engine_error_for_that_function():
    sandbox = _Sandbox(error=RuntimeError("unexpected"))
    result = SymbolicVerifier(sandbox=sandbox).verify_code(TYPED)

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields["constraint_id"] == "symbolic_verifier.incomplete_coverage"
    assert result.developer_fields["issues"][0]["type"] == "error"
