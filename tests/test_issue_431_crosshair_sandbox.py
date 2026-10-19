"""#431: CrossHair imports, and so executes, the code it analyses.

SymbolicVerifier used to run ``python -m crosshair check`` as a plain host
subprocess on a temp file holding the caller's code. Every CrossHair run now
goes through SecureCodeExecutor.run_isolated (no network, read-only root and
input, no capabilities, unprivileged user, resource limits). When the sandbox
cannot run it, the result is BLOCKED and the code is never imported on the
host.
"""

import ast
import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import docker
import pytest

from qwed_new.core import secure_code_executor as sce
from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.secure_code_executor import (
    ExecutionError,
    SandboxUnavailable,
    SecureCodeExecutor,
)
from qwed_new.core.symbolic_verifier import (
    CONSTRAINT_RUNTIME_UNAVAILABLE,
    CROSSHAIR_IMAGE_ENV,
    DEFAULT_CROSSHAIR_IMAGE,
    SymbolicVerifier,
    _CROSSHAIR_RUNNER,
)

TYPED = "def add(x: int, y: int) -> int:\n    return x + y\n"


class _Sandbox:
    def __init__(self, available=True, returncode=0, output="", error=None):
        self.available, self.returncode, self.output, self.error = available, returncode, output, error
        self.calls = []

    def is_available(self):
        return self.available

    def run_isolated(self, files, command, **kwargs):
        self.calls.append({"files": files, "command": command, **kwargs})
        if self.error is not None:
            raise self.error
        return self.returncode, self.output


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
    # The code went to the sandbox as a read-only input, untouched.
    assert sandbox.calls[0]["files"] == {"target.py": _marker_code(marker)}
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
        _Sandbox(returncode=97),  # image without CrossHair
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
    calls = iter([(0, ""), SandboxUnavailable("Sandbox capacity reached — retry shortly.")])

    def run_isolated(files, command, **kwargs):
        outcome = next(calls)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

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


# ---------------------------------------------------------------------------
# What the verifier asks the sandbox to run
# ---------------------------------------------------------------------------

def test_crosshair_command_names_the_function_by_qualname():
    sandbox = _Sandbox(returncode=0)
    SymbolicVerifier(timeout_seconds=7, sandbox=sandbox, image="img:1").verify_code(TYPED)

    (call,) = sandbox.calls
    assert call["command"] == ["python", "-c", _CROSSHAIR_RUNNER, "add", "7"]
    assert call["image"] == "img:1"
    assert call["timeout"] == 14
    assert call["max_output_bytes"] > 0


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


def test_runner_keeps_crashes_apart_from_counterexamples(tmp_path):
    """The real runner, run on the host only against a harmless fixture: an
    unknown function is exit 98 (engine error), never 1 (counterexample)."""
    pytest.importorskip("crosshair")
    (tmp_path / "target.py").write_text(
        'def div(a: int, b: int) -> float:\n    """\n    post: True\n    """\n    return a / b\n',
        encoding="utf-8",
    )

    def run(func):
        return subprocess.run(
            [sys.executable, "-c", _CROSSHAIR_RUNNER, func, "5"],
            capture_output=True, text=True, timeout=180, cwd=tmp_path,
        )

    assert run("missing").returncode == 98
    counterexample = run("div")
    assert counterexample.returncode == 1
    assert "div(0, 0)" in counterexample.stdout + counterexample.stderr


# ---------------------------------------------------------------------------
# SecureCodeExecutor.run_isolated
# ---------------------------------------------------------------------------

def _executor(logs=b"", status=0, wait_error=None):
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    executor.client = MagicMock()
    executor.docker_available = True
    executor.cpu_limit, executor.memory_limit, executor.pids_limit = 0.5, "512m", 128
    executor.execution_count = 0
    container = MagicMock()
    container.logs.return_value = logs
    if wait_error is not None:
        container.wait.side_effect = wait_error
    else:
        container.wait.return_value = {"StatusCode": status}
    executor.client.containers.create.return_value = container
    return executor, container


def test_run_isolated_hardens_the_container():
    executor, container = _executor(logs=b"ok", status=1)

    seen = {}

    def create(**kwargs):
        mount = next(iter(kwargs["volumes"]))
        seen["files"] = sorted(os.listdir(mount))
        seen["mode"] = oct(os.stat(mount).st_mode & 0o777)
        return container

    executor.client.containers.create.side_effect = create
    code, output = executor.run_isolated(
        {"target.py": "x = 1\n"}, ["python", "-c", "print(1)"], image="img:1", timeout=5
    )

    assert (code, output) == (1, "ok")
    kwargs = executor.client.containers.create.call_args.kwargs
    assert kwargs["image"] == "img:1"
    assert kwargs["network_mode"] == "none"
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["user"] == "65534:65534"
    assert kwargs["pids_limit"] == 128
    assert kwargs["mem_limit"] == "512m"
    (mount,) = kwargs["volumes"].values()
    assert mount == {"bind": "/workspace", "mode": "ro"}
    assert seen["files"] == ["target.py"]
    container.remove.assert_called_once_with(force=True)
    # The image is never pulled.
    executor.client.images.pull.assert_not_called()


def test_run_isolated_caps_the_output():
    executor, _ = _executor(logs=b"A" * 5000)

    _, output = executor.run_isolated({"t.py": ""}, ["true"], image="i", timeout=5, max_output_bytes=100)

    assert output.startswith("A" * 100)
    assert output.endswith("[output truncated]")
    assert len(output) < 200


def test_run_isolated_timeout_kills_and_removes():
    executor, container = _executor(wait_error=Exception("read timed out"))

    with pytest.raises(ExecutionError):
        executor.run_isolated({"t.py": ""}, ["sleep", "99"], image="i", timeout=1)

    container.kill.assert_called_once()
    container.remove.assert_called_once_with(force=True)


def test_run_isolated_missing_image_is_unavailable_and_not_pulled():
    executor, _ = _executor()
    executor.client.containers.create.side_effect = docker.errors.ImageNotFound("no such image")

    with pytest.raises(SandboxUnavailable, match="not available"):
        executor.run_isolated({"t.py": ""}, ["true"], image="missing:1", timeout=5)

    executor.client.images.pull.assert_not_called()


def test_run_isolated_without_docker_is_unavailable():
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    executor.client = None

    with pytest.raises(SandboxUnavailable):
        executor.run_isolated({"t.py": ""}, ["true"], image="i", timeout=5)


def test_run_isolated_without_a_slot_is_unavailable(monkeypatch):
    executor, _ = _executor()
    slots = MagicMock()
    slots.acquire.return_value = False
    monkeypatch.setattr(sce, "_sandbox_slots", slots)

    with pytest.raises(SandboxUnavailable, match="capacity"):
        executor.run_isolated({"t.py": ""}, ["true"], image="i", timeout=5)

    executor.client.containers.create.assert_not_called()
    slots.release.assert_not_called()


def test_run_isolated_releases_its_slot(monkeypatch):
    executor, _ = _executor()
    slots = MagicMock()
    slots.acquire.return_value = True
    monkeypatch.setattr(sce, "_sandbox_slots", slots)

    executor.run_isolated({"t.py": ""}, ["true"], image="i", timeout=5)

    slots.release.assert_called_once()


@pytest.mark.parametrize("name", ["../t.py", "a/t.py", "a\\t.py", "", ".."])
def test_run_isolated_accepts_only_plain_file_names(name):
    executor, _ = _executor()

    with pytest.raises(ValueError):
        executor.run_isolated({name: ""}, ["true"], image="i", timeout=5)

    executor.client.containers.create.assert_not_called()


# ---------------------------------------------------------------------------
# End to end, only where the sandbox image exists
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


@pytest.mark.skipif(not _crosshair_image_ready(), reason="Docker or the CrossHair sandbox image is not available")
def test_end_to_end_in_the_real_sandbox(tmp_path):
    verifier = SymbolicVerifier(timeout_seconds=10)

    # Code with a host side effect: it runs only in the container, where the
    # host path does not exist, so nothing appears on the host.
    marker = tmp_path / "imported_on_host"
    side_effect = verifier.verify_code(_marker_code(marker))
    assert not marker.exists()
    assert side_effect.status is not DiagnosticStatus.VERIFIED

    divide = verifier.verify_code(
        'def div(a: int, b: int) -> float:\n    """\n    post: True\n    """\n    return a / b\n'
    )
    assert divide.developer_fields["constraint_id"] == "symbolic_verifier.counterexample_found"
    assert "div(0, 0)" in str(divide.developer_fields["issues"])
