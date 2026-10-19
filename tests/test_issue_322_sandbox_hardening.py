"""#322: the execute() sandbox ran a floating image tag with no filesystem or
capability hardening.

The image is now pinned by digest, and the container runs with a read-only
root, no Linux capabilities, no privilege escalation and never as root, in
addition to the existing network, memory, CPU and PID limits.
"""

import os
from unittest.mock import MagicMock

import pytest

from qwed_new.core import secure_code_executor as sce
from qwed_new.core.secure_code_executor import (
    SANDBOX_IMAGE,
    SANDBOX_IMAGE_ENV,
    SecureCodeExecutor,
)

DIGEST = "sha256:" + "a" * 64


def _executor():
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    executor.client = MagicMock()
    executor.docker_available = True
    executor.cpu_limit, executor.memory_limit, executor.pids_limit = 0.5, "512m", 128
    executor.timeout = 10
    executor.max_result_bytes = 2 * 1024 * 1024
    executor.execution_count = 0
    executor.image = SANDBOX_IMAGE
    executor._rootless = None
    executor.client.info.return_value = {"SecurityOptions": ["name=seccomp,profile=builtin"]}
    executor.client.containers.create.return_value = MagicMock()
    return executor


def _as_host_user(monkeypatch, uid, gid=1000):
    monkeypatch.setattr(sce.os, "getuid", lambda: uid, raising=False)
    monkeypatch.setattr(sce.os, "getgid", lambda: gid, raising=False)


# ---------------------------------------------------------------------------
# The image is pinned
# ---------------------------------------------------------------------------

def test_default_image_is_pinned_by_digest():
    name, digest = SANDBOX_IMAGE.split("@")
    assert name == "amancevice/pandas"
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


def test_executor_uses_the_pinned_image(monkeypatch):
    monkeypatch.delenv(SANDBOX_IMAGE_ENV, raising=False)

    assert SecureCodeExecutor().image == SANDBOX_IMAGE


def test_an_override_by_digest_is_used(monkeypatch):
    monkeypatch.setenv(SANDBOX_IMAGE_ENV, f"registry.local/pandas@{DIGEST}")

    assert SecureCodeExecutor().image == f"registry.local/pandas@{DIGEST}"


@pytest.mark.parametrize(
    "override",
    [
        "amancevice/pandas:slim",
        "amancevice/pandas:latest",
        "amancevice/pandas@sha256:short",
        f"amancevice/pandas@sha512:{'a' * 64}",
        f"bad name@{DIGEST}",
    ],
)
def test_an_override_without_a_digest_is_refused(monkeypatch, override):
    monkeypatch.setenv(SANDBOX_IMAGE_ENV, override)

    assert SecureCodeExecutor().image == SANDBOX_IMAGE


def test_a_missing_image_is_pulled_by_digest():
    executor = _executor()
    container = MagicMock()
    executor.client.containers.create.side_effect = [sce.docker.errors.ImageNotFound("missing"), container]

    executor._run_in_container("/does-not-matter", "exec_1")

    executor.client.images.pull.assert_called_once_with(SANDBOX_IMAGE)


# ---------------------------------------------------------------------------
# The container is hardened
# ---------------------------------------------------------------------------

def test_execute_container_is_hardened(monkeypatch):
    _as_host_user(monkeypatch, 1000)
    executor = _executor()

    executor._run_in_container("/does-not-matter", "exec_1")

    kwargs = executor.client.containers.create.call_args.kwargs
    assert kwargs["image"] == SANDBOX_IMAGE
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["network_mode"] == "none"
    assert kwargs["user"] == "1000:1000"
    # Nothing but the exchange directory is writable, so temp files and
    # library caches go there.
    assert kwargs["environment"]["HOME"] == "/workspace"
    assert kwargs["environment"]["TMPDIR"] == "/workspace"
    # The existing limits are unchanged.
    assert kwargs["mem_limit"] == "512m"
    assert kwargs["pids_limit"] == 128
    assert kwargs["volumes"] == {"/does-not-matter": {"bind": "/workspace", "mode": "rw"}}


@pytest.mark.parametrize(
    "uid, rootless, expected",
    [
        (1000, False, "1000:1000"),  # the owner of the private exchange directory
        (0, False, "65534:65534"),  # never root; execute() hands it the directory
        (1000, True, "0:0"),  # rootless: container root is the unprivileged host user
        (0, True, "0:0"),
    ],
)
def test_container_user_is_never_a_privileged_root(monkeypatch, uid, rootless, expected):
    _as_host_user(monkeypatch, uid)
    executor = _executor()
    options = ["name=seccomp,profile=builtin"] + (["name=rootless"] if rootless else [])
    executor.client.info.return_value = {"SecurityOptions": options}

    assert executor._container_user() == expected


def test_container_user_without_getuid_is_unprivileged(monkeypatch):
    # Docker Desktop on Windows: no getuid, and the folder is shared with any user.
    monkeypatch.delattr(sce.os, "getuid", raising=False)
    executor = _executor()

    assert executor._container_user() == "65534:65534"


@pytest.mark.parametrize("info", [RuntimeError("daemon down"), {"SecurityOptions": None}, {}])
def test_an_unknown_daemon_is_not_treated_as_rootless(monkeypatch, info):
    _as_host_user(monkeypatch, 0)
    executor = _executor()
    if isinstance(info, Exception):
        executor.client.info.side_effect = info
    else:
        executor.client.info.return_value = info

    assert executor._container_user() == "65534:65534"


def test_the_daemon_is_asked_once(monkeypatch):
    _as_host_user(monkeypatch, 1000)
    executor = _executor()

    executor._container_user()
    executor._container_user()

    executor.client.info.assert_called_once()


# ---------------------------------------------------------------------------
# The exchange directory stays private
# ---------------------------------------------------------------------------

def _chown_recorder(monkeypatch):
    calls = []
    monkeypatch.setattr(sce.os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)), raising=False)
    return calls


def test_as_root_the_directory_is_handed_to_the_container_user(monkeypatch, tmp_path):
    _as_host_user(monkeypatch, 0)
    calls = _chown_recorder(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "script.py").write_text("x = 1\n")
    (workspace / "context.json").write_text("{}")

    _executor()._hand_workspace_to_container_user(str(workspace))

    assert sorted(calls) == sorted([
        (str(workspace), 65534, 65534),
        (str(workspace / "script.py"), 65534, 65534),
        (str(workspace / "context.json"), 65534, 65534),
    ])


@pytest.mark.parametrize("uid, rootless", [(1000, False), (0, True), (1000, True)])
def test_otherwise_the_directory_is_left_alone(monkeypatch, tmp_path, uid, rootless):
    _as_host_user(monkeypatch, uid)
    calls = _chown_recorder(monkeypatch)
    executor = _executor()
    if rootless:
        executor.client.info.return_value = {"SecurityOptions": ["name=rootless"]}

    executor._hand_workspace_to_container_user(str(tmp_path))

    assert calls == []


def test_execute_hands_over_the_directory_before_the_container_runs(monkeypatch):
    _as_host_user(monkeypatch, 0)
    calls = _chown_recorder(monkeypatch)
    executor = _executor()
    executor.client.ping.return_value = True
    safe = MagicMock(is_verified=True, developer_fields={"is_valid": True})
    monkeypatch.setattr(executor, "_is_safe_code", lambda code: safe)
    seen = {}

    def fake_run(tmpdir, execution_id, cleanup_status=None):
        seen["chowned_before_run"] = any(path == tmpdir for path, _, _ in calls)
        seen["files"] = sorted(os.listdir(tmpdir))
        with open(os.path.join(tmpdir, "result.json"), "w") as f:
            f.write('{"result": 2}')

    monkeypatch.setattr(executor, "_run_in_container", fake_run)

    success, error, result = executor.execute("result = 1 + 1", {})

    assert (success, error, result) == (True, None, 2)
    assert seen["chowned_before_run"] is True
    assert seen["files"] == ["context.json", "script.py", "user_code.py"]
