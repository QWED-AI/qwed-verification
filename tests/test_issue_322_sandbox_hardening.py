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
    SECURE_RUNTIME_UNAVAILABLE,
    SandboxUnavailable,
    SecureCodeExecutor,
)

DIGEST = "sha256:" + "a" * 64
FLOOR, LAST = sce._DEFAULT_SANDBOX_UID_RANGE
CEILING = LAST + 1


@pytest.fixture(autouse=True)
def _no_host_delegations(monkeypatch):
    # Tests decide for themselves which ids the host has delegated.
    monkeypatch.delenv(sce.SANDBOX_UID_RANGE_ENV, raising=False)
    monkeypatch.setattr(sce, "_SUBORDINATE_ID_FILES", ())


def _executor(options=("name=seccomp,profile=builtin",)):
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    executor.client = MagicMock()
    executor.docker_available = True
    executor.cpu_limit, executor.memory_limit, executor.pids_limit = 0.5, "512m", 128
    executor.timeout = 10
    executor.max_result_bytes = 2 * 1024 * 1024
    executor.execution_count = 0
    executor.image = SANDBOX_IMAGE
    executor._daemon_mode_cache = None
    executor._workspace_users = {}
    executor.client.info.return_value = {"SecurityOptions": list(options)}
    executor.client.containers.create.return_value = MagicMock()
    return executor


def _as_host_user(monkeypatch, uid, gid=1000):
    monkeypatch.setattr(sce.os, "getuid", lambda: uid, raising=False)
    monkeypatch.setattr(sce.os, "getgid", lambda: gid, raising=False)


def _chown_recorder(monkeypatch):
    calls = []

    def chown(path, uid, gid, *, follow_symlinks=True):
        calls.append((path, uid, gid, follow_symlinks))

    monkeypatch.setattr(sce.os, "chown", chown, raising=False)
    return calls


def _uid_of(user):
    uid, gid = user.split(":")
    assert uid == gid
    return int(uid)


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


@pytest.mark.parametrize(
    "override",
    [
        f"pandas@{DIGEST}",
        f"registry.local/pandas@{DIGEST}",
        f"registry.local:5000/team/pandas:slim@{DIGEST}",
        f"localhost/img@{DIGEST}",
        f"myreg:5000/img@{DIGEST}",
        f"[2001:db8::1]:5000/team/pandas@{DIGEST}",
        f"[::1]/img@{DIGEST}",
    ],
)
def test_an_override_by_digest_is_used(monkeypatch, override):
    monkeypatch.setenv(SANDBOX_IMAGE_ENV, override)

    assert SecureCodeExecutor().image == override


@pytest.mark.parametrize(
    "override",
    [
        "amancevice/pandas:slim",
        "amancevice/pandas:latest",
        "amancevice/pandas@sha256:short",
        f"amancevice/pandas@sha512:{'a' * 64}",
        f"bad name@{DIGEST}",
        f"/bad@{DIGEST}",
        f"Upper/case@{DIGEST}",
        f"a//b@{DIGEST}",
        f"img-@{DIGEST}",
        f"[zz]/img@{DIGEST}",
    ],
)
def test_an_override_that_is_not_a_valid_digest_reference_is_refused(monkeypatch, override):
    monkeypatch.setenv(SANDBOX_IMAGE_ENV, override)

    assert SecureCodeExecutor().image == SANDBOX_IMAGE


def test_a_missing_image_is_pulled_by_digest(monkeypatch):
    _as_host_user(monkeypatch, 1000)
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


def test_a_non_root_host_runs_the_container_as_itself(monkeypatch):
    _as_host_user(monkeypatch, 1000, gid=1001)

    assert _executor()._container_user("/ws") == "1000:1001"


def test_a_root_host_runs_the_container_as_the_workspace_uid(monkeypatch):
    _as_host_user(monkeypatch, 0)
    executor = _executor()
    executor._workspace_users["/ws"] = FLOOR + 42

    assert executor._container_user("/ws") == f"{FLOOR + 42}:{FLOOR + 42}"


def test_a_root_host_without_a_prepared_workspace_still_never_runs_as_root(monkeypatch):
    _as_host_user(monkeypatch, 0)

    uid = _uid_of(_executor()._container_user("/not-prepared"))

    assert FLOOR <= uid < CEILING


def test_a_rootless_daemon_runs_the_container_as_its_root(monkeypatch):
    # Container root is the unprivileged host user who runs the daemon.
    _as_host_user(monkeypatch, 1000)

    assert _executor(options=["name=rootless"])._container_user("/ws") == "0:0"


@pytest.mark.parametrize(
    "uid, options",
    [
        (0, ["name=rootless"]),  # the daemon's user is not the directory's owner
        (1000, ["name=userns"]),  # userns-remap maps every container uid away
        (0, ["name=userns"]),
    ],
)
def test_unsupported_user_mappings_are_refused(monkeypatch, uid, options):
    _as_host_user(monkeypatch, uid)
    executor = _executor(options=options)

    with pytest.raises(SandboxUnavailable):
        executor._container_user("/ws")


def test_container_user_without_getuid_is_unprivileged(monkeypatch):
    # Docker Desktop on Windows: no getuid, and the folder is shared with any user.
    monkeypatch.delattr(sce.os, "getuid", raising=False)
    executor = _executor()

    assert executor._container_user("/ws") == "65534:65534"
    executor.client.info.assert_not_called()


def test_an_unreadable_daemon_is_unavailable_and_asked_again(monkeypatch):
    _as_host_user(monkeypatch, 1000)
    executor = _executor()
    executor.client.info.side_effect = [RuntimeError("daemon down"), {"SecurityOptions": []}]

    with pytest.raises(SandboxUnavailable):
        executor._container_user("/ws")
    # The failure is not cached as an answer.
    assert executor._container_user("/ws") == "1000:1000"


@pytest.mark.parametrize("info", [{"SecurityOptions": None}, {}, {"SecurityOptions": "name=rootless"}])
def test_missing_or_odd_security_options_are_the_default_mode(monkeypatch, info):
    _as_host_user(monkeypatch, 1000)
    executor = _executor()
    executor.client.info.return_value = info

    assert executor._container_user("/ws") == "1000:1000"


def test_the_daemon_is_asked_once(monkeypatch):
    _as_host_user(monkeypatch, 1000)
    executor = _executor()

    executor._container_user("/ws")
    executor._container_user("/ws")

    executor.client.info.assert_called_once()


# ---------------------------------------------------------------------------
# The exchange directory stays private
# ---------------------------------------------------------------------------

def _workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "script.py").write_text("x = 1\n")
    (workspace / "context.json").write_text("{}")
    return workspace


def test_as_root_the_workspace_goes_to_a_fresh_uid_files_first(monkeypatch, tmp_path):
    _as_host_user(monkeypatch, 0)
    calls = _chown_recorder(monkeypatch)
    workspace = _workspace(tmp_path)
    executor = _executor()

    executor._hand_workspace_to_container_user(str(workspace))

    uid = executor._workspace_users[str(workspace)]
    assert FLOOR <= uid < CEILING
    assert uid in sce._sandbox_uids_in_use
    # Every entry, then the directory last, and never through a link.
    assert calls[-1] == (str(workspace), uid, uid, False)
    assert sorted(calls[:-1]) == sorted([
        (str(workspace / "script.py"), uid, uid, False),
        (str(workspace / "context.json"), uid, uid, False),
    ])
    executor._release_workspace_user(str(workspace))
    assert uid not in sce._sandbox_uids_in_use
    assert str(workspace) not in executor._workspace_users


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_non_regular_entry_is_refused_before_anything_is_handed_over(monkeypatch, tmp_path):
    _as_host_user(monkeypatch, 0)
    calls = _chown_recorder(monkeypatch)
    workspace = _workspace(tmp_path)
    try:
        os.symlink(tmp_path / "outside", workspace / "link")
    except OSError:
        pytest.skip("symlinks are not permitted here")

    executor = _executor()
    with pytest.raises(SandboxUnavailable):
        executor._hand_workspace_to_container_user(str(workspace))

    # The directory itself was never handed over.
    assert all(path != str(workspace) for path, *_ in calls)


@pytest.mark.parametrize("uid, options", [(1000, []), (1000, ["name=rootless"])])
def test_otherwise_the_directory_is_left_alone(monkeypatch, tmp_path, uid, options):
    _as_host_user(monkeypatch, uid)
    calls = _chown_recorder(monkeypatch)
    executor = _executor(options=options)

    executor._hand_workspace_to_container_user(str(tmp_path))

    assert calls == []
    assert executor._workspace_users == {}


def test_two_workspaces_never_share_a_uid(monkeypatch):
    picks = iter([FLOOR + 1, FLOOR + 1, FLOOR + 2])
    monkeypatch.setattr(sce.secrets, "randbelow", lambda span: next(picks) - FLOOR)
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: False)

    first = sce._claim_sandbox_uid()
    second = sce._claim_sandbox_uid()

    assert (first, second) == (FLOOR + 1, FLOOR + 2)
    sce._release_sandbox_uid(first)
    sce._release_sandbox_uid(second)


def test_a_uid_a_host_account_has_is_skipped(monkeypatch):
    picks = iter([FLOOR + 7, FLOOR + 8])
    monkeypatch.setattr(sce.secrets, "randbelow", lambda span: next(picks) - FLOOR)
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: uid == FLOOR + 7)

    uid = sce._claim_sandbox_uid()

    assert uid == FLOOR + 8
    assert FLOOR + 7 not in sce._sandbox_uids_in_use
    sce._release_sandbox_uid(uid)


def test_a_uid_inside_a_subordinate_id_range_is_skipped(monkeypatch, tmp_path):
    # /etc/subuid and /etc/subgid delegate ids to user namespaces (rootless
    # containers, nspawn); a process there runs as that host uid.
    subuid = tmp_path / "subuid"
    subuid.write_text(f"alice:100000:65536\nbob:{FLOOR + 10}:5\nbroken line\n")
    subgid = tmp_path / "subgid"
    subgid.write_text(f"carol:{FLOOR + 20}:1\n")
    monkeypatch.setattr(sce, "_SUBORDINATE_ID_FILES", (str(subuid), str(subgid), str(tmp_path / "missing")))
    monkeypatch.setattr(sce.secrets, "randbelow", lambda span: 12)
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: False)

    uid = sce._claim_sandbox_uid()

    # The walk starts inside bob's block (10-14) and takes the first id after it.
    assert uid == FLOOR + 15
    sce._release_sandbox_uid(uid)


def _delegate(monkeypatch, tmp_path, lines):
    subuid = tmp_path / "subuid"
    subuid.write_text("".join(f"{line}\n" for line in lines))
    monkeypatch.setattr(sce, "_SUBORDINATE_ID_FILES", (str(subuid),))


@pytest.mark.parametrize("start", [0, 5000, 99998])
def test_a_large_delegated_block_is_skipped_whole(monkeypatch, tmp_path, start):
    # A 99999-id block, far more than the probe budget, covers all but the
    # last id of the range; wherever the walk starts, it finds that id.
    monkeypatch.setenv(sce.SANDBOX_UID_RANGE_ENV, "2000000000-2000099999")
    _delegate(monkeypatch, tmp_path, ["podman:2000000000:99999"])
    monkeypatch.setattr(sce.secrets, "randbelow", lambda span: start)
    probes = []
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: probes.append(uid) or False)

    uid = sce._claim_sandbox_uid()

    assert uid == 2000099999
    assert probes == [2000099999]
    sce._release_sandbox_uid(uid)


def test_a_block_running_past_the_range_end_wraps_to_its_start(monkeypatch, tmp_path):
    monkeypatch.setenv(sce.SANDBOX_UID_RANGE_ENV, "2000000000-2000000009")
    _delegate(monkeypatch, tmp_path, ["a:2000000005:100"])
    monkeypatch.setattr(sce.secrets, "randbelow", lambda span: 7)
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: False)

    uid = sce._claim_sandbox_uid()

    assert uid == 2000000000
    sce._release_sandbox_uid(uid)


def test_a_range_wholly_delegated_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv(sce.SANDBOX_UID_RANGE_ENV, "2000000000-2000000009")
    _delegate(monkeypatch, tmp_path, ["a:1999999990:15", "b:2000000004:6"])
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: False)

    with pytest.raises(SandboxUnavailable):
        sce._claim_sandbox_uid()


@pytest.mark.parametrize("start", [0, 41, 98, 99])
def test_a_small_range_with_one_free_uid_always_finds_it(monkeypatch, start):
    monkeypatch.setenv(sce.SANDBOX_UID_RANGE_ENV, "2000000000-2000000099")
    monkeypatch.setattr(sce.secrets, "randbelow", lambda span: start)
    free = 2000000042
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: uid != free)

    uid = sce._claim_sandbox_uid()

    assert uid == free
    sce._release_sandbox_uid(uid)


def test_a_large_range_is_probed_a_bounded_number_of_times(monkeypatch):
    probes = []

    def taken(uid):
        probes.append(uid)
        return True

    monkeypatch.setattr(sce, "_host_id_exists", taken)

    with pytest.raises(SandboxUnavailable):
        sce._claim_sandbox_uid()
    assert len(probes) == sce._MAX_UID_PROBES


@pytest.mark.parametrize(
    "users, groups, expected",
    [({5}, set(), True), (set(), {5}, True), (set(), set(), False)],
    ids=["a-user-has-it", "a-group-has-it", "free"],
)
def test_host_id_exists_reads_the_user_and_group_databases(monkeypatch, users, groups, expected):
    import sys
    import types

    def lookup(ids):
        def find(uid):
            if uid in ids:
                return object()
            raise KeyError(uid)
        return find

    monkeypatch.setitem(sys.modules, "pwd", types.SimpleNamespace(getpwuid=lookup(users)))
    monkeypatch.setitem(sys.modules, "grp", types.SimpleNamespace(getgrgid=lookup(groups)))

    assert sce._host_id_exists(5) is expected


def test_the_default_range_is_the_documented_unused_one():
    # systemd: 1879048192-2147483647 is unused, above the container range.
    assert sce._sandbox_uid_range() == (1879048192, 2147483646)


@pytest.mark.parametrize(
    "configured, expected",
    [
        ("3000000000-3000000010", sce._DEFAULT_SANDBOX_UID_RANGE),  # past 2^31
        ("100-200", sce._DEFAULT_SANDBOX_UID_RANGE),  # ordinary accounts
        ("500000-400000", sce._DEFAULT_SANDBOX_UID_RANGE),  # reversed
        ("abc", sce._DEFAULT_SANDBOX_UID_RANGE),
        ("2000000000-2000000099", (2000000000, 2000000099)),
        (" 70000 - 70000 ", (70000, 70000)),
    ],
)
def test_an_operator_reserved_range_is_validated(monkeypatch, configured, expected):
    monkeypatch.setenv(sce.SANDBOX_UID_RANGE_ENV, configured)

    assert sce._sandbox_uid_range() == expected


def test_uids_come_from_the_operator_range(monkeypatch):
    monkeypatch.setenv(sce.SANDBOX_UID_RANGE_ENV, "2000000000-2000000000")
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: False)

    uid = sce._claim_sandbox_uid()

    assert uid == 2000000000
    sce._release_sandbox_uid(uid)


def test_no_free_uid_is_unavailable(monkeypatch):
    monkeypatch.setattr(sce, "_host_id_exists", lambda uid: True)

    with pytest.raises(SandboxUnavailable):
        sce._claim_sandbox_uid()


def _prepared_execute(monkeypatch, executor):
    executor.client.ping.return_value = True
    safe = MagicMock(is_verified=True, developer_fields={"is_valid": True})
    monkeypatch.setattr(executor, "_is_safe_code", lambda code: safe)


def test_execute_hands_over_the_workspace_and_releases_it(monkeypatch):
    _as_host_user(monkeypatch, 0)
    calls = _chown_recorder(monkeypatch)
    executor = _executor()
    _prepared_execute(monkeypatch, executor)
    seen = {}

    def fake_run(tmpdir, execution_id, cleanup_status=None):
        seen["uid"] = executor._workspace_users.get(tmpdir)
        seen["handed_before_run"] = (tmpdir, seen["uid"], seen["uid"], False) in calls
        seen["files"] = sorted(os.listdir(tmpdir))
        with open(os.path.join(tmpdir, "result.json"), "w") as f:
            f.write('{"result": 2}')

    monkeypatch.setattr(executor, "_run_in_container", fake_run)

    success, error, result = executor.execute("result = 1 + 1", {})

    assert (success, error, result) == (True, None, 2)
    assert seen["handed_before_run"] is True
    assert seen["files"] == ["context.json", "script.py", "user_code.py"]
    assert executor._workspace_users == {}
    assert seen["uid"] not in sce._sandbox_uids_in_use


def test_execute_reports_an_unsupported_daemon_as_runtime_unavailable(monkeypatch):
    _as_host_user(monkeypatch, 0)
    _chown_recorder(monkeypatch)
    executor = _executor(options=["name=userns"])
    _prepared_execute(monkeypatch, executor)

    def run_in_container(tmpdir, execution_id, cleanup_status=None):
        executor._container_user(tmpdir)

    monkeypatch.setattr(executor, "_run_in_container", run_in_container)

    assert executor.execute("result = 1", {}) == (False, SECURE_RUNTIME_UNAVAILABLE, None)


def test_execute_reports_an_unreadable_daemon_as_runtime_unavailable(monkeypatch):
    _as_host_user(monkeypatch, 0)
    executor = _executor()
    executor.client.info.side_effect = RuntimeError("daemon down")
    _prepared_execute(monkeypatch, executor)

    assert executor.execute("result = 1", {}) == (False, SECURE_RUNTIME_UNAVAILABLE, None)
