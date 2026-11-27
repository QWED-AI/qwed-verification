"""
SystemGuard.verify_file_access: a path is allowed only inside an allowed
directory, compared part by part after links are resolved.

A string prefix is not containment: "/tmp-exfil" starts with "/tmp" but is
not inside it, and a link inside an allowed directory can name a file
outside it.
"""

import os
import shutil
import stat
import tempfile
import unicodedata
from pathlib import Path
from types import SimpleNamespace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qwed_sdk.guards import system_guard
from qwed_sdk.guards.system_guard import MAX_PATH_CHARS, MAX_PATH_PARTS, SystemGuard
from qwed_sdk.qwed_local import QWEDLocal


ZERO_WIDTH_SPACE = chr(0x200B)
WORD_JOINER = chr(0x2060)
CYRILLIC_A = chr(0x0430)
FULLWIDTH_HYPHEN = chr(0xFF0D)
NUL = chr(0)

# Names that share a string prefix with the allowed directory but are
# other directories next to it.
SIBLING_SUFFIXES = [
    "-exfil",
    "XYZ",
    "2",
    "_old",
    ".d",
    "-secrets",
    ZERO_WIDTH_SPACE,
    WORD_JOINER,
    CYRILLIC_A,
    FULLWIDTH_HYPHEN + "x",
]


def _make_dir_link(link: Path, target: Path) -> None:
    """A directory link: a symbolic link, or a junction on Windows."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        try:
            import _winapi

            _winapi.CreateJunction(str(target), str(link))
            return
        except (ImportError, OSError):
            pass
    pytest.skip("this system cannot create a directory link")


def _make_file_link(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this system cannot create a file link")


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "data.json").write_text("{}")
    return ws


# --- the report: a prefix is not containment ---------------------------------


@pytest.mark.parametrize("suffix", SIBLING_SUFFIXES)
def test_a_sibling_sharing_the_prefix_is_outside(workspace, suffix):
    sibling = Path(str(workspace) + suffix)
    sibling.mkdir()
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(sibling / "secret.txt"))

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


@pytest.mark.parametrize("suffix", ["-old", "2", ZERO_WIDTH_SPACE])
def test_a_sibling_of_a_relative_allowed_directory_is_outside(tmp_path, monkeypatch, suffix):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace").mkdir()
    guard = SystemGuard(allowed_paths=["./workspace"])

    result = guard.verify_file_access("./workspace" + suffix + "/x.txt")

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


@pytest.mark.parametrize("path", [
    "/tmp/report.txt", "/tmp", "/tmp/", "//tmp/report.txt", "/tmp/./report.txt", "/TMP/report.txt",
    "/var/tmp/report.txt", "/dev/shm/report.txt",
    "/tmp-exfil/secret", "/tmpXYZ/anything", "/tmp" + ZERO_WIDTH_SPACE + "/x",
])
def test_the_defaults_do_not_allow_tmp(tmp_path, monkeypatch, path):
    # Every user of the machine can write to /tmp, so a file there may be
    # someone else's: it is not a default.
    monkeypatch.chdir(tmp_path)

    result = SystemGuard().verify_file_access(path)

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


def test_a_sibling_of_the_working_directory_is_outside_dot(tmp_path, monkeypatch):
    # "." as in the defaults, named so that the test does not depend on them.
    project = tmp_path / "proj"
    project.mkdir()
    secrets = tmp_path / "proj-secrets"
    secrets.mkdir()
    (secrets / "key.txt").write_text("secret")
    monkeypatch.chdir(project)

    result = SystemGuard(allowed_paths=["."]).verify_file_access(str(secrets / "key.txt"))

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


def test_the_same_path_through_qwed_local_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("QWED_QUIET", "1")
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(project)
    client = QWEDLocal(base_url="http://localhost:11434/v1", model="test-model", cache=False)

    refused = client.verify_file_access(str(tmp_path / "proj-secrets" / "key.txt"), allowed_paths=["."])
    allowed = client.verify_file_access("notes.txt", allowed_paths=["."])

    assert refused.verified is False
    assert refused.evidence["risk"] == "SANDBOX_ESCAPE"
    assert allowed.verified is True
    assert allowed.evidence["resolved_path"] == os.path.realpath(project / "notes.txt")


# --- links are resolved before the check --------------------------------------


def test_a_link_inside_that_points_outside_is_refused(tmp_path, workspace):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "key.txt").write_text("secret")
    _make_dir_link(workspace / "escape", outside)
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace / "escape" / "key.txt"))

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


def test_a_link_inside_that_points_inside_is_allowed(workspace):
    (workspace / "real").mkdir()
    _make_dir_link(workspace / "alias", workspace / "real")
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace / "alias" / "a.txt"))

    assert result["verified"] is True
    assert result["resolved_path"] == os.path.realpath(workspace / "real" / "a.txt")


def test_a_link_outside_that_points_inside_is_refused_as_written(tmp_path, workspace):
    # The path as written must be inside before anything is read: the
    # resolved path is checked as well, never instead.
    _make_dir_link(tmp_path / "door", workspace)
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(tmp_path / "door" / "data.json"))

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


def test_an_allowed_directory_that_is_a_link_is_not_used(tmp_path, workspace):
    # Whoever can replace the link decides where it points.
    _make_dir_link(tmp_path / "ws-link", workspace)
    guard = SystemGuard(allowed_paths=[str(tmp_path / "ws-link")])

    assert guard.verify_file_access(str(workspace / "data.json"))["verified"] is False
    assert guard.verify_file_access(str(tmp_path / "ws-link" / "data.json"))["verified"] is False


def test_a_link_made_where_an_allowed_directory_should_be_widens_nothing(tmp_path, monkeypatch):
    # The working directory is allowed, so whoever can write there can make
    # "workspace" a link to anywhere.
    project = tmp_path / "proj"
    project.mkdir()
    victim = tmp_path / "victim"
    (victim / ".config").mkdir(parents=True)
    (victim / "notes.txt").write_text("secret")
    monkeypatch.chdir(project)
    _make_dir_link(project / "workspace", victim)
    guard = SystemGuard(allowed_paths=["./workspace", "."])

    for path in [str(victim / "notes.txt"), str(victim / ".config" / "app.toml"),
                 "workspace/notes.txt", "./workspace/.config/app.toml"]:
        result = guard.verify_file_access(path)
        assert result["verified"] is False, path
        assert result["risk"] == "SANDBOX_ESCAPE", path


def test_a_link_between_two_allowed_directories_is_not_trusted(tmp_path):
    # Whoever can write the outer directory can replace "mid" with a link.
    outer = tmp_path / "outer"
    (outer / "real-mid" / "inner").mkdir(parents=True)
    victim = tmp_path / "victim"
    (victim / "inner").mkdir(parents=True)
    (victim / "inner" / "secret.txt").write_text("secret")
    _make_dir_link(outer / "mid", victim)
    guard = SystemGuard(allowed_paths=[str(outer), str(outer / "mid" / "inner")])

    for path in [str(victim / "inner" / "secret.txt"), str(outer / "mid" / "inner" / "secret.txt")]:
        result = guard.verify_file_access(path)
        assert result["verified"] is False, path
        assert result["risk"] == "SANDBOX_ESCAPE", path
    assert guard.verify_file_access(str(outer / "real-mid" / "inner" / "a.txt"))["verified"] is True


def test_a_link_above_a_dropped_allowed_directory_drops_the_ones_inside(tmp_path):
    # "outer-link" is not used (it is a link); "outer-link/mid/inner" goes
    # through it, so it is not trusted either.
    outer = tmp_path / "outer"
    (outer / "mid" / "inner").mkdir(parents=True)
    victim = tmp_path / "victim"
    (victim / "inner").mkdir(parents=True)
    (victim / "inner" / "secret.txt").write_text("secret")
    _make_dir_link(tmp_path / "outer-link", outer)
    inner = tmp_path / "outer-link" / "mid" / "inner"
    guard = SystemGuard(allowed_paths=[str(tmp_path / "outer-link"), str(inner)])

    assert guard.verify_file_access(str(inner / "a.txt"))["verified"] is False
    assert guard.verify_file_access(str(outer / "mid" / "inner" / "a.txt"))["verified"] is False
    assert guard.verify_file_access(str(victim / "inner" / "secret.txt"))["verified"] is False


def test_a_link_that_cannot_be_followed_is_not_an_allowed_directory(tmp_path):
    # Resolving a loop returns the link itself, so it is "the same file" as
    # what it resolves to; it is still a link, and could be pointed anywhere.
    loop = tmp_path / "loop"
    try:
        os.symlink(loop, loop, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this system cannot create a symbolic link")
    guard = SystemGuard(allowed_paths=[str(loop)])

    assert guard._allowed_roots() == []
    assert guard.verify_file_access(str(loop / "x.txt"))["verified"] is False


@pytest.mark.skipif(os.name == "nt", reason="needs a directory that tells case apart")
def test_a_link_to_a_name_that_differs_only_in_case_is_not_the_directory(tmp_path):
    other = tmp_path / "WS"
    other.mkdir()
    (other / "secret.txt").write_text("secret")
    _make_dir_link(tmp_path / "ws", other)
    guard = SystemGuard(allowed_paths=[str(tmp_path / "ws")])

    for path in [str(other / "secret.txt"), str(tmp_path / "ws" / "secret.txt")]:
        assert guard.verify_file_access(path)["verified"] is False, path


def _short_name(path: Path) -> str:
    """The Windows short (8.3) form of ``path``, or "" when the volume keeps none."""
    import ctypes

    buffer = ctypes.create_unicode_buffer(1024)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
    short = buffer.value if 0 < length < len(buffer) else ""
    return short if short and os.path.basename(short) != path.name else ""


@pytest.mark.skipif(os.name != "nt", reason="Windows short names")
def test_an_allowed_directory_written_with_its_short_name_is_used(tmp_path):
    long_dir = tmp_path / "a-long-directory-name"
    (long_dir / "sub").mkdir(parents=True)
    short = _short_name(long_dir)
    if not short:
        pytest.skip("this volume keeps no short names")
    guard = SystemGuard(allowed_paths=[short])
    nested = SystemGuard(allowed_paths=[str(tmp_path), os.path.join(short, "sub")])

    assert guard.verify_file_access(str(long_dir / "data.json"))["verified"] is True
    assert guard.verify_file_access(os.path.join(short, "data.json"))["verified"] is True
    assert len(nested._allowed_roots()) == 2


def test_an_allowed_directory_that_resolves_elsewhere_is_not_used(tmp_path, workspace, monkeypatch):
    # A link swapped in between two reads of the directory must not count:
    # here resolving the directory lands elsewhere, though nothing on disk
    # is a link when the guard could look again.
    victim = tmp_path / "victim"
    victim.mkdir()
    real_realpath = os.path.realpath
    ws_key = os.path.normcase(str(workspace))

    def swapped_realpath(path, *args, **kwargs):
        if os.path.normcase(os.fspath(path)) == ws_key:
            return str(victim)
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", swapped_realpath)
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(victim / "notes.txt"))

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


@pytest.mark.skipif(os.name == "nt", reason="Windows removes '..' before it reads links")
def test_dotdot_after_a_link_is_the_parent_of_the_link_target(tmp_path, workspace):
    outside = tmp_path / "outside" / "dir"
    outside.mkdir(parents=True)
    (tmp_path / "outside" / "secret").write_text("secret")
    _make_dir_link(workspace / "link", outside)
    # Custom patterns replace the defaults, so ".." is not refused by name.
    guard = SystemGuard(allowed_paths=[str(workspace)], forbidden_path_patterns=[r"\.pem$"])

    result = guard.verify_file_access(str(workspace / "link") + "/../secret")

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


def test_case_folding_is_not_containment(workspace):
    # The Kelvin sign folds to "k" in Python but names another directory.
    kelvin = chr(0x212A)
    work = workspace.parent / "work"
    work.mkdir()
    guard = SystemGuard(allowed_paths=[str(work)], forbidden_path_patterns=[r"\.pem$"])

    result = guard.verify_file_access(str(workspace.parent / ("wor" + kelvin)) + os.sep + "secret.txt")

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


def test_a_path_outside_is_refused_before_the_file_system_is_read(tmp_path, workspace, monkeypatch):
    resolved = []
    real_realpath = os.path.realpath

    def recording_realpath(path, *args, **kwargs):
        resolved.append(os.fspath(path))
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", recording_realpath)
    walked = []
    real_walk = system_guard._links_stay_inside

    def recording_walk(path, walkable):
        walked.append(path)
        return real_walk(path, walkable)

    monkeypatch.setattr(system_guard, "_links_stay_inside", recording_walk)
    guard = SystemGuard(allowed_paths=[str(workspace)])
    outside = [str(tmp_path / "elsewhere" / "x"), str(workspace) + "-exfil/x",
               "//server/share/x", "\\\\server\\share\\x"]

    for path in outside:
        assert guard.verify_file_access(path)["verified"] is False, path

    assert not any("elsewhere" in p or "exfil" in p or "server" in p for p in resolved), resolved
    # Refused as written: the links on the way are not read either.
    assert walked == []


@pytest.mark.skipif(os.name == "nt", reason="Windows removes '..' before it reads links")
def test_a_path_outside_as_written_is_refused_where_links_lead_back_inside(workspace):
    # "workspace/deep/../../x" is outside as written. The system reads it
    # as "workspace/a/x", but a caller that removes ".." first opens the
    # "x" next to the workspace: both readings must be inside.
    (workspace / "a" / "b" / "c").mkdir(parents=True)
    _make_dir_link(workspace / "deep", workspace / "a" / "b" / "c")
    guard = SystemGuard(allowed_paths=[str(workspace)], forbidden_path_patterns=[r"\.pem$"])

    result = guard.verify_file_access(str(workspace / "deep") + "/../../x")

    assert result["verified"] is False
    assert result["risk"] == "SANDBOX_ESCAPE"


# --- links are read one by one, and never followed outside ------------------


def _record_lstat(monkeypatch) -> list:
    seen = []
    real_lstat = os.lstat

    def recording(path, *args, **kwargs):
        seen.append(os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", recording)
    return seen


def _read_under(seen: list, directory) -> list:
    key = os.path.normcase(str(directory))
    return [path for path in seen if os.path.normcase(path).startswith(key)]


def test_a_link_inside_to_outside_is_refused_without_reading_outside(tmp_path, workspace, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "key.txt").write_text("secret")
    _make_dir_link(workspace / "escape", outside)
    guard = SystemGuard(allowed_paths=[str(workspace)])
    seen = _record_lstat(monkeypatch)

    result = guard.verify_file_access(str(workspace / "escape" / "key.txt"))

    assert result["risk"] == "SANDBOX_ESCAPE"
    assert _read_under(seen, outside) == []


def test_a_link_inside_to_a_network_share_is_refused_without_connecting(workspace, monkeypatch):
    share = "\\\\192.0.2.1\\share" if os.name == "nt" else "//192.0.2.1/share"
    try:
        os.symlink(share, workspace / "share", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this system cannot create a symbolic link")
    seen = _record_lstat(monkeypatch)
    real_realpath = os.path.realpath

    def guarded_realpath(path, *args, **kwargs):
        assert "192.0.2.1" not in os.fspath(path)
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", guarded_realpath)
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace / "share" / "x.txt"))

    assert result["risk"] == "SANDBOX_ESCAPE"
    assert not any("192.0.2.1" in path for path in seen)


def test_a_chain_of_links_is_followed_only_while_it_stays_inside(tmp_path, workspace, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "sub" / "real").mkdir(parents=True)
    _make_dir_link(workspace / "sub" / "deep", outside)
    _make_dir_link(workspace / "sub" / "inner", workspace / "sub" / "real")
    _make_dir_link(workspace / "first", workspace / "sub")
    guard = SystemGuard(allowed_paths=[str(workspace)])
    seen = _record_lstat(monkeypatch)

    escaping = guard.verify_file_access(str(workspace / "first" / "deep" / "key.txt"))
    staying = guard.verify_file_access(str(workspace / "first" / "inner" / "a.txt"))

    assert escaping["risk"] == "SANDBOX_ESCAPE"
    assert _read_under(seen, outside) == []
    assert staying["verified"] is True
    assert staying["resolved_path"] == os.path.realpath(workspace / "sub" / "real" / "a.txt")


@pytest.mark.parametrize("extra", [0, 1])
def test_the_number_of_links_followed_is_bounded_exactly(workspace, extra):
    # A chain of links, each to the next, the last to a real directory.
    count = system_guard._MAX_LINKS + extra
    (workspace / "real").mkdir()
    target = workspace / "real"
    for number in reversed(range(count)):
        link = workspace / f"l{number}"
        _make_dir_link(link, target)
        target = link

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(workspace / "l0" / "x.txt"))

    if extra == 0:
        assert result["verified"] is True
        assert result["resolved_path"] == os.path.realpath(workspace / "real" / "x.txt")
    else:
        assert result["risk"] == "INVALID_PATH"


def test_links_that_go_round_are_refused(workspace):
    try:
        os.symlink(workspace / "b", workspace / "a", target_is_directory=True)
        os.symlink(workspace / "a", workspace / "b", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this system cannot create a symbolic link")

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(workspace / "a" / "x.txt"))

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


def test_a_link_above_the_allowed_directory_does_not_refuse_its_files(tmp_path):
    # A parent of the allowed directory is the caller's own setup (macOS
    # /var is one): the walk may read through it.
    (tmp_path / "real" / "ws").mkdir(parents=True)
    _make_dir_link(tmp_path / "alias", tmp_path / "real")
    guard = SystemGuard(allowed_paths=[str(tmp_path / "alias" / "ws")])

    result = guard.verify_file_access(str(tmp_path / "alias" / "ws" / "a.txt"))

    assert result["verified"] is True


def _make_junction(link: Path, target: Path) -> None:
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions")
def test_windows_junctions_are_links_too(tmp_path, workspace, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    _make_junction(tmp_path / "ws-junction", workspace)
    _make_junction(workspace / "escape", outside)

    assert SystemGuard(allowed_paths=[str(tmp_path / "ws-junction")])._allowed_roots() == []
    assert system_guard._is_link(str(workspace / "escape"))
    seen = _record_lstat(monkeypatch)
    resolved = []
    real_realpath = os.path.realpath

    def recording_realpath(path, *args, **kwargs):
        resolved.append(os.fspath(path))
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", recording_realpath)
    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(workspace / "escape" / "k"))
    assert result["risk"] == "SANDBOX_ESCAPE"
    assert _read_under(seen, outside) == []
    # Refused by the walk: the junction is never resolved.
    assert not any("escape" in path for path in resolved), resolved


@pytest.mark.parametrize(
    ("mode", "tag", "is_link"),
    [
        (stat.S_IFLNK, 0, True),
        (stat.S_IFDIR, 0xA0000003, True),   # junction (mount point)
        (stat.S_IFDIR, 0xA000000C, True),   # symbolic link
        (stat.S_IFDIR, 0x80000013, False),  # deduplicated file: not a name
        (stat.S_IFDIR, 0, False),
        (stat.S_IFREG, 0, False),
    ],
)
def test_reparse_points_that_name_another_file_count_as_links(mode, tag, is_link):
    status = SimpleNamespace(st_mode=mode, st_reparse_tag=tag)

    assert system_guard._is_link_stat(status) is is_link


@pytest.mark.skipif(os.name == "nt", reason="Windows removes '..' before it reads links")
def test_dotdot_in_the_walk_climbs_from_the_link_target(tmp_path, workspace, monkeypatch):
    # "workspace/self/../next/k" is inside as written, but "self" is the
    # workspace, so ".." is its parent and "next" is the link beside it.
    outside = tmp_path / "outside"
    outside.mkdir()
    _make_dir_link(workspace / "self", workspace)
    _make_dir_link(tmp_path / "next", outside)
    guard = SystemGuard(allowed_paths=[str(workspace)], forbidden_path_patterns=[r"\.pem$"])
    seen = _record_lstat(monkeypatch)

    result = guard.verify_file_access(str(workspace / "self") + "/../next/k")

    assert result["risk"] == "SANDBOX_ESCAPE"
    assert _read_under(seen, tmp_path / "next") == []


@pytest.mark.skipif(os.name == "nt", reason="Windows removes '..' before it reads links")
def test_dotdot_after_a_link_is_checked_where_the_system_reads_it(workspace):
    # As written this is "workspace/config"; the system opens
    # "workspace/.git/config".
    (workspace / ".git" / "hooks").mkdir(parents=True)
    _make_dir_link(workspace / "hooks", workspace / ".git" / "hooks")
    guard = SystemGuard(allowed_paths=[str(workspace)], forbidden_path_patterns=[r"\.git/config"])

    result = guard.verify_file_access(str(workspace / "hooks") + "/../config")

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


@pytest.mark.skipif(os.name == "nt", reason="Windows removes '..' before it reads links")
def test_an_allowed_directory_with_dotdot_after_a_link_is_read_as_the_system_reads_it(tmp_path, monkeypatch):
    # Lexically "ws", but the system reads "ws/link/.." as the parent of the
    # link's target: two different directories, so it is not used.
    outside = tmp_path / "outside" / "dir"
    outside.mkdir(parents=True)
    (tmp_path / "ws").mkdir()
    _make_dir_link(tmp_path / "ws" / "link", outside)
    monkeypatch.chdir(tmp_path)

    assert SystemGuard(allowed_paths=["ws/link/.."])._allowed_roots() == []


def test_a_link_to_a_parent_of_the_allowed_directory_is_outside_it(tmp_path, workspace):
    _make_dir_link(workspace / "up", tmp_path)

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(workspace / "up"))

    assert result["risk"] == "SANDBOX_ESCAPE"


def test_a_link_that_cannot_be_read_is_invalid(workspace, monkeypatch):
    (workspace / "sub").mkdir()
    _make_dir_link(workspace / "link", workspace / "sub")

    def unreadable(*_args, **_kwargs):
        raise OSError("cannot read link")

    monkeypatch.setattr(os, "readlink", unreadable)

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(workspace / "link" / "a.txt"))

    assert result["risk"] == "INVALID_PATH"


def _lstat_denied_for(monkeypatch, denied: Path) -> None:
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        if os.path.normcase(os.fspath(path)) == os.path.normcase(str(denied)):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)


def test_a_part_that_is_there_but_cannot_be_read_is_invalid(workspace, monkeypatch):
    # Whether it is a link is unknown, and resolving would take it for a
    # plain directory: on Windows a junction can deny reading its
    # attributes and still be followed when a path through it is opened.
    (workspace / "d").mkdir()
    _lstat_denied_for(monkeypatch, workspace / "d" / "j")

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(workspace / "d" / "j" / "new.txt"))

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


def test_an_allowed_directory_that_cannot_be_read_is_not_used(workspace, monkeypatch):
    _lstat_denied_for(monkeypatch, workspace)

    assert SystemGuard(allowed_paths=[str(workspace)])._allowed_roots() == []


def test_a_missing_part_is_not_an_unreadable_one(workspace):
    assert system_guard._lstat_or_none(str(workspace / "missing")) is None
    assert system_guard._lstat_or_none(str(workspace / "data.json" / "x")) is None

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(workspace / "missing" / "new.txt"))

    assert result["verified"] is True


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions and access control lists")
def test_a_windows_junction_that_hides_its_attributes_is_refused(tmp_path, workspace):
    import subprocess

    user = os.environ.get("USERNAME", "")
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "d").mkdir()
    junction = workspace / "d" / "j"
    _make_junction(junction, outside)

    def icacls(*args):
        return subprocess.run(["icacls", *args], capture_output=True, text=True).returncode

    try:
        # Reading the junction's attributes, and listing its folder, denied:
        # opening a path through it only needs traverse, so it still works.
        if icacls(str(junction), "/L", "/deny", f"{user}:(RA)") or icacls(
            str(workspace / "d"), "/deny", f"{user}:(RD)"
        ):
            pytest.skip("icacls could not set the access control lists")
        with pytest.raises(PermissionError):
            os.lstat(junction)

        result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(str(junction / "new.txt"), "write")
        roots = SystemGuard(allowed_paths=[str(junction)])._allowed_roots()
    finally:
        icacls(str(workspace / "d"), "/remove:d", user)
        icacls(str(junction), "/L", "/remove:d", user)

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"
    assert roots == []


def test_the_walk_reads_nothing_it_may_not_read(tmp_path):
    (tmp_path / "t").mkdir()
    _make_dir_link(tmp_path / "l", tmp_path / "t")

    def nothing(_part):
        return False

    assert system_guard._links_stay_inside(str(tmp_path / "a"), nothing) == "SANDBOX_ESCAPE"
    assert system_guard._follow_link(str(tmp_path / "l"), nothing) == "SANDBOX_ESCAPE"


def test_the_walk_follows_windows_rules_when_running_on_windows(tmp_path, monkeypatch):
    (tmp_path / "t").mkdir()
    _make_dir_link(tmp_path / "l", tmp_path / "t")
    monkeypatch.setattr(system_guard, "_ON_WINDOWS", True)

    assert system_guard._links_stay_inside(str(tmp_path / "a" / ".." / "b"), lambda _part: True) is None
    link = str(tmp_path / "l")
    assert system_guard._link_target(link, os.readlink(link)) == os.path.normpath(str(tmp_path / "t"))


@pytest.mark.parametrize(
    ("written", "depends"),
    [
        ("..\\x", True),
        ("a\\..\\x", True),
        ("../x", True),
        ("D:x", True),
        ("\\x", True),
        ("/x", True),
        ("sub\\x", False),
        ("x", False),
        ("...", False),
        ("x..", False),
        ("C:\\x", False),
        ("C:\\a\\..\\x", False),
        ("\\\\?\\C:\\x", False),
        ("\\\\server\\share\\x", False),
        ("\\\\?\\UNC\\server\\share\\x", False),
    ],
)
def test_windows_link_targets_read_from_the_route_that_reached_them(written, depends):
    assert system_guard._target_depends_on_route(written) is depends


def _make_relative_dir_link(link: Path, written: str) -> None:
    try:
        os.symlink(written, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this system cannot create a relative symbolic link")


def test_on_windows_a_climbing_relative_link_after_another_link_is_not_followed(workspace, monkeypatch):
    # Windows reads "../.." in "rel" from "workspace/j", the path that
    # reached it, not from "workspace/p/p", where "j" leads: the walk
    # cannot tell which it will be, so it follows neither.
    deep = workspace / "p" / "p"
    deep.mkdir(parents=True)
    _make_dir_link(workspace / "j", deep)
    _make_relative_dir_link(deep / "rel", os.path.join(os.pardir, os.pardir, "x"))
    (workspace / "x").mkdir()
    monkeypatch.setattr(system_guard, "_ON_WINDOWS", True)

    def anywhere(_part):
        return True

    assert system_guard._links_stay_inside(str(workspace / "j" / "rel" / "k"), anywhere) == "INVALID_PATH"
    # Reached directly, "rel" is read from its own folder on every system.
    assert system_guard._links_stay_inside(str(deep / "rel" / "k"), anywhere) is None


@pytest.mark.skipif(os.name != "nt", reason="Windows reads relative links from the route")
def test_a_windows_relative_link_through_a_junction_is_refused_before_it_is_resolved(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    deep = ws / "p" / "p"
    deep.mkdir(parents=True)
    _make_junction(ws / "j", deep)
    _make_relative_dir_link(deep / "rel", "..\\..\\probe")
    resolved = []
    real_realpath = os.path.realpath

    def recording_realpath(path, *args, **kwargs):
        resolved.append(os.fspath(path))
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", recording_realpath)

    result = SystemGuard(allowed_paths=[str(ws)]).verify_file_access(str(ws / "j" / "rel" / "f.txt"))

    assert result["risk"] == "INVALID_PATH"
    through = os.path.normcase(str(ws / "j"))
    assert not any(os.path.normcase(path).startswith(through) for path in resolved), resolved


@pytest.mark.parametrize(
    ("target", "plain"),
    [
        ("\\\\?\\C:\\ws\\t", "C:\\ws\\t"),
        ("\\\\?\\UNC\\server\\share\\y", "\\\\server\\share\\y"),
        ("C:\\ws\\t", "C:\\ws\\t"),
        ("t", "t"),
    ],
)
def test_windows_long_path_prefixes_are_read_as_plain_paths(target, plain):
    assert system_guard._without_long_path_prefix(target) == plain


def test_is_inside_compares_whole_parts_exactly(tmp_path):
    root = str(tmp_path / "ws")
    work = str(tmp_path / "work")
    filesystem_root = os.path.abspath(os.sep)

    assert system_guard._is_inside(root, root)
    assert system_guard._is_inside(root, root + os.sep + "a")
    assert not system_guard._is_inside(root, root + "-exfil" + os.sep + "a")
    assert not system_guard._is_inside(root, str(tmp_path / "WS" / "a"))
    assert not system_guard._is_inside(work, str(tmp_path / ("wor" + chr(0x212A)) / "a"))
    assert system_guard._is_inside(filesystem_root, os.path.join(filesystem_root, "a"))


def test_a_missing_allowed_directory_must_keep_its_name(tmp_path):
    missing = str(tmp_path / "missing-a")
    existing = tmp_path / "here"
    existing.mkdir()

    assert system_guard._resolves_in_place(missing, missing)
    assert not system_guard._resolves_in_place(missing, str(tmp_path / "missing-b"))
    assert not system_guard._resolves_in_place(missing, str(existing))


# --- forbidden patterns hold for every spelling of the path ------------------


@pytest.mark.parametrize("rel", [".git//config", ".git/./config", "sub/../.git/config"])
def test_a_forbidden_file_inside_is_refused_however_it_is_spelt(workspace, rel):
    (workspace / ".git").mkdir()
    (workspace / "sub").mkdir()
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace) + os.sep + rel)

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


def test_a_link_to_a_forbidden_file_inside_is_refused(workspace):
    (workspace / ".env").write_text("TOKEN=x")
    _make_file_link(workspace / "settings.txt", workspace / ".env")
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace / "settings.txt"))

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


@pytest.mark.parametrize("path", ["/etc/./passwd", "/etc//shadow", "/var//log/auth.log", "/etc/x/../passwd"])
def test_with_the_root_allowed_a_respelt_system_file_is_refused(path):
    guard = SystemGuard(allowed_paths=[os.path.abspath(os.sep)])

    result = guard.verify_file_access(path)

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


@pytest.mark.parametrize(
    ("allowed", "path"),
    [("/etc", "/etc//passwd"), ("/etc", "/etc/./shadow"), ("/var", "/var//log/auth.log"), ("/", "/root//.bashrc")],
)
def test_an_absolute_pattern_reaching_below_the_allowed_directory_is_refused(allowed, path):
    if os.path.islink(allowed):
        pytest.skip(f"{allowed} is a link here (macOS): a linked directory is not used")
    result = SystemGuard(allowed_paths=[allowed]).verify_file_access(path)

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


@pytest.mark.parametrize("rel", [".ssh/authorized_keys", "sub/.ssh/id_ed25519", ".ssh"])
def test_an_ssh_directory_at_any_depth_is_refused(tmp_path, monkeypatch, rel):
    monkeypatch.chdir(tmp_path)

    result = SystemGuard(allowed_paths=["."]).verify_file_access(rel)

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


@pytest.mark.parametrize("dir_name", ["root", ".env-project", "var"])
def test_the_allowed_directory_own_name_does_not_refuse_its_files(tmp_path, monkeypatch, dir_name):
    project = tmp_path / dir_name / "log"
    project.mkdir(parents=True)
    monkeypatch.chdir(project)

    result = SystemGuard(allowed_paths=["."]).verify_file_access("data.json")

    assert result["verified"] is True


@pytest.mark.parametrize(
    "rel",
    ["var/log/dev.log", "root/index.html", "roots.txt", "rootCA.crt", "etc/passwd.example",
     "~$report.docx", "~tmp.txt", "sub/~cache/x.txt"],
)
def test_ordinary_names_inside_the_allowed_directory_are_allowed(tmp_path, monkeypatch, rel):
    # Absolute patterns ("/var/log", "/root") name system locations, not
    # folders of the same name inside the allowed directory.
    monkeypatch.chdir(tmp_path)

    result = SystemGuard(allowed_paths=["."]).verify_file_access(rel)

    assert result["verified"] is True, result


@pytest.mark.parametrize("pattern", [r"^/etc/passwd", r"(?:/etc/passwd)", r"\/etc\/passwd", r"(?i)/etc/passwd"])
@pytest.mark.parametrize("allowed", ["/", "/etc"])
def test_a_custom_pattern_however_written_holds_for_a_respelt_path(pattern, allowed):
    if os.path.islink(allowed):
        pytest.skip(f"{allowed} is a link here (macOS): a linked directory is not used")
    guard = SystemGuard(allowed_paths=[allowed], forbidden_path_patterns=[pattern])

    result = guard.verify_file_access("/etc//passwd")

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


# --- paths this check cannot resolve to one file -----------------------------


@pytest.mark.parametrize("path", ["~", "~/notes.txt", "~/.aws/credentials", "~root/x", "~" + os.sep + "x"])
def test_a_home_directory_path_is_refused(tmp_path, monkeypatch, path):
    monkeypatch.chdir(tmp_path)

    result = SystemGuard().verify_file_access(path)

    assert result["verified"] is False
    assert result["risk"] in {"INVALID_PATH", "FORBIDDEN_PATH"}


def test_a_literal_tilde_directory_below_the_working_directory_is_allowed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = SystemGuard(allowed_paths=["."]).verify_file_access("./~/notes.txt")

    assert result["verified"] is True


@pytest.mark.parametrize("path", ["data" + NUL + ".json", b"data.json"])
def test_a_path_with_nul_or_bytes_is_invalid(workspace, path):
    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(path)

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


@pytest.mark.parametrize("path", ["", None])
def test_an_empty_path_is_refused(workspace, path):
    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(path)

    assert result["verified"] is False
    assert result["risk"] == "EMPTY_PATH"


def _path_of_length(base: str, length: int) -> str:
    """``base`` plus parts of at most 100 characters, ``length`` characters long."""
    path = base
    while len(path) < length:
        room = length - len(path) - 1
        path += "a" if room < 1 else os.sep + "a" * min(100, room)
    return path


def test_a_path_up_to_the_length_bound_is_checked_and_one_over_is_refused(workspace):
    guard = SystemGuard(allowed_paths=[str(workspace)])
    under = _path_of_length(str(workspace), MAX_PATH_CHARS - 1)
    at_bound = under + "a"

    assert len(at_bound) == MAX_PATH_CHARS
    assert guard.verify_file_access(under)["verified"] is True
    # At the bound the length rule lets it through. Linux cannot name a
    # path this long (its limit counts the closing NUL), so there reading
    # it fails and the path is refused all the same.
    at = guard.verify_file_access(at_bound)
    assert at["verified"] is True or (os.name != "nt" and at["risk"] == "INVALID_PATH")
    assert at.get("message") != "Path is too long."
    over = guard.verify_file_access(at_bound + "a")
    assert over["verified"] is False
    assert over["risk"] == "INVALID_PATH"
    assert over["message"] == "Path is too long."


def test_a_path_with_too_many_parts_is_refused_before_it_is_resolved(workspace, monkeypatch):
    resolved = []
    real_realpath = os.path.realpath

    def recording_realpath(path, *args, **kwargs):
        resolved.append(os.fspath(path))
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", recording_realpath)
    guard = SystemGuard(allowed_paths=[str(workspace)])
    deep = str(workspace) + (os.sep + "a") * (MAX_PATH_PARTS + 1)
    shallow = str(workspace) + (os.sep + "a") * 20

    result = guard.verify_file_access(deep)

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"
    assert deep not in resolved
    assert guard.verify_file_access(shallow)["verified"] is True


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot remove the working directory")
def test_a_removed_working_directory_leaves_the_other_directories(tmp_path, monkeypatch, workspace):
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    guard = SystemGuard(allowed_paths=[".", str(workspace)])

    assert guard.verify_file_access(str(workspace / "data.json"))["verified"] is True
    assert guard.verify_file_access("data.json")["verified"] is False


@pytest.mark.parametrize("length", [1, 200, 255, 300])
def test_a_long_sibling_name_is_outside(workspace, length):
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace) + "x" * length + os.sep + "secret.txt")

    assert result["verified"] is False


def test_dot_is_the_working_directory_at_the_time_of_the_check(tmp_path, monkeypatch):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.chdir(first)
    guard = SystemGuard(allowed_paths=["."])
    monkeypatch.chdir(second)

    assert guard.verify_file_access(str(second / "a.txt"))["verified"] is True
    assert guard.verify_file_access(str(first / "a.txt"))["verified"] is False


def test_a_path_object_is_read_once(workspace):
    class Shifting:
        """Gives a harmless name first, then a forbidden one."""

        def __init__(self):
            self.calls = 0

        def __fspath__(self):
            self.calls += 1
            return str(workspace / ("notes.txt" if self.calls == 1 else ".env"))

    shifting = Shifting()

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(shifting)

    assert shifting.calls == 1
    assert result["verified"] is True
    assert result["resolved_path"] == os.path.realpath(workspace / "notes.txt")


@pytest.mark.parametrize(
    ("entry", "error"), [("a" + NUL + "b", ValueError), (None, TypeError), (42, TypeError), (b"/tmp", TypeError)]
)
def test_an_allowed_directory_that_is_not_a_path_is_an_error(entry, error):
    with pytest.raises(error, match="allowed_paths entries"):
        SystemGuard(allowed_paths=[entry])


def test_a_path_object_that_fails_is_invalid(workspace):
    class Failing:
        def __fspath__(self):
            raise ValueError("no path")

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(Failing())

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


def test_named_parts_are_counted_up_to_the_bound(workspace):
    base = system_guard._part_count(str(workspace))
    at_bound = str(workspace) + (os.sep + "d") * (MAX_PATH_PARTS - base)
    guard = SystemGuard(allowed_paths=[str(workspace)])

    assert system_guard._part_count(at_bound) == MAX_PATH_PARTS
    assert guard.verify_file_access(at_bound)["verified"] is True
    assert guard.verify_file_access(at_bound + os.sep + "d")["risk"] == "INVALID_PATH"


def test_dot_parts_as_given_count_toward_the_bound(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = SystemGuard(allowed_paths=["."]).verify_file_access("./" * (MAX_PATH_PARTS + 1) + "a.txt")

    assert result["risk"] == "INVALID_PATH"


@pytest.mark.parametrize("rel", [".g" + chr(0x200C) + "it/config", ".e" + chr(0x200D) + "nv", "a/i" + chr(0xFEFF) + "d_rsa"])
def test_a_forbidden_name_with_invisible_format_characters_is_refused(tmp_path, monkeypatch, rel):
    # HFS+ leaves such characters out of names: ".g<ZWNJ>it" is ".git" there.
    monkeypatch.chdir(tmp_path)

    result = SystemGuard(allowed_paths=["."]).verify_file_access(rel)

    assert result["verified"] is False
    assert result["risk"] == "FORBIDDEN_PATH"


@pytest.mark.parametrize("value", [42, object(), ["a.txt"]])
def test_a_value_that_is_not_a_path_is_invalid(workspace, value):
    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(value)

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


def test_paths_that_cannot_be_compared_are_not_inside_each_other():
    # A relative path against an absolute one (or another drive on Windows)
    assert system_guard._is_within(os.path.abspath(os.sep), "relative") is False


@pytest.mark.parametrize("failing", ["abspath", "realpath"])
def test_a_path_the_system_cannot_resolve_is_invalid(workspace, monkeypatch, failing):
    target = str(workspace / "data.json")
    real = getattr(os.path, failing)

    def refusing(path, *args, **kwargs):
        if os.fspath(path) == target:
            raise OSError("cannot resolve")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os.path, failing, refusing)

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(target)

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


def test_the_refusal_message_shows_the_path_escaped(workspace):
    # The message may be printed to a terminal (QWEDLocal does): a newline or
    # an escape sequence from the path must not reach it as written.
    escape = chr(27) + "[2J"
    path = str(workspace) + "-x" + os.sep + "a" + chr(10) + escape + ".txt"

    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(path)

    assert result["risk"] == "SANDBOX_ESCAPE"
    assert chr(10) not in result["message"]
    assert chr(27) not in result["message"]


def test_a_link_to_a_missing_directory_is_not_an_allowed_directory(tmp_path):
    missing = tmp_path / "gone" / "ws"
    try:
        os.symlink(missing, tmp_path / "ws", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this system cannot create a symbolic link")
    guard = SystemGuard(allowed_paths=[str(tmp_path / "ws")])

    assert guard._allowed_roots() == []
    assert guard.verify_file_access(str(tmp_path / "ws" / "x.txt"))["verified"] is False


def test_a_pathlib_path_inside_is_allowed(workspace):
    result = SystemGuard(allowed_paths=[str(workspace)]).verify_file_access(workspace / "data.json")

    assert result["verified"] is True


# --- what the caller configures ----------------------------------------------


def test_an_empty_allowed_list_allows_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    guard = SystemGuard(allowed_paths=[])

    for path in ["data.json", "/tmp/x", str(tmp_path / "x")]:
        result = guard.verify_file_access(path)
        assert result["verified"] is False
        assert result["risk"] == "SANDBOX_ESCAPE"


@pytest.mark.parametrize("allowed", ["/tmp", b"/tmp", Path("/tmp")])
def test_a_single_path_instead_of_a_list_is_a_type_error(allowed):
    with pytest.raises(TypeError, match="list of directories"):
        SystemGuard(allowed_paths=allowed)


def test_the_default_dot_is_not_used_in_a_filesystem_root(monkeypatch):
    monkeypatch.chdir(os.path.abspath(os.sep))

    by_default = SystemGuard().verify_file_access("qwed-wfx7-probe.txt")
    named = SystemGuard(allowed_paths=["."]).verify_file_access("qwed-wfx7-probe.txt")

    assert by_default["verified"] is False
    assert by_default["risk"] == "SANDBOX_ESCAPE"
    assert named["verified"] is True


def test_a_named_filesystem_root_allows_paths_below_it():
    root = os.path.abspath(os.sep)
    guard = SystemGuard(allowed_paths=[root])

    assert guard.verify_file_access(os.path.join(root, "srv", "data.txt"))["verified"] is True
    assert guard.verify_file_access(root)["verified"] is True


# --- controls ----------------------------------------------------------------


def test_paths_inside_are_allowed(tmp_path, monkeypatch, workspace):
    monkeypatch.chdir(tmp_path)
    guard = SystemGuard(allowed_paths=[str(workspace), "./workspace"])

    for path in [str(workspace / "data.json"), str(workspace), str(workspace) + os.sep,
                 "./workspace/data.json", "workspace/new/dir/file.txt", "workspace//sub/./file.txt"]:
        result = guard.verify_file_access(path)
        assert result["verified"] is True, path


@pytest.mark.skipif(os.name == "nt" or os.path.islink("/tmp"),
                    reason="no /tmp on Windows; /tmp is a link here (macOS): a linked directory is not used")
def test_a_named_tmp_still_allows_its_own_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert SystemGuard(allowed_paths=["/tmp"]).verify_file_access("/tmp/report.txt")["verified"] is True


@pytest.mark.skipif(os.name == "nt", reason="Windows mode bits do not say who may write")
def test_no_default_is_used_under_a_directory_every_user_can_write(tmp_path, monkeypatch):
    # A shared directory, as /tmp is: another user could have made the
    # working directory's workspace, or could make it while it is missing,
    # and put files there. A caller who names a directory decides.
    shared = tmp_path / "shared"
    workspace = shared / "workspace"
    private = shared / ".ssh" / "work"
    workspace.mkdir(parents=True)
    private.mkdir(parents=True)
    shared.chmod(0o1777)
    workspace.chmod(0o755)
    private.chmod(0o700)

    monkeypatch.chdir(shared)
    by_default = SystemGuard()
    for path in ["report.txt", "workspace/report.txt", "workspace/new/report.txt"]:
        assert by_default.verify_file_access(path)["risk"] == "SANDBOX_ESCAPE", path
    assert SystemGuard(allowed_paths=["."]).verify_file_access("report.txt")["verified"] is True
    assert SystemGuard(allowed_paths=["./workspace"]).verify_file_access("workspace/report.txt")["verified"] is True

    # A private working directory below it is no default either, also where
    # a forbidden folder sits between the two.
    monkeypatch.chdir(private)
    assert SystemGuard().verify_file_access("notes.txt")["risk"] == "SANDBOX_ESCAPE"


def test_a_default_another_user_could_have_made_is_not_used(tmp_path, monkeypatch):
    # The rule applies to the defaults only, and on every system.
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(project)
    cwd = os.path.realpath(".")
    monkeypatch.setattr(system_guard, "_open_to_others", lambda path: os.path.normcase(path) == os.path.normcase(cwd))

    assert SystemGuard().verify_file_access("report.txt")["risk"] == "SANDBOX_ESCAPE"
    assert SystemGuard(allowed_paths=["."]).verify_file_access("report.txt")["verified"] is True
    # The default ./workspace is still used when it is not open to others.
    assert SystemGuard().verify_file_access("workspace/report.txt")["verified"] is True


def test_open_to_others_reads_the_mode_bits_up_to_the_root(monkeypatch):
    leaf = os.path.join(os.sep, "srv", "app", "proj")
    parent = os.path.dirname(leaf)
    modes = {}

    def fake_stat(path, *args, **kwargs):
        mode = modes.get(os.fspath(path), 0o755)
        if isinstance(mode, Exception):
            raise mode
        return SimpleNamespace(st_mode=stat.S_IFDIR | mode)

    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(system_guard, "_ON_WINDOWS", False)
    cases = [
        ({}, False),
        ({leaf: 0o775}, False),
        ({leaf: 0o777}, True),
        ({leaf: 0o703}, True),
        ({parent: 0o1777}, True),
        ({parent: 0o777}, True),
        ({os.path.dirname(parent): 0o1777}, True),
        ({leaf: FileNotFoundError(2, "missing")}, True),
        ({leaf: NotADirectoryError(20, "not a directory")}, True),
        ({parent: PermissionError(13, "denied")}, True),
    ]
    for case, expected in cases:
        modes.clear()
        modes.update(case)
        assert system_guard._open_to_others(leaf) is expected, case

    # Windows: the mode bits do not say who may write, so only a missing or
    # unreadable directory counts.
    monkeypatch.setattr(system_guard, "_ON_WINDOWS", True)
    for case, expected in [({leaf: 0o777}, False), ({parent: 0o1777}, False),
                           ({leaf: FileNotFoundError(2, "missing")}, True), ({parent: PermissionError(13, "denied")}, True)]:
        modes.clear()
        modes.update(case)
        assert system_guard._open_to_others(leaf) is expected, case


def test_the_defaults_are_workspace_and_the_working_directory():
    assert SystemGuard.DEFAULT_ALLOWED_PATHS == ["./workspace", "."]
    assert SystemGuard().allowed_paths == ["./workspace", "."]


def test_the_readme_example_is_still_refused_as_a_forbidden_path():
    result = SystemGuard().verify_file_access("~/.ssh/id_rsa")

    assert result["risk"] == "FORBIDDEN_PATH"


# --- Windows spellings ---------------------------------------------------------


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
def test_windows_alternate_stream_on_the_directory_name_is_outside(workspace):
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace) + ":hidden")

    assert result["verified"] is False


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
def test_windows_case_and_slashes_inside_are_allowed(workspace):
    guard = SystemGuard(allowed_paths=[str(workspace)])

    assert guard.verify_file_access(str(workspace).upper() + "\\data.json")["verified"] is True
    assert guard.verify_file_access(str(workspace).replace("\\", "/") + "/data.json")["verified"] is True


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
@pytest.mark.parametrize("prefix", ["\\\\?\\", "\\\\.\\", "\\??\\", "//?/", "//./", "/??/"])
def test_windows_device_and_namespace_forms_are_refused(workspace, prefix):
    root = os.path.abspath(os.sep)
    guard = SystemGuard(allowed_paths=[root, str(workspace)])

    for rest in [str(workspace) + "\\data.json", "GLOBALROOT\\Device\\HarddiskVolume1\\x", "UNC\\192.0.2.1\\share\\x"]:
        result = guard.verify_file_access(prefix + rest)
        assert result["verified"] is False, prefix + rest
        assert result["risk"] == "INVALID_PATH", prefix + rest


@pytest.mark.parametrize(
    ("path", "special"),
    [
        ("\\\\?\\C:\\ws\\a.txt", True),
        ("//./C:/ws/a.txt", True),
        ("\\??\\GLOBALROOT\\Device\\x", True),
        ("C:\\ws\\key.pem:x", True),
        ("ws/data.json::$DATA", True),
        ("C:\\ws\\CON", True),
        ("ws/com1.txt", True),
        ("ws\\nul .txt", True),
        ("ws\\LPT" + chr(0xB9), True),
        ("ws\\COM0", True),
        ("ws\\new.pem.", True),
        ("ws\\new.pem ", True),
        ("ws\\dir.\\x.txt", True),
        ("ws\\.\\a.txt", False),
        ("C:\\ws\\a.txt", False),
        ("C:ws\\a.txt", False),
        ("\\\\server\\share\\a.txt", False),
        ("ws\\CONSOLE.txt", False),
        ("ws\\com10.txt", False),
        ("ws/nullable.json", False),
    ],
)
def test_windows_special_forms_are_recognised_on_every_system(path, special):
    # The helper reads Windows path rules (ntpath) wherever it runs.
    assert system_guard._is_windows_special(path) is special


def test_windows_special_forms_are_refused_when_running_on_windows(workspace, monkeypatch):
    monkeypatch.setattr(system_guard, "_ON_WINDOWS", True)
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace) + "\\CON")

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
@pytest.mark.parametrize(
    "name",
    ["key.pem:x", "notes.txt:hidden", "data.json::$DATA", "CON", "con.", "com1.txt", "aux", "NUL .txt",
     "LPT" + chr(0xB9), "COM0", "lpt0.log", "CONOUT$", "new.pem.", "new.pem ", ".ssh.\\authorized_keys"],
)
def test_windows_streams_and_device_names_are_refused(workspace, name):
    guard = SystemGuard(allowed_paths=[str(workspace)])

    result = guard.verify_file_access(str(workspace) + "\\" + name)

    assert result["verified"] is False
    assert result["risk"] == "INVALID_PATH"


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
@pytest.mark.parametrize("name", ["CONSOLE.txt", "auxiliary.txt", "com10.txt", "nullable.json"])
def test_windows_names_that_only_start_like_a_device_are_allowed(workspace, name):
    guard = SystemGuard(allowed_paths=[str(workspace)])

    assert guard.verify_file_access(str(workspace) + "\\" + name)["verified"] is True


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
def test_windows_other_drive_or_share_is_outside(workspace):
    guard = SystemGuard(allowed_paths=[str(workspace)])
    drive = "Z:" if not str(workspace).upper().startswith("Z:") else "Y:"

    assert guard.verify_file_access(drive + "\\workspace\\data.json")["verified"] is False
    assert guard.verify_file_access("\\\\server\\share\\workspace\\data.json")["verified"] is False
    assert guard.verify_file_access("\\\\?\\" + str(workspace) + "-x\\data.json")["verified"] is False


# --- properties: the file system decides what "inside" means -----------------

NAME_CHARS = (
    "abcXYZ019-_.~+ !#$%&'()@[]^{}=,;"
    + ZERO_WIDTH_SPACE + WORD_JOINER + chr(0x200C) + chr(0x200D) + chr(0xFEFF)
    + CYRILLIC_A + chr(0x0435) + chr(0x043E) + chr(0x03BF) + FULLWIDTH_HYPHEN
    + chr(0xFF0E) + chr(0x00A0) + chr(0x3000) + chr(0x0301)
    # slashes that are not separators: fullwidth, division, big solidus
    + chr(0xFF0F) + chr(0x2215) + chr(0x29F8)
)
NAMES = st.text(alphabet=NAME_CHARS, min_size=1, max_size=8)


@pytest.fixture(scope="module")
def property_base():
    base = tempfile.mkdtemp(prefix="qwed_wfx7_")
    yield Path(base)
    shutil.rmtree(base, ignore_errors=True)


def _same_directory(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


@settings(max_examples=150, deadline=None)
@given(suffix=NAMES)
def test_property_a_sibling_directory_is_never_inside(property_base, suffix):
    root = property_base / "allowed"
    root.mkdir(exist_ok=True)
    sibling = Path(str(root) + suffix)
    try:
        sibling.mkdir(exist_ok=True)
    except OSError:
        return  # a name this file system refuses names no directory
    guard = SystemGuard(allowed_paths=[str(root)])

    result = guard.verify_file_access(str(sibling) + os.sep + "secret.txt")

    if _same_directory(sibling, root):
        # Windows drops trailing dots and spaces: that is the directory itself.
        return
    assert result["verified"] is False, (suffix, result)


@settings(max_examples=150, deadline=None)
@given(name=NAMES)
def test_property_a_child_is_allowed_exactly_when_no_rule_refuses_it(property_base, name):
    root = property_base / "allowed-children"
    root.mkdir(exist_ok=True)
    guard = SystemGuard(allowed_paths=[str(root)])

    result = guard.verify_file_access(str(root) + os.sep + name)

    # Worked out apart from the guard: with these characters only ".." can
    # match a default pattern, and Windows drops a trailing dot or space.
    readable = "".join(char for char in name if unicodedata.category(char) != "Cf")
    trailing = os.name == "nt" and name not in (".", "..") and name.endswith((".", " "))
    forbidden = ".." in name or ".." in readable

    if trailing:
        assert result["risk"] == "INVALID_PATH", (name, result)
    elif forbidden:
        assert result["risk"] == "FORBIDDEN_PATH", (name, result)
    else:
        assert result["verified"] is True, (name, result)
