"""#466: the Action's default ``paths: '.'`` crashed every scan mode, and an
empty scan reported VERIFIED · ADMIT.

``Path('.').glob('.')`` raises (IndexError on 3.11 and 3.12, ValueError on
3.14), so scan-code, verify-shell and scan-secrets exited with a traceback
before scanning anything. A pattern that matched no files reported
``verified=true``. Now each mode uses its own default when ``paths`` is unset
or ``.``, a bad pattern is reported instead of raised, and a scan that
covered no files is UNVERIFIABLE · DENY.
"""

import json
import os
from pathlib import Path

import pytest
import yaml

import action_entrypoint as entry

REPO_ROOT = Path(__file__).resolve().parent.parent

MODES = {
    "scan-code": ("app.py", "x = 1\n"),
    "verify-shell": ("run.sh", "echo hello\n"),
    "scan-secrets": ("config.json", '{"name": "demo"}\n'),
}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    for name in ("PATHS", "OUTPUT_FORMAT", "FAIL_ON_FINDINGS"):
        monkeypatch.delenv(f"INPUT_{name}", raising=False)
    return root


def _run(monkeypatch, workspace, mode, paths=None, fail_on_findings="true", output_format=None):
    outputs = {}
    monkeypatch.setattr(entry, "set_output", outputs.__setitem__)
    monkeypatch.setenv("INPUT_ACTION", mode)
    monkeypatch.setenv("INPUT_FAIL_ON_FINDINGS", fail_on_findings)
    if paths is not None:
        monkeypatch.setenv("INPUT_PATHS", paths)
    if output_format is not None:
        monkeypatch.setenv("INPUT_OUTPUT_FORMAT", output_format)

    exit_code = 0
    try:
        entry.main()
    except SystemExit as exc:
        exit_code = exc.code
    return exit_code, outputs


def _write(workspace, name, content):
    path = workspace / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _symlink(link, target, target_is_directory=False):
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks are not available here: {exc}")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("paths", [None, "", ".", "./", " . "], ids=["unset", "empty", "dot", "dot-slash", "dot-padded"])
def test_default_paths_scan_the_mode_default(monkeypatch, workspace, mode, paths):
    _write(workspace, *MODES[mode])

    exit_code, out = _run(monkeypatch, workspace, mode, paths)

    assert exit_code == 0
    assert out["verdict"] == "VERIFIED"
    assert out["admission"] == "ADMIT"
    assert out["files_scanned"] == "1"
    assert out["proof_ref"].startswith("sha256:")


@pytest.mark.parametrize("mode", MODES)
def test_a_pattern_matching_nothing_is_unverifiable_and_denied(monkeypatch, workspace, mode):
    _write(workspace, *MODES[mode])

    exit_code, out = _run(monkeypatch, workspace, mode, "src/**/*.nothing")

    assert exit_code == 1
    assert out["verified"] == "false"
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"
    assert out["files_scanned"] == "0"
    assert out["proof_ref"] == ""


@pytest.mark.parametrize("mode", MODES)
def test_an_empty_workspace_is_unverifiable_and_denied(monkeypatch, workspace, mode):
    exit_code, out = _run(monkeypatch, workspace, mode)

    assert exit_code == 1
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"


def test_an_empty_scan_still_denies_without_failing_the_step(monkeypatch, workspace):
    exit_code, out = _run(monkeypatch, workspace, "scan-code", "missing/*.py", fail_on_findings="false")

    assert exit_code == 0
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"


def test_scan_secrets_does_not_swap_in_other_files_for_an_empty_match(monkeypatch, workspace):
    # The old fallback scanned the common secret files instead and admitted
    # them, which is a claim about files the caller did not ask for.
    _write(workspace, *MODES["scan-secrets"])

    _, out = _run(monkeypatch, workspace, "scan-secrets", "deploy/*.env")

    assert out["verdict"] == "UNVERIFIABLE"
    assert out["files_scanned"] == "0"


@pytest.mark.parametrize("pattern", ["/etc/*", "../*"], ids=["absolute", "parent"])
def test_a_pattern_outside_the_workspace_is_reported_not_raised(monkeypatch, workspace, pattern):
    _write(workspace, *MODES["scan-code"])
    (workspace.parent / "outside.py").write_text("x = 1\n")

    exit_code, out = _run(monkeypatch, workspace, "scan-code", f"**/*.py,{pattern}")

    assert exit_code == 1
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"


def test_a_file_that_cannot_be_parsed_is_not_counted(monkeypatch, workspace):
    _write(workspace, "broken.py", "def (:\n")

    _, out = _run(monkeypatch, workspace, "scan-code")

    assert out["files_scanned"] == "0"
    assert out["verdict"] == "UNVERIFIABLE"


def test_one_unparseable_file_denies_an_otherwise_clean_scan(monkeypatch, workspace):
    # A partial scan proves nothing about the files it skipped.
    _write(workspace, *MODES["scan-code"])
    _write(workspace, "broken.py", "def (:\n")

    exit_code, out = _run(monkeypatch, workspace, "scan-code")

    assert exit_code == 1
    assert out["files_scanned"] == "1"
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"
    assert out["proof_ref"] == ""


@pytest.mark.parametrize("mode", MODES)
def test_one_unreadable_file_denies_an_otherwise_clean_scan(monkeypatch, workspace, mode):
    name, content = MODES[mode]
    _write(workspace, name, content)
    _write(workspace, "locked" + Path(name).suffix, content)
    real_read_text = Path.read_text

    def read_text(self, *args, **kwargs):
        if self.name.startswith("locked"):
            raise PermissionError("denied")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)

    exit_code, out = _run(monkeypatch, workspace, mode)

    assert exit_code == 1
    assert out["files_scanned"] == "1"
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"


def test_findings_are_still_denied(monkeypatch, workspace):
    _write(workspace, "bad.py", "eval('1')\n")

    exit_code, out = _run(monkeypatch, workspace, "scan-code")

    assert exit_code == 1
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"
    assert out["findings_count"] == "1"


def test_overlapping_patterns_count_a_file_once(monkeypatch, workspace):
    _write(workspace, *MODES["scan-code"])

    _, out = _run(monkeypatch, workspace, "scan-code", "**/*.py,*.py,app.py")

    assert out["files_scanned"] == "1"
    assert out["verdict"] == "VERIFIED"


def test_the_verification_context_says_why_an_empty_scan_was_denied(monkeypatch, workspace):
    _, out = _run(monkeypatch, workspace, "verify-shell", "nothing/*.sh", output_format="json")

    vc = json.loads(out["verification_context"])
    assert vc["verdict"] == "UNVERIFIABLE"
    assert vc["context"]["decision"]["admission"] == "DENY"
    assert "nothing was scanned" in vc["object"]["formal_statement"]
    assert vc["context"]["evidence"]["evidence"]["files_scanned"] == 0
    assert vc["context"]["evidence"]["proof_ref"] is None


def test_expand_paths_reports_invalid_patterns():
    files, errors = entry.expand_paths("/etc/*", entry.CODE_PATTERNS)

    assert files == []
    assert len(errors) == 1
    assert "/etc/*" in errors[0]


def test_a_symlinked_directory_outside_the_workspace_is_not_an_error(monkeypatch, workspace):
    # Only files that would be scanned are checked against the workspace.
    outside = workspace.parent / "elsewhere.py"
    outside.mkdir()
    _symlink(workspace / "linked.py", outside, target_is_directory=True)
    _write(workspace, *MODES["scan-code"])

    exit_code, out = _run(monkeypatch, workspace, "scan-code")

    assert exit_code == 0
    assert out["verdict"] == "VERIFIED"


def test_a_symlinked_file_outside_the_workspace_is_named(workspace):
    outside = workspace.parent / "elsewhere.json"
    outside.write_text("{}")
    _symlink(workspace / "linked.json", outside)

    files, errors = entry.expand_paths("", entry.CONFIG_FILE_PATTERNS)

    assert files == []
    assert len(errors) == 1
    assert "linked.json" in errors[0]


def test_a_link_with_another_name_does_not_hide_the_file_it_points_to(monkeypatch, workspace):
    # alias.txt -> bad.py: de-duplicating before the .py filter would keep the
    # alias, drop bad.py, and then skip the alias for its suffix.
    _write(workspace, "bad.py", "eval('1')\n")
    _write(workspace, *MODES["scan-code"])
    _symlink(workspace / "alias.txt", workspace / "bad.py")

    exit_code, out = _run(monkeypatch, workspace, "scan-code", "alias.txt,**/*.py")

    assert exit_code == 1
    assert out["findings_count"] == "1"
    assert out["files_scanned"] == "2"


def test_action_yml_no_longer_defaults_paths_to_dot():
    spec = yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))

    assert spec["inputs"]["paths"]["default"] == ""
    assert "files_scanned" in spec["outputs"]
