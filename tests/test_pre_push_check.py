"""scripts/pre_push_check.py: the checks CI and the PR bots run, before a push."""

import importlib.util
import os
import subprocess
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("pre_push_check", ROOT / "scripts" / "pre_push_check.py")
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

# Built at run time: written out, these lines are the very pattern that
# secret scanners report, in this file as anywhere else.
VALUE = "z" * 12
NAMES = {"api": "api" + "_key", "token": "auth" + "_token", "password": "pass" + "word", "constant": "FAKE" + "_KEY"}


def _git(repo, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main", *args],
        cwd=repo, check=True, capture_output=True,
    )


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A repository whose main branch has a.py, c.py and e.py."""
    _git(tmp_path, "init")
    for name in ("a.py", "c.py", "e.py"):
        (tmp_path / name).write_text("import os\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    _git(tmp_path, "checkout", "-b", "topic")
    monkeypatch.setattr(check, "REPO_ROOT", tmp_path)
    return tmp_path


def _commit(repo):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "change")


# --------------------------------------------------------------------------
# size: QWED Security's 100,000 character limit
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, chars, expected",
    [
        ("qwed_sdk/cli.py", 100_228, "fail"),  # what QWED Security blocked on #575
        ("qwed_sdk/cli.py", 98_562, "warn"),
        ("qwed_sdk/cli_model.py", 2_490, None),
        ("CHANGELOG.md", 122_293, "warn"),  # the scan reports documentation, it does not block it
        ("CHANGELOG.md", 99_000, None),
    ],
)
def test_size_problem(path, chars, expected):
    problem = check.size_problem(path, chars)

    assert (problem[0] if problem else None) == expected


def test_a_file_over_the_limit_fails_the_check(repo, capsys):
    (repo / "big.py").write_text("#" * 100_001, encoding="utf-8")
    _commit(repo)

    status = check.main(["--base", "main", "--skip", "ruff", "--skip", "tests"])

    assert status == 1
    assert "FAIL  big.py: 100,001 characters" in capsys.readouterr().out


# --------------------------------------------------------------------------
# changed files, and ruff findings the branch adds
# --------------------------------------------------------------------------


def test_changed_files_follow_adds_changes_and_renames(repo):
    (repo / "a.py").write_text("import os\nimport sys\n", encoding="utf-8")
    (repo / "b.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "c.py").rename(repo / "d.py")
    (repo / "e.py").unlink()
    _commit(repo)

    assert set(check.changed_files("main")) == {
        check.Change("a.py", "a.py"),
        check.Change("b.py", None),
        check.Change("d.py", "c.py"),
    }


def test_new_findings_leave_out_those_on_the_base_branch():
    finding = ("a.py", "F401", "`os` imported but unused")
    added = ("a.py", "F401", "`sys` imported but unused")

    assert check.new_findings(Counter([finding, added]), Counter([finding])) == [added]


def test_ruff_reports_only_what_the_branch_adds(repo):
    pytest.importorskip("ruff")
    (repo / "a.py").write_text("import os\nimport sys\n", encoding="utf-8")
    (repo / "c.py").rename(repo / "d.py")
    _commit(repo)

    findings = check.check_ruff(check.changed_files("main"), "main")

    assert findings == ["a.py: F401 `sys` imported but unused"]


def test_ruff_that_cannot_run_is_reported_not_failed(repo, monkeypatch, capsys):
    (repo / "b.py").write_text("x = 1\n", encoding="utf-8")
    _commit(repo)

    def no_ruff(*_args):
        raise subprocess.CalledProcessError(1, ["ruff"], stderr=b"No module named ruff\n")

    monkeypatch.setattr(check, "check_ruff", no_ruff)

    assert check.main(["--base", "main", "--skip", "tests"]) == 0
    assert "WARN  ruff did not run (No module named ruff)" in capsys.readouterr().out


# --------------------------------------------------------------------------
# secrets: string literals set as keys, tokens, secrets or passwords
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "template, name",
    [
        ('client = Client({name}="{value}")', "api"),
        ("    '{name}': '{value}',", "password"),
        ('{name} = "{value}"', "token"),
        ('{name} = "{value}"', "constant"),
    ],
)
def test_a_literal_key_is_reported(template, name):
    line = template.format(name=NAMES[name], value=VALUE)

    assert check.secret_literals([("tests/test_x.py", line)]) == [
        f"tests/test_x.py: {NAMES[name]} is set to a string literal"
    ]


@pytest.mark.parametrize(
    "line",
    [
        '{api}=os.getenv("OPENAI_API_KEY")',
        '{api}="sk-..."',  # a placeholder, too short to be a key
        '{constant} = f"unit-test-{{uuid5(NAMESPACE_URL, name).hex}}"',
        "{token} = None",
        'cache_key = "{value}"',
        '{password} = "two words here"',
    ],
)
def test_a_value_that_is_not_a_literal_key_is_not_reported(line):
    line = line.format(value=VALUE, **NAMES)

    assert check.secret_literals([("tests/test_x.py", line)]) == []


def test_the_secret_check_reads_python_only():
    line = f'{NAMES["api"]}="{VALUE}"'

    assert check.secret_literals([("docs/setup.md", line)]) == []


# --------------------------------------------------------------------------
# tests: the environment CI runs them in
# --------------------------------------------------------------------------


def test_the_tests_get_no_provider_or_model_of_the_developers(monkeypatch, tmp_path):
    monkeypatch.setenv("ACTIVE_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_MODEL", "a-local-model")

    env = check.ci_environment(tmp_path)

    assert env["ACTIVE_PROVIDER"] == "mock"
    assert "OPENAI_MODEL" not in env
    assert env["HOME"] == env["USERPROFILE"] == str(tmp_path)


def test_the_tests_import_this_checkouts_code_first(monkeypatch, tmp_path):
    monkeypatch.setenv("PYTHONPATH", "elsewhere")

    path = check.ci_environment(tmp_path)["PYTHONPATH"].split(os.pathsep)

    assert path == [str(check.REPO_ROOT / "src"), str(check.REPO_ROOT), "elsewhere"]


@pytest.mark.parametrize(
    "path, expected",
    [
        ("tests/test_cli_init.py", True),
        ("tests/guards/money_test.py", True),
        ("tests/conftest.py", False),
        ("scripts/test_qwed_integrity.py", False),
    ],
)
def test_is_test_file(path, expected):
    assert check.is_test_file(path) is expected


def test_an_unknown_base_stops_with_a_message(repo, capsys):
    assert check.main(["--base", "no-such-branch"]) == 2
    assert "no commit 'no-such-branch'" in capsys.readouterr().out
