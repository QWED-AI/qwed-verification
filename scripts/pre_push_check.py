#!/usr/bin/env python3
"""Checks to run before pushing: the ones QWED's CI and PR bots run.

Each check stands for one that CI or a bot ran on a recent PR, so a branch
reaches review with nothing left for them to find:

- size: QWED Security blocks a file over 100,000 characters (#524, #575).
  A documentation file over the limit is only reported, as the scan does.
- ruff: pyflakes findings (F) and syntax errors (E9) that the branch adds to
  the Python files it changes. Findings already on the base branch are not
  counted.
- secrets: a string literal set as, or passed as, a name such as api_key,
  token, secret or password, on a line the branch adds. Snyk Code reports
  these in tests too (#575). Reported, not fatal.
- tests: pytest as CI runs it (pytest.ini, ACTIVE_PROVIDER=mock), from an
  empty directory with an empty home, so no local .env or ~/.qwed state can
  supply a provider or a model (#575), and with this checkout's code first
  on the path. By default only the test files the branch changes run;
  --full runs every test.

Usage:
    python scripts/pre_push_check.py            # the quick checks
    python scripts/pre_push_check.py --full     # and the whole test suite
    git config core.hooksPath .githooks         # run it before each push
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import NamedTuple, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

# QWED Security blocks code over this many characters, and reports
# documentation over it.
SIZE_LIMIT = 100_000
SIZE_WARNING = 95_000
DOC_SUFFIXES = {".md", ".mdx", ".rst", ".txt"}

# Variables that select a provider or a model. A local value would let a test
# pass that fails in CI, where none is set.
PROVIDER_ENV = (
    "ACTIVE_PROVIDER",
    "OPENAI_MODEL",
    "AZURE_OPENAI_DEPLOYMENT",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEPLOYMENT",
    "CLAUDE_OPUS_DEPLOYMENT",
    "GEMINI_MODEL",
    "OLLAMA_MODEL",
    "CUSTOM_MODEL",
)

# name = "literal", name: "literal" or "name": "literal", for a name such as
# api_key, token, secret or password, or a constant such as FAKE_KEY. An
# f-string or a value with a space or a brace is not a literal key.
SECRET_LITERAL = re.compile(
    r"""\b(?P<name>\w*(?:api_?key|token|secret|password)\w*|(?-i:[A-Z][A-Z0-9_]*_KEY))["']?\s*[:=]\s*"""
    r"""(?P<quote>["'])(?P<value>[^"'{}\s]{8,})(?P=quote)""",
    re.IGNORECASE,
)


class Change(NamedTuple):
    """A file the branch adds, changes or renames."""

    path: str
    base_path: Optional[str]  # its path on the base branch; None when added


def run(
    args: list[str], cwd: Path, *, capture: bool = True, check: bool = True, env: Optional[dict[str, str]] = None
) -> subprocess.CompletedProcess:
    """Run a command with a fixed argument list and no shell. It is the one
    place this script starts a process: git, ruff or pytest."""
    return subprocess.run(args, cwd=cwd, env=env, check=check, capture_output=capture)


def git(*args: str) -> str:
    return run(["git", *args], REPO_ROOT).stdout.decode("utf-8")


def changed_files(base: str) -> list[Change]:
    """The files the branch adds, changes or renames, since it left ``base``."""
    changes = []
    for line in git("diff", "--name-status", "-M", f"{base}...HEAD").splitlines():
        status, *paths = line.split("\t")
        if status.startswith("A"):
            changes.append(Change(paths[0], None))
        elif status.startswith(("M", "R")):
            changes.append(Change(paths[-1], paths[0]))
    return changes


def blob_text(rev: str, path: str) -> Optional[str]:
    """The file at ``rev`` as text, or None for a binary file."""
    data = run(["git", "show", f"{rev}:{path}"], REPO_ROOT).stdout
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n")


def size_problem(path: str, chars: int) -> Optional[tuple[str, str]]:
    """("fail" | "warn", message) for a file near or over the scan's limit."""
    if chars > SIZE_LIMIT:
        if Path(path).suffix.lower() in DOC_SUFFIXES:
            return "warn", f"{path}: {chars:,} characters, over {SIZE_LIMIT:,} (reported, not blocked)"
        return "fail", f"{path}: {chars:,} characters, over QWED Security's {SIZE_LIMIT:,} limit"
    if chars > SIZE_WARNING and Path(path).suffix.lower() not in DOC_SUFFIXES:
        return "warn", f"{path}: {chars:,} characters, near the {SIZE_LIMIT:,} limit"
    return None


def check_size(changes: list[Change]) -> tuple[list[str], list[str]]:
    failures, warnings = [], []
    for change in changes:
        text = blob_text("HEAD", change.path)
        problem = None if text is None else size_problem(change.path, len(text))
        if problem:
            (failures if problem[0] == "fail" else warnings).append(problem[1])
    return failures, warnings


def ruff_findings(root: Path, paths: list[str]) -> Counter:
    """(path, code, message) for each F and E9 finding; lines are left out,
    so a finding the branch only moves is not new."""
    if not paths:
        return Counter()
    result = run(
        [sys.executable, "-m", "ruff", "check", "--select", "F,E9", "--no-cache",
         "--output-format", "json", "--exit-zero", *paths],
        root,
    )
    return Counter(
        (Path(item["filename"]).resolve().relative_to(root.resolve()).as_posix(), item["code"], item["message"])
        for item in json.loads(result.stdout or b"[]")
    )


def new_findings(head: Counter, base: Counter) -> list[tuple[str, str, str]]:
    return sorted((head - base).elements())


def check_ruff(changes: list[Change], base: str) -> list[str]:
    python = [change for change in changes if change.path.endswith(".py")]
    head = ruff_findings(REPO_ROOT, [change.path for change in python])
    with tempfile.TemporaryDirectory(prefix="qwed-pre-push-ruff-") as tmp:
        # The base versions, at their new paths, so the two sets compare.
        copied = []
        for change in python:
            if change.base_path:
                target = Path(tmp, change.path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(blob_text(base, change.base_path) or "", encoding="utf-8")
                copied.append(change.path)
        base_findings = ruff_findings(Path(tmp), copied)
    return [f"{path}: {code} {message}" for path, code, message in new_findings(head, base_findings)]


def added_lines(base: str) -> list[tuple[str, str]]:
    """(path, line) for each line the branch adds."""
    lines, path = [], None
    for line in git("diff", "-U0", "--no-color", f"{base}...HEAD").splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and path:
            lines.append((path, line[1:]))
    return lines


def secret_literals(lines: list[tuple[str, str]]) -> list[str]:
    return [
        f"{path}: {match.group('name')} is set to a string literal"
        for path, line in lines
        if path.endswith(".py")
        for match in SECRET_LITERAL.finditer(line)
    ]


def ci_environment(home: Path) -> dict[str, str]:
    """The environment CI runs the tests in: no provider or model of the
    developer's, ACTIVE_PROVIDER=mock, and an empty home.

    This checkout's code comes first on the path. The tests run from an
    empty directory, so without it they would import an installed qwed_sdk,
    or another checkout's code from an editable install.
    """
    env = {name: value for name, value in os.environ.items() if name not in PROVIDER_ENV}
    path = [str(REPO_ROOT / "src"), str(REPO_ROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    env.update(ACTIVE_PROVIDER="mock", HOME=str(home), USERPROFILE=str(home), PYTHONPATH=os.pathsep.join(path))
    return env


def run_tests(paths: list[str]) -> int:
    with tempfile.TemporaryDirectory(prefix="qwed-pre-push-tests-") as tmp:
        cwd, home = Path(tmp, "cwd"), Path(tmp, "home")
        cwd.mkdir()
        home.mkdir()
        return run(
            [sys.executable, "-m", "pytest", "--rootdir", str(REPO_ROOT), "-c", str(REPO_ROOT / "pytest.ini"),
             "-p", "no:cacheprovider", "-q", *[str(REPO_ROOT / path) for path in paths]],
            cwd, capture=False, check=False, env=ci_environment(home),
        ).returncode


def is_test_file(path: str) -> bool:
    name = Path(path).name
    return path.startswith("tests/") and name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="origin/main", help="the branch the PR goes into (default: origin/main)")
    parser.add_argument("--full", action="store_true", help="run every test, not only the changed test files")
    parser.add_argument("--skip", action="append", default=[], choices=["size", "ruff", "secrets", "tests"],
                        help="skip a check (repeatable)")
    args = parser.parse_args(argv)

    try:
        git("rev-parse", "--verify", "--quiet", f"{args.base}^{{commit}}")
    except subprocess.CalledProcessError:
        print(f"pre-push check: no commit {args.base!r}; fetch it (git fetch origin main) or pass --base")
        return 2
    changes = changed_files(args.base)
    failures: list[str] = []
    warnings: list[str] = []
    if git("status", "--porcelain", "--untracked-files=no").strip():
        warnings.append("uncommitted changes: the tests run on the working tree, not on what you push")

    if "size" not in args.skip:
        size_failures, size_warnings = check_size(changes)
        failures += size_failures
        warnings += size_warnings
    if "ruff" not in args.skip:
        try:
            failures += [f"ruff: {finding}" for finding in check_ruff(changes, args.base)]
        except subprocess.CalledProcessError as exc:
            last_line = (exc.stderr or b"").decode("utf-8", errors="replace").strip().splitlines()[-1:]
            reason = last_line[0] if last_line else f"exit status {exc.returncode}"
            warnings.append(f"ruff did not run ({reason}); install it with: pip install ruff")
    if "secrets" not in args.skip:
        warnings += secret_literals(added_lines(args.base))

    for message in warnings:
        print(f"WARN  {message}")
    for message in failures:
        print(f"FAIL  {message}")

    if "tests" not in args.skip:
        if args.full:
            tests = ["tests"]
        else:
            tests = [change.path for change in changes if is_test_file(change.path)]
            if not tests:
                print("NOTE  no test file changed; run with --full before asking for review")
        if tests and run_tests(tests) != 0:
            failures.append("tests failed")

    if failures:
        print(f"pre-push check: {len(failures)} problem(s); push with --no-verify to skip this hook")
        return 1
    print("pre-push check: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
