"""#182: the repository tracks no file that its .gitignore ignores.

A file that is tracked and ignored at once gets nothing from the ignore rule:
git keeps tracking it, and a change to it is committed like any other.
``.coverage`` was one such file, and ``deploy/kubernetes/secret.yaml`` was
the last. The Secret template is now ``secret.yaml.example``, which
``kubectl apply -f deploy/kubernetes/`` does not apply, since it reads only
.yaml, .yml and .json files. The filled-in copy belongs outside the
checkout; ``deploy/kubernetes/secret.yaml`` stays ignored for a copy put
there anyway.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
KUBERNETES = ROOT / "deploy" / "kubernetes"
TEMPLATE = KUBERNETES / "secret.yaml.example"
GIT = shutil.which("git")
KUBECTL_SUFFIXES = {".yaml", ".yml", ".json"}


def _git(*args):
    return subprocess.run(
        [GIT, *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False
    )


def _in_this_repository():
    if GIT is None:
        return False
    top = _git("rev-parse", "--show-toplevel")
    return top.returncode == 0 and Path(top.stdout.strip()).resolve() == ROOT


IN_REPOSITORY = _in_this_repository()

# Run from a source tree without git, outside CI, the git checks skip. In CI
# they always run, and fail when there is no checkout, so a CI run never
# passes without them.
needs_git = pytest.mark.skipif(
    not IN_REPOSITORY and not os.environ.get("CI"),
    reason="needs a git checkout of this repository",
)


def _require_repository():
    assert IN_REPOSITORY, "these checks need git and a git checkout of this repository"


@needs_git
def test_no_tracked_file_is_ignored():
    _require_repository()
    # Only the repository's own .gitignore files count here, not a
    # developer's global excludes or .git/info/exclude.
    result = _git("ls-files", "--cached", "--ignored", "--exclude-per-directory=.gitignore")

    assert result.returncode == 0, result.stderr
    assert [line for line in result.stdout.splitlines() if line] == []


@needs_git
def test_a_secret_put_in_the_directory_is_ignored_by_the_repository():
    _require_repository()
    result = _git("check-ignore", "--verbose", "--no-index", "deploy/kubernetes/secret.yaml")

    assert result.returncode == 0, result.stderr
    source, _, pattern = result.stdout.split("\t")[0].split(":", 2)
    assert source == ".gitignore"
    assert not pattern.startswith("!")


@needs_git
def test_the_template_is_tracked():
    _require_repository()
    result = _git("ls-files", "--error-unmatch", "deploy/kubernetes/secret.yaml.example")

    assert result.returncode == 0, result.stderr


def test_the_template_is_a_secret_under_a_name_kubectl_does_not_apply():
    assert TEMPLATE.is_file()
    assert TEMPLATE.suffix not in KUBECTL_SUFFIXES
    assert yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))["kind"] == "Secret"


def test_the_template_copies_without_overwriting_a_filled_in_copy():
    commands = [
        line.lstrip("#").strip()
        for line in TEMPLATE.read_text(encoding="utf-8").splitlines()
        if line.lstrip("#").strip().startswith("cp ")
    ]

    assert commands
    for command in commands:
        assert command.startswith("cp -n ")
        assert not command.split()[-1].startswith("deploy/")


def test_kubectl_applies_no_secret_from_the_repository():
    # secret.yaml is an operator's own filled-in copy, if there is one.
    applied = [
        path
        for path in KUBERNETES.iterdir()
        if path.suffix in KUBECTL_SUFFIXES and path.name != "secret.yaml"
    ]
    kinds = {
        document["kind"]
        for path in applied
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if document
    }

    assert applied
    assert "Secret" not in kinds
