"""#182: the repository tracks no file that its .gitignore ignores.

A file that is tracked and ignored at once gets nothing from the ignore rule:
git keeps tracking it, and a change to it is committed like any other.
``.coverage`` was one such file, and ``deploy/kubernetes/secret.yaml`` was
the last. The Secret template is now ``secret.yaml.example``, the filled-in
``secret.yaml`` is ignored, and ``kubectl apply -f deploy/kubernetes/`` does
not apply the template, since it reads only .yaml, .yml and .json files.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
KUBERNETES = ROOT / "deploy" / "kubernetes"
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


needs_git = pytest.mark.skipif(
    not _in_this_repository(), reason="needs a git checkout of this repository"
)


@needs_git
def test_no_tracked_file_is_ignored():
    # Only the repository's own .gitignore files count here, not a
    # developer's global excludes or .git/info/exclude.
    result = _git("ls-files", "--cached", "--ignored", "--exclude-per-directory=.gitignore")

    assert result.returncode == 0, result.stderr
    assert [line for line in result.stdout.splitlines() if line] == []


@needs_git
def test_the_filled_in_secret_is_ignored_by_the_repository():
    result = _git("check-ignore", "--verbose", "--no-index", "deploy/kubernetes/secret.yaml")

    assert result.returncode == 0, result.stderr
    source, _, pattern = result.stdout.split("\t")[0].split(":", 2)
    assert source == ".gitignore"
    assert not pattern.startswith("!")


def test_the_template_is_tracked_under_a_name_kubectl_does_not_apply():
    template = KUBERNETES / "secret.yaml.example"

    assert template.is_file()
    assert template.suffix not in KUBECTL_SUFFIXES
    assert yaml.safe_load(template.read_text(encoding="utf-8"))["kind"] == "Secret"


def test_kubectl_applies_no_secret_from_the_repository():
    # secret.yaml is the operator's own filled-in copy, if there is one.
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
