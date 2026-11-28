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
import re
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


def _header_steps():
    # The header's steps are the comment lines indented by three spaces; its
    # prose lines are not.
    return [
        line[len("#   "):].strip()
        for line in TEMPLATE.read_text(encoding="utf-8").splitlines()
        if line.startswith("#   ")
    ]


def _header_commands(verb):
    return [step for step in _header_steps() if step.startswith(verb + " ")]


def _outside_the_checkout(destination):
    # The header's commands run from the repository root.
    path = (ROOT / os.path.expanduser(destination)).resolve()
    return not path.is_relative_to(ROOT.resolve())


def test_the_template_copies_outside_the_checkout_without_overwriting():
    commands = _header_commands("cp")

    assert commands
    for command in commands:
        assert command.startswith("cp -n ")
        assert _outside_the_checkout(command.split()[-1]), command


def test_the_template_makes_each_copy_owner_only_before_it_is_filled_in():
    steps = _header_steps()
    for copy in _header_commands("cp"):
        destination = copy.split()[-1]
        at = steps.index(copy)
        # The path anywhere in a step, quoted or after < or >, but not as
        # part of a longer path.
        path = re.compile(r"(?<![\w./-])" + re.escape(destination) + r"(?![\w./-])")
        uses = [i for i, step in enumerate(steps) if path.search(step)]
        # Nothing uses the file before the copy, and the very next step
        # restricts it, so nothing reads or fills it in before that.
        assert uses[0] == at
        assert steps[at + 1] == f"chmod 600 {destination}"


@pytest.mark.parametrize("destination, outside", [
    ("../qwed-secret.yaml", True),
    ("../../elsewhere/qwed-secret.yaml", True),
    ("qwed-secret.yaml", False),
    ("deploy/kubernetes/secret.yaml", False),
    ("./deploy/../qwed-secret.yaml", False),
    ("deploy/../../qwed-secret.yaml", True),
])
def test_the_destination_check_resolves_against_the_repository_root(destination, outside):
    assert _outside_the_checkout(destination) is outside


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
