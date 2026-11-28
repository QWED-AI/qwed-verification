"""#184: Dependabot keeps every Dockerfile's base image up to date.

The docker entry read only the root ``Dockerfile``, so
``docker/crosshair-sandbox/Dockerfile``, which uses the same base image, was
left behind. Every Dockerfile in the repository must sit in a directory a
docker entry reads.

Dependabot expands glob patterns only under ``directories``; ``directory``
is a plain path. Matching here is per path segment and case-sensitive, so a
pattern never matches across a ``/`` and a test on Windows does not ignore
case. As in Ruby's ``Dir.glob``, which Dependabot uses, ``**`` followed by
another segment spans any number of directories, a ``**`` at the end
matches one segment, like ``*``, and no wildcard matches or crosses a name
that starts with a dot unless the pattern spells the dot.

The search covers the repository's own files: it skips caches, virtual
environments and installed packages, and any directory with a ``.git`` of
its own, which is another checkout (a nested repository or a worktree).
"""

import os
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
# Directories that are not the repository's own files: version control,
# virtual environments, caches, installed packages and local worktrees.
# Other dot directories, such as .devcontainer, are searched, and so is any
# other directory without a .git of its own.
SKIP_PARTS = {
    ".git", ".venv", "venv", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".hypothesis", ".claude", "__pycache__", "node_modules", "site-packages", "build", "dist",
}


# Dockerfile, Containerfile, server.Dockerfile, Dockerfile.dev: the name is
# the word itself, or the word joined to the rest by a dot.
DOCKERFILE_NAME = re.compile(r"^(?:[\w.-]+\.)?(?:docker|container)file(?:\.[\w.-]+)?$", re.IGNORECASE)


def _is_dockerfile(name):
    return bool(DOCKERFILE_NAME.match(name))


def _dockerfile_directories():
    found = set()
    for directory, subdirectories, files in os.walk(ROOT):
        subdirectories[:] = [
            d for d in subdirectories
            if d not in SKIP_PARTS and not (Path(directory) / d / ".git").exists()
        ]
        if any(_is_dockerfile(name) for name in files):
            parent = Path(directory).relative_to(ROOT).as_posix()
            found.add("/" if parent == "." else "/" + parent)
    return found


def _segments(path):
    return [part for part in path.split("/") if part]


def _glob_covers(directory, pattern):
    names, globs = _segments(directory), _segments(pattern)

    def visible(name, glob):
        # A wildcard does not match a leading dot unless the pattern has it.
        return not name.startswith(".") or glob.startswith(".")

    def match(i, j):
        if j == len(globs):
            return i == len(names)
        if globs[j] == "**" and j + 1 < len(globs):
            return any(
                match(k, j + 1)
                for k in range(i, len(names) + 1)
                if all(not name.startswith(".") for name in names[i:k])
            )
        segment = "*" if globs[j] == "**" else globs[j]
        return (
            i < len(names)
            and visible(names[i], segment)
            and fnmatchcase(names[i], segment)
            and match(i + 1, j + 1)
        )

    return match(0, 0)


def _covered(directory, entries):
    for entry in entries:
        if "directory" in entry and _segments(entry["directory"]) == _segments(directory):
            return True
        if any(_glob_covers(directory, pattern) for pattern in entry.get("directories", [])):
            return True
    return False


def _docker_entries():
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    return [entry for entry in config["updates"] if entry["package-ecosystem"] == "docker"]


@pytest.mark.parametrize("name, dockerfile", [
    ("Dockerfile", True), ("server.Dockerfile", True), ("Dockerfile.dev", True),
    ("Containerfile", True), ("api.dockerfile", True), (".dockerignore", False),
    ("docker-compose.yml", False), ("test_issue_184_dependabot_dockerfiles.py", False),
    ("dockerfiles", False),
])
def test_dockerfile_names(name, dockerfile):
    assert _is_dockerfile(name) is dockerfile


@pytest.mark.parametrize("directory, entry, covered", [
    ("/", {"directory": "/"}, True),
    ("/docker/crosshair-sandbox", {"directories": ["/", "/docker/crosshair-sandbox"]}, True),
    ("/docker/crosshair-sandbox", {"directories": ["/docker/*"]}, True),
    ("/docker/crosshair-sandbox", {"directories": ["/**/*"]}, True),
    ("/docker", {"directories": ["/**/*"]}, True),
    ("/docker/crosshair-sandbox", {"directories": ["/**"]}, False),
    ("/docker", {"directories": ["/**"]}, True),
    ("/.devcontainer", {"directories": ["/*"]}, False),
    ("/.devcontainer", {"directories": ["/**/*"]}, False),
    ("/.devcontainer/sub", {"directories": ["/**/sub"]}, False),
    ("/.devcontainer", {"directories": ["/.devcontainer"]}, True),
    ("/.devcontainer", {"directories": ["/.*"]}, True),
    ("/docker/crosshair-sandbox", {"directory": "/docker/*"}, False),
    ("/docker/crosshair-sandbox", {"directories": ["/*"]}, False),
    ("/docker/crosshair-sandbox", {"directories": ["/docker*"]}, False),
    ("/docker/crosshair-sandbox", {"directories": ["/Docker/crosshair-sandbox"]}, False),
    ("/docker/crosshair-sandbox", {"directory": "/"}, False),
])
def test_coverage_matching(directory, entry, covered):
    assert _covered(directory, [entry]) is covered


def test_the_search_skips_another_checkout_inside_the_repository(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    for sub in ("worktrees/topic", "nested", ".devcontainer"):
        (tmp_path / sub).mkdir(parents=True)
        (tmp_path / sub / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "worktrees" / "topic" / ".git").write_text("gitdir: elsewhere\n")
    (tmp_path / "nested" / ".git").mkdir()
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)

    assert _dockerfile_directories() == {"/", "/.devcontainer"}


def test_the_repository_has_both_dockerfiles():
    assert {"/", "/docker/crosshair-sandbox"} <= _dockerfile_directories()


def test_every_dockerfile_directory_has_a_docker_entry():
    entries = _docker_entries()
    missing = [d for d in sorted(_dockerfile_directories()) if not _covered(d, entries)]

    assert missing == []
