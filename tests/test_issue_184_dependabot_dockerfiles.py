"""#184: Dependabot keeps every Dockerfile's base image up to date.

The docker entry read only the root ``Dockerfile``, so
``docker/crosshair-sandbox/Dockerfile``, which uses the same base image, was
left behind. Every Dockerfile in the repository must sit in a directory a
docker entry reads.
"""

from fnmatch import fnmatch
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SKIP_PARTS = {"node_modules", "site-packages", "venv", "build", "dist"}


def _dockerfile_directories():
    found = set()
    for path in ROOT.rglob("Dockerfile*"):
        parts = path.relative_to(ROOT).parts
        if any(part.startswith(".") or part in SKIP_PARTS for part in parts[:-1]):
            continue
        parent = path.parent.relative_to(ROOT).as_posix()
        found.add("/" if parent == "." else "/" + parent)
    return found


def _docker_entry_directories():
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    directories = []
    for entry in config["updates"]:
        if entry["package-ecosystem"] != "docker":
            continue
        directories.extend(entry.get("directories", []))
        if "directory" in entry:
            directories.append(entry["directory"])
    return [d.rstrip("/") or "/" for d in directories]


def test_the_repository_has_both_dockerfiles():
    assert {"/", "/docker/crosshair-sandbox"} <= _dockerfile_directories()


def test_every_dockerfile_directory_has_a_docker_entry():
    covered = _docker_entry_directories()
    missing = [
        directory
        for directory in sorted(_dockerfile_directories())
        if not any(fnmatch(directory, pattern) for pattern in covered)
    ]

    assert missing == []
