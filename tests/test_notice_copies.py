"""The NOTICE copies that ship inside packages match the repository's NOTICE.

The Go module proxy serves only the sdk-go directory, plus the repository's
LICENSE, so the Go module keeps its own copy of NOTICE. The npm package lists
NOTICE in "files"; the publish workflow copies it in before packing.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def test_go_module_notice_matches_the_repository_notice():
    assert _text(ROOT / "sdk-go" / "NOTICE") == _text(ROOT / "NOTICE")


def test_npm_package_lists_the_licence_files():
    files = json.loads(_text(ROOT / "sdk-ts" / "package.json"))["files"]
    assert "LICENSE" in files
    assert "NOTICE" in files
