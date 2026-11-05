"""GHSA-hg73-j3qv-w4vh: the GitHub Action's scan-code mode reported
VERIFIED · ADMIT, zero findings and a passing badge for a file that reached
eval, os.system, subprocess and exec through a from-import, an alias,
importlib or getattr. Its local list matched names only as written and never
read a from-import.

scan-code now also runs CodeVerifier, the /verify/code engine, on each file,
and reads from-imports of the modules it names. Nothing is executed.
"""

import pytest

import action_entrypoint as entry


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    for name in ("PATHS", "OUTPUT_FORMAT", "FAIL_ON_FINDINGS"):
        monkeypatch.delenv(f"INPUT_{name}", raising=False)
    return root


def _scan(monkeypatch, workspace, files, fail_on_findings="true"):
    for name, content in files.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    outputs = {}
    monkeypatch.setattr(entry, "set_output", outputs.__setitem__)
    monkeypatch.setenv("INPUT_ACTION", "scan-code")
    monkeypatch.setenv("INPUT_FAIL_ON_FINDINGS", fail_on_findings)
    exit_code = 0
    try:
        entry.main()
    except SystemExit as exc:
        exit_code = exc.code
    return exit_code, outputs


ROUTES = {
    "from_import_alias": 'from builtins import eval as e\ne("1+1")\n',
    "from_import_call": 'from os import system\nsystem("id")\n',
    "importlib": 'import importlib\nimportlib.import_module("subprocess").check_output(["id"])\n',
    "getattr_builtins": 'getattr(__builtins__, "exec")("print(1)")\n',
    "stored_alias": 'import subprocess as sp\nrun = sp.run\nrun(["id"])\n',
}


@pytest.mark.parametrize("source", ROUTES.values(), ids=list(ROUTES))
def test_each_route_is_found_and_denied(monkeypatch, workspace, source):
    exit_code, out = _scan(monkeypatch, workspace, {"app.py": source})

    assert exit_code == 1
    assert out["verified"] == "false"
    assert int(out["findings_count"]) >= 1
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"
    assert "QWED-failed" in out["badge_url"]


def test_the_advisory_file_reports_every_call(monkeypatch, workspace):
    source = (
        "from builtins import eval as e\n"
        "from os import system\n"
        "import importlib\n"
        "\n"
        'e("1+1")\n'
        'system("id")\n'
        'importlib.import_module("subprocess").check_output(["id"])\n'
        'getattr(__builtins__, "exec")("print(1)")\n'
    )

    exit_code, out = _scan(monkeypatch, workspace, {"evasions.py": source})

    assert exit_code == 1
    assert out["verified"] == "false"
    assert int(out["findings_count"]) >= 4
    assert out["admission"] == "DENY"


def test_a_from_import_of_a_listed_module_is_a_finding_like_an_import(monkeypatch, workspace):
    _, imported = _scan(monkeypatch, workspace, {"a.py": "import shutil\n"})
    _, from_imported = _scan(monkeypatch, workspace, {"a.py": "from shutil import which\n"})

    assert imported["findings_count"] == "1"
    assert from_imported["findings_count"] == "1"


REPOSITORY_CODE = {
    "plain": "import json\n\n\ndef total(xs):\n    return sum(xs)\n\nprint(json.dumps(total([1, 2])))\n",
    "file_read": 'with open("data.txt") as f:\n    print(f.read())\n',
    "http": 'import requests\nr = requests.get("https://example.com")\n',
    "pathlib": 'from pathlib import Path\nprint(Path("a").exists())\n',
    "reflection": 'class A:\n    x = 1\n\nprint(getattr(A, "x", None), A().__class__.__name__, vars(A()) or A().__dict__)\n',
    "regex": 'import re\npattern = re.compile("a+")\n',
}


@pytest.mark.parametrize("source", REPOSITORY_CODE.values(), ids=list(REPOSITORY_CODE))
def test_ordinary_repository_code_is_still_admitted(monkeypatch, workspace, source):
    # File and network access and plain reflection are outside scan-code's
    # scope, as before; CodeVerifier's findings for them are not taken.
    exit_code, out = _scan(monkeypatch, workspace, {"app.py": source})

    assert exit_code == 0
    assert out["verified"] == "true"
    assert out["findings_count"] == "0"
    assert out["verdict"] == "VERIFIED"
    assert out["admission"] == "ADMIT"


def test_a_file_the_verifier_cannot_verify_denies_the_scan(monkeypatch, workspace):
    class Unverified:
        status = entry.DiagnosticStatus.BLOCKED
        developer_fields = {}

    class Verifier:
        def verify_code(self, code, language):
            return Unverified()

    monkeypatch.setattr(entry, "CodeVerifier", Verifier)

    exit_code, out = _scan(monkeypatch, workspace, {"app.py": "x = 1\n"})

    assert exit_code == 1
    assert out["verdict"] == "UNVERIFIABLE"
    assert out["admission"] == "DENY"


def test_an_unsafe_verdict_without_line_findings_still_counts(monkeypatch, workspace):
    class Unsafe:
        status = entry.DiagnosticStatus.VERIFIED
        developer_fields = {"is_safe": False, "issues": []}

    class Verifier:
        def verify_code(self, code, language):
            return Unsafe()

    monkeypatch.setattr(entry, "CodeVerifier", Verifier)

    exit_code, out = _scan(monkeypatch, workspace, {"app.py": "x = 1\n"})

    assert exit_code == 1
    assert out["findings_count"] == "1"
    assert out["admission"] == "DENY"


def test_a_finding_already_on_a_line_is_not_reported_twice(monkeypatch, workspace):
    # The local list and CodeVerifier both see os.system on line 2.
    _, out = _scan(monkeypatch, workspace, {"app.py": 'import os\nos.system("id")\n'})

    # One for the import on line 1, one for the call on line 2.
    assert out["findings_count"] == "2"


# getattr with a constant name reaches that attribute as surely as writing it.
CONSTANT_NAME_ROUTES = {
    "posix": 'import posix\ngetattr(posix, "system")("id")\n',
    "pty": 'import pty\ngetattr(pty, "spawn")("sh")\n',
    "alias": 'import pty as p\ngetattr(p, "spawn")("sh")\n',
    "stored": 'import posix\nrun = getattr(posix, "system")\n',
    "builtins": 'import builtins\nrun = getattr(builtins, "exec")\n',
}


@pytest.mark.parametrize("source", CONSTANT_NAME_ROUTES.values(), ids=list(CONSTANT_NAME_ROUTES))
def test_getattr_with_a_constant_dangerous_name_is_a_finding(monkeypatch, workspace, source):
    exit_code, out = _scan(monkeypatch, workspace, {"app.py": source})

    assert exit_code == 1
    assert int(out["findings_count"]) >= 1
    assert out["admission"] == "DENY"


def test_a_computed_attribute_name_is_a_warning_that_does_not_fail(monkeypatch, workspace, capsys):
    source = "class A:\n    pass\n\nname = input()\ngetattr(A(), name)\n"

    exit_code, out = _scan(monkeypatch, workspace, {"app.py": source})

    assert exit_code == 0
    assert out["admission"] == "ADMIT"
    assert out["findings_count"] == "0"
    assert out["warnings_count"] == "1"
    assert "DYNAMIC_ATTRIBUTE" in capsys.readouterr().out


def test_warnings_reach_sarif_at_warning_level(monkeypatch, workspace):
    import json

    monkeypatch.setenv("INPUT_OUTPUT_FORMAT", "sarif")
    source = 'import posix\ngetattr(posix, "system")\nclass A:\n    pass\nsetattr(A, input(), 1)\n'

    _scan(monkeypatch, workspace, {"app.py": source})

    results = json.loads((workspace / "qwed-results.sarif").read_text())["runs"][0]["results"]
    levels = sorted(r["level"] for r in results)
    assert "warning" in levels and "error" in levels


def test_constant_names_that_are_not_dangerous_are_not_warned_about(monkeypatch, workspace):
    source = 'class A:\n    x = 1\n\nprint(getattr(A, "x", None))\nsetattr(A, "y", 2)\n'

    exit_code, out = _scan(monkeypatch, workspace, {"app.py": source})

    assert exit_code == 0
    assert out["findings_count"] == "0"
    assert out["warnings_count"] == "0"


def _utf7_hidden_source():
    # Each character of the hidden lines encoded on its own, so no part of
    # them is readable to a UTF-8 reader; Python decodes it into statements.
    import base64

    hidden = "\nimport os\nos.system('id')\n"
    encoded = "".join(
        "+" + base64.b64encode(ch.encode("utf-16-be")).decode().rstrip("=") + "-" for ch in hidden
    )
    return ("# -*- coding: utf-7 -*-\nx = 1  #" + encoded + "\n").encode()


@pytest.mark.parametrize(
    "data",
    [_utf7_hidden_source(), b"# coding: latin-1\nprint('caf\xe9')\n", b"print('\xff')\n"],
    ids=["utf7_hidden_statements", "latin1_declaration", "invalid_utf8"],
)
def test_source_that_is_not_utf8_is_not_admitted(monkeypatch, workspace, data):
    # The scan must read the code Python runs; another source encoding can
    # make a comment into statements.
    (workspace / "app.py").write_bytes(data)
    exit_code, out = _scan(monkeypatch, workspace, {})

    assert exit_code == 1
    assert out["admission"] == "DENY"


def test_a_utf8_bom_or_declaration_is_read_as_python_reads_it(monkeypatch, workspace):
    (workspace / "a.py").write_bytes("﻿print('ok')\n".encode("utf-8"))
    (workspace / "b.py").write_bytes("# -*- coding: utf-8 -*-\nprint('café')\n".encode("utf-8"))
    (workspace / "c.py").write_bytes(b"# coding: UTF8\nprint('ok')\n")
    exit_code, out = _scan(monkeypatch, workspace, {})

    assert exit_code == 0
    assert out["admission"] == "ADMIT"
    assert out["files_scanned"] == "3"


def test_getattr_on_an_attribute_chain_or_a_call_result_is_checked(monkeypatch, workspace):
    # A dotted owner resolves through import aliases; an owner that is not a
    # name chain still has its constant name checked.
    source = 'import os\ngetattr(os.path, "join")\ngetattr(object(), "system")\ngetattr(os)\n'
    exit_code, out = _scan(monkeypatch, workspace, {"app.py": source})

    assert exit_code == 1
    assert out["findings_count"] != "0"
    assert out["warnings_count"] == "0"


def test_json_output_carries_warnings(monkeypatch, workspace, capsys):
    import json

    monkeypatch.setenv("INPUT_OUTPUT_FORMAT", "json")
    _scan(monkeypatch, workspace, {"app.py": "class A:\n    pass\n\ngetattr(A(), input())\n"})

    printed = capsys.readouterr().out
    report, _ = json.JSONDecoder().raw_decode(printed[printed.index("\n{") + 1:])
    assert report["count"] == 0
    assert report["warnings"] == [{"type": "DYNAMIC_ATTRIBUTE", "file": "app.py", "line": 4}]


def test_long_reports_are_cut_at_twenty(monkeypatch, workspace, capsys):
    source = "import os\n" + "".join(f"os.system('x{n}')\n" for n in range(21)) + "".join(
        "getattr(os.path, input())\n" for _ in range(21)
    )
    _scan(monkeypatch, workspace, {"app.py": source})
    printed = capsys.readouterr().out

    assert "more issues" in printed
    assert "more warnings" in printed


def test_a_file_the_verifier_fails_on_denies_the_scan(monkeypatch, workspace):
    class Verifier:
        def verify_code(self, code, language):
            raise RuntimeError("engine failed")

    monkeypatch.setattr(entry, "CodeVerifier", Verifier)
    exit_code, out = _scan(monkeypatch, workspace, {"app.py": "x = 1\n"})

    assert exit_code == 1
    assert out["files_scanned"] == "1"
    assert out["admission"] == "DENY"
