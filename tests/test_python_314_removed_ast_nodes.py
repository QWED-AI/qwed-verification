"""Issue #568: Python 3.14 removed ``ast.Num``, ``ast.Str``, ``ast.Bytes``,
``ast.NameConstant`` and ``ast.Ellipsis``, and the ``n`` and ``s`` attributes of
``ast.Constant``.
The server image runs the Python its Dockerfile names (3.14 since #356), so a
reference to any of them fails there: ``stats_verifier`` read two in a class
body and could not be imported, which made every ``/verify/stats`` request
BLOCKED, and the taint analyzer raised on a sink argument that was neither a
name nor a constant, which blocked deep code verification of that code.

The CI ``test`` job runs 3.11, where these names still exist, so the scan below
reads the source instead of relying on the interpreter that runs it. It covers
everything the wheel and the images ship: ``qwed_sdk`` named them too, behind
``hasattr`` checks that every supported Python made dead code, since each
function tested ``ast.Constant`` first.
"""

import ast
import importlib
from pathlib import Path

import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.taint_analyzer import TaintAnalyzer

REMOVED_AST_NAMES = {"Num", "Str", "Bytes", "NameConstant", "Ellipsis"}
REPO = Path(__file__).resolve().parents[1]
SHIPPED = [
    *sorted((REPO / "src" / "qwed_new").rglob("*.py")),
    *sorted((REPO / "qwed_sdk").rglob("*.py")),
    REPO / "action_entrypoint.py",
]


def _removed_references(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in REMOVED_AST_NAMES
            and isinstance(node.value, ast.Name)
            and node.value.id == "ast"
        ):
            found.append(f"{path.name}:{node.lineno} ast.{node.attr}")
        elif isinstance(node, ast.ImportFrom) and node.module == "ast":
            found.extend(
                f"{path.name}:{node.lineno} from ast import {alias.name}"
                for alias in node.names
                if alias.name in REMOVED_AST_NAMES
            )
    return found


def test_shipped_code_names_no_ast_node_removed_in_314():
    found = [ref for path in SHIPPED for ref in _removed_references(path)]
    assert found == []


def test_the_scan_finds_attribute_reads_and_from_imports(tmp_path):
    path = tmp_path / "legacy.py"
    path.write_text(
        "import ast\nfrom ast import Num as N, Constant\nok = isinstance(n, ast.Str)\nfine = ast.Constant\n",
        encoding="utf-8",
    )

    assert _removed_references(path) == ["legacy.py:2 from ast import Num", "legacy.py:3 ast.Str"]


@pytest.mark.parametrize("module", [
    "qwed_new.core.stats_verifier",
    "qwed_new.core.taint_analyzer",
])
def test_module_imports(module):
    importlib.import_module(module)


@pytest.mark.parametrize("source, expected", [
    ("request.args", "<expr>"),
    ("'ls'", "'ls'"),
    ("cmd", "cmd"),
])
def test_taint_node_to_str_handles_any_expression(source, expected):
    node = ast.parse(source, mode="eval").body
    assert TaintAnalyzer()._node_to_str(node) == expected


def test_deep_verification_refuses_an_attribute_sink_argument_with_a_verdict():
    # On 3.14 this was BLOCKED ("taint analysis failed"), not a verdict.
    result = CodeVerifier().verify_python_deep("import os\nos.system(request.args)")

    assert result.status is DiagnosticStatus.VERIFIED
    assert result.developer_fields["is_safe"] is False
