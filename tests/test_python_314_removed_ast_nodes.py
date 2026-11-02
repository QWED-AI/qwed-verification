"""Issue #568: Python 3.14 removed ``ast.Num``, ``ast.Str``, ``ast.Bytes``,
``ast.NameConstant`` and ``ast.Ellipsis``, and the ``n`` and ``s`` attributes of
``ast.Constant``.
The server image runs the Python its Dockerfile names (3.14 since #356), so a
reference to any of them fails there: ``stats_verifier`` read two in a class
body and could not be imported, which made every ``/verify/stats`` request
BLOCKED, and the taint analyzer raised on a sink argument that was neither a
name nor a constant, which blocked deep code verification of that code.

The CI ``test`` job runs 3.11, where these names still exist, so the scan below
reads the source instead of relying on the interpreter that runs it.
``qwed_sdk`` is left out: it checks ``hasattr(ast, ...)`` before each legacy
name, for interpreters older than the server supports.
"""

import ast
import importlib
from pathlib import Path

import pytest

from qwed_new.core.taint_analyzer import TaintAnalyzer

REMOVED_AST_NAMES = {"Num", "Str", "Bytes", "NameConstant", "Ellipsis"}
SHIPPED = [
    *sorted((Path(__file__).resolve().parents[1] / "src" / "qwed_new").rglob("*.py")),
    Path(__file__).resolve().parents[1] / "action_entrypoint.py",
]


def _removed_references(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        f"{path.name}:{node.lineno} ast.{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr in REMOVED_AST_NAMES
        and isinstance(node.value, ast.Name)
        and node.value.id == "ast"
    ]


def test_shipped_code_names_no_ast_node_removed_in_314():
    found = [ref for path in SHIPPED for ref in _removed_references(path)]
    assert found == []


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
