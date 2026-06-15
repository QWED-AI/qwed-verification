#!/usr/bin/env python3
"""Lightweight boundary check for QWED regression patterns.

Scans source files for forbidden patterns that have historically led to
CWE-95 / CWE-94 / CWE-78 vulnerabilities. This is a release gate, not a
replacement for proper security review.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

# Approved wrapper paths (relative to repo root) — basename matching is too broad
APPROVED_WRAPPER_PATHS = {
    "src/qwed_new/core/safe_parser.py",
    "src/qwed_new/core/safe_evaluator.py",
    # TODO: refactor these to safe_shell() — pre-existing debt, tracked in #tech-debt
    "src/qwed_new/guards/state_guard.py",
    "src/qwed_new/core/symbolic_verifier.py",
}

# Full call names that are forbidden outside approved wrappers (dotted names)
FORBIDDEN_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.check_call",
    "subprocess.check_output",
    "popen",
}


def get_call_names(node: ast.Call) -> list[str]:
    names = []
    if isinstance(node.func, ast.Name):
        names.append(node.func.id)
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        elif isinstance(current, ast.Call):
            return names
        names.append(".".join(reversed(parts)))
    return names


def check_file(filepath: Path) -> list[str]:
    errors = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        errors.append(
            f"  [PARSE_ERROR] {filepath.relative_to(REPO_ROOT)}:{exc.lineno}: "
            "File could not be parsed; boundary check must fail closed"
        )
        return errors

    relpath = filepath.relative_to(REPO_ROOT).as_posix()
    in_wrapper = relpath in APPROVED_WRAPPER_PATHS

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_names = get_call_names(node)
        if not call_names:
            continue

        for name in call_names:
            leaf = name.split(".")[-1]

            # bare eval/exec → always dangerous
            if leaf in {"eval", "exec"} and not in_wrapper:
                # Flag if bare (exec(...)) or qualified as builtins.eval(...)
                # Do NOT flag session.exec(...) or similar ORM method calls
                if "." not in name or name.startswith("builtins."):
                    errors.append(
                        f"  [BARE_EVAL] {relpath}:{node.lineno}: "
                        f"Disallowed call '{name}()' — use approved wrappers"
                    )

            # parse_expr: flag both bare and qualified (sympy.parse_expr etc.)
            if leaf == "parse_expr" and not in_wrapper:
                errors.append(
                    f"  [BARE_PARSE_EXPR] {relpath}:{node.lineno}: "
                    f"Disallowed call '{name}()' — use approved wrappers"
                )

            # os.system, subprocess.*, popen, system, spawn
            if name in FORBIDDEN_CALLS and not in_wrapper:
                errors.append(
                    f"  [BARE_SHELL] {relpath}:{node.lineno}: "
                    f"Disallowed call '{name}()' — use safe_shell() or approved wrapper"
                )

    return errors


def main() -> int:
    errors: list[str] = []
    for pyfile in sorted(SRC_DIR.rglob("*.py")):
        errors.extend(check_file(pyfile))

    if errors:
        print(" QWED Boundary check FAILED")
        for err in errors:
            print(err)
        return 1

    print(" QWED Boundary check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
