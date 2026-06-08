"""
Security tests for CWE-95: parse_expr code injection prevention.

Verifies that safe_parse_expr blocks code execution payloads while
allowing legitimate mathematical expressions.
"""

import pytest
from qwed_new.core.safe_parser import safe_parse_expr


class TestSafeParseExprBlocksCodeExecution:
    """Verify that crafted expressions cannot execute arbitrary code."""

    @pytest.mark.parametrize(
        "payload",
        [
            '__import__("os").system("id")',
            '__import__("os").getpid()',
            '__import__("subprocess").check_output("id")',
            'exec("import os")',
            'open("/etc/passwd").read()',
            'getattr(int, "__subclasses__")',
            '().__class__.__bases__[0].__subclasses__()',
            '__builtins__["__import__"]("os")',
            'globals()["__builtins__"]',
            'locals()',
            'compile("1", "<>", "exec")',
            'type("X", (), {})',
            'os.system("id")',
            'sys.exit(1)',
            'breakpoint()',
            'dir()',
            'vars()',
            'setattr(x, "y", 1)',
            'delattr(x, "y")',
            'subprocess.call("id")',
        ],
        ids=lambda p: p[:40],
    )
    def test_dangerous_payload_is_rejected(self, payload: str) -> None:
        with pytest.raises(ValueError, match="disallowed constructs"):
            safe_parse_expr(payload)

    @pytest.mark.parametrize(
        "payload",
        [
            'print("hello")',
            'input("prompt")',
        ],
        ids=lambda p: p[:40],
    )
    def test_io_functions_blocked(self, payload: str) -> None:
        with pytest.raises(ValueError, match="disallowed constructs"):
            safe_parse_expr(payload)


class TestSafeParseExprAllowsLegitMath:
    """Verify that normal math expressions still parse correctly."""

    @pytest.mark.parametrize(
        "expression,expected_str",
        [
            ("2+2", "4"),
            ("x**2 + 2*x + 1", "x**2 + 2*x + 1"),
            ("sin(x)", "sin(x)"),
            ("cos(x)**2 + sin(x)**2", "sin(x)**2 + cos(x)**2"),
            ("pi", "pi"),
            ("sqrt(16)", "4"),
            ("3/4", "3/4"),
            ("log(x)", "log(x)"),
            ("exp(1)", "E"),
            ("factorial(5)", "120"),
            ("atan2(1, 1)", "pi/4"),
        ],
    )
    def test_valid_expression_parses(
        self, expression: str, expected_str: str
    ) -> None:
        result = safe_parse_expr(expression)
        assert str(result) == expected_str


class TestSafeParseExprInputValidation:
    """Verify input validation guards."""

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            safe_parse_expr("")

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValueError, match="must be a string"):
            safe_parse_expr(123)  # type: ignore[arg-type]

    def test_rejects_oversized_input(self) -> None:
        with pytest.raises(ValueError, match="too long"):
            safe_parse_expr("x + " * 2000)
