"""
Security tests for safe_parse_expr - CWE-95 mitigation.
"""

import pytest
from qwed_new.core.safe_parser import (
    safe_parse_expr,
    validate_variable_name,
    SafeParserError,
    MAX_EXPRESSION_LENGTH,
)


class TestDenylist:

    @pytest.mark.parametrize("payload", [
        '__import__("os").system("id")',
        '__import__(chr(111)+chr(115)).system(chr(105)+chr(100))',
        'eval("1+1")',
        'exec("print(1)")',
        'os.system("id")',
        'os.popen("id").read()',
        'subprocess.call(["id"])',
        '__builtins__["__import__"]("os")',
        'getattr(__import__("os"), "system")("id")',
        'open("/etc/passwd")',
        '"".__class__.__bases__[0].__subclasses__()',
        'sys.modules["os"]',
        'compile("import os", "", "exec")',
        'chr(65)',
        'ord("A")',
        'print("hello")',
        'input("prompt")',
        'breakpoint()',
        'exit(0)',
        'type("X", (), {})',
        'dir()',
        'vars()',
    ])
    def test_injection_blocked(self, payload):
        with pytest.raises(SafeParserError, match="disallowed construct"):
            safe_parse_expr(payload)


class TestLegitimateExpressions:

    @pytest.mark.parametrize("expr,expected_str", [
        ("2 + 2", "4"),
        ("3 * 4 + 1", "13"),
        ("10 / 2", "5"),
        ("x**2 + 2*x + 1", "x**2 + 2*x + 1"),
        ("(x + 1)**2", "(x + 1)**2"),
        ("sin(pi/2)", "1"),
        ("cos(0)", "1"),
        ("log(1)", "0"),
        ("exp(0)", "1"),
        ("sqrt(16)", "4"),
        ("factorial(5)", "120"),
        ("pi", "pi"),
        ("E", "E"),
        ("Abs(-5)", "5"),
    ])
    def test_valid_expression(self, expr, expected_str):
        result = safe_parse_expr(expr)
        assert str(result) == expected_str


class TestMultiLetterVariables:

    @pytest.mark.parametrize("var_name", [
        "alpha", "beta", "gamma", "delta", "epsilon",
        "theta", "phi", "psi", "omega", "sigma",
        "tau", "mu", "nu", "xi", "eta", "zeta",
        "kappa", "rho", "chi",
    ])
    def test_greek_variable(self, var_name):
        result = safe_parse_expr(f"{var_name}**2 + 1")
        assert var_name in str(result)

    def test_multi_variable_expression(self):
        result = safe_parse_expr("alpha * beta + gamma")
        result_str = str(result)
        assert "alpha" in result_str
        assert "beta" in result_str
        assert "gamma" in result_str


class TestInputValidation:

    def test_non_string_input(self):
        with pytest.raises(SafeParserError, match="must be a string"):
            safe_parse_expr(42)

    def test_none_input(self):
        with pytest.raises(SafeParserError, match="must be a string"):
            safe_parse_expr(None)

    def test_empty_string(self):
        with pytest.raises(SafeParserError, match="empty"):
            safe_parse_expr("")

    def test_whitespace_only(self):
        with pytest.raises(SafeParserError, match="empty"):
            safe_parse_expr("   ")

    def test_too_long(self):
        expr = "x + " * (MAX_EXPRESSION_LENGTH // 4 + 1)
        with pytest.raises(SafeParserError, match="maximum length"):
            safe_parse_expr(expr)


class TestVariableNameValidation:

    @pytest.mark.parametrize("name", ["x", "y", "theta", "alpha", "x1"])
    def test_valid_variable(self, name):
        assert validate_variable_name(name) == name

    def test_non_string(self):
        with pytest.raises(SafeParserError, match="must be a string"):
            validate_variable_name(42)

    def test_empty(self):
        with pytest.raises(SafeParserError, match="empty"):
            validate_variable_name("")

    def test_too_long(self):
        with pytest.raises(SafeParserError, match="too long"):
            validate_variable_name("a" * 51)

    def test_starts_with_number(self):
        with pytest.raises(SafeParserError, match="Invalid variable name"):
            validate_variable_name("1x")

    def test_special_characters(self):
        with pytest.raises(SafeParserError, match="Invalid variable name"):
            validate_variable_name("x;drop")

    def test_denylist_blocked(self):
        with pytest.raises(SafeParserError):
            validate_variable_name("__import__")

    def test_os_blocked(self):
        with pytest.raises(SafeParserError, match="disallowed"):
            validate_variable_name("os")


class TestNamespaceIsolation:

    def test_global_dict_not_polluted(self):
        safe_parse_expr("x + 1")
        safe_parse_expr("y + 2")
        result = safe_parse_expr("x + y")
        assert "x" in str(result)
        assert "y" in str(result)

    def test_global_dict_not_shared_between_calls(self):
        from qwed_new.core.safe_parser import _SAFE_GLOBAL_DICT_TEMPLATE
        before = dict(_SAFE_GLOBAL_DICT_TEMPLATE)
        safe_parse_expr("x + 1")
        safe_parse_expr("y + 2")
        assert _SAFE_GLOBAL_DICT_TEMPLATE == before


class TestGetSafeSymbol:

    def test_consistency_with_n(self):
        from qwed_new.core.safe_parser import get_safe_symbol
        n1 = get_safe_symbol("n")
        n2 = get_safe_symbol("n")
        assert n1 == n2

    def test_plain_symbol(self):
        from qwed_new.core.safe_parser import get_safe_symbol
        s = get_safe_symbol("myvar")
        assert str(s) == "myvar"

    def test_invalid_variable(self):
        from qwed_new.core.safe_parser import get_safe_symbol
        with pytest.raises(SafeParserError):
            get_safe_symbol("os.system")


class TestASTDepthLimit:

    def test_deeply_nested_rejected(self):
        deep_expr = "x"
        for _ in range(40):
            deep_expr = f"sin({deep_expr})"
        with pytest.raises((SafeParserError, ValueError)):
            safe_parse_expr(deep_expr)

    def test_normal_expression_accepted(self):
        result = safe_parse_expr("sin(cos(x + 1) * 2)")
        assert result is not None


class TestExtraSymbols:

    def test_extra_symbol(self):
        from sympy import Symbol
        custom = {"myvar": Symbol("myvar")}
        result = safe_parse_expr("myvar + 1", extra_symbols=custom)
        assert "myvar" in str(result)

    def test_extra_symbol_rejects_non_sympy(self):
        result = safe_parse_expr("x + 1", extra_symbols={"bad": lambda: None})
        assert str(result) == "x + 1"
