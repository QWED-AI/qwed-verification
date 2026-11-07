"""GHSA-5h3v-3463-78hf: safe_parse_expr split a name it did not know into a
product of letters (split_symbols), so sinc(0) and zeta(0) read as 0 and
floor(7/2) as 7*f*l*o**2*r/2, and it gave n hidden assumptions (a positive
integer), so Abs(n) = n held. /verify/math returned VERIFIED · ADMIT for
false identities and proved true ones false.
"""
import pytest
import sympy

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.math_identity import math_identity_result
from qwed_new.core.safe_parser import SafeParserError, safe_parse_expr


@pytest.mark.parametrize(
    "expression",
    [
        "sinc(0)", "zeta(0)", "gamma(1)", "floor(7/2)", "log10(100)", "theta(2)", "sinc 0", "theta 2", "alpha beta",
        # Function exponentiation and a parenthesised name put it in call
        # position too: sinc^2(0) read as sinc**2 * 0.
        "sinc**2(0)", "sinc^2(0)", "sinc^2 (0)", "(sinc)(0)", "( floor )(3.5)", "alpha^2(x)",
    ],
)
def test_a_name_in_call_position_that_is_not_a_function_is_refused(expression):
    with pytest.raises(SafeParserError, match="Unknown function"):
        safe_parse_expr(expression)


@pytest.mark.parametrize("expression", ["sinc(0) = 0", "zeta(0) = 0", "floor(7/2) = 3", "sinc^2(0) = 0", "(sinc)(0) = 0"])
def test_identities_about_unknown_functions_are_input_errors(expression):
    with pytest.raises(SafeParserError):
        math_identity_result(expression)


@pytest.mark.parametrize("expression", ["Abs(n) = n", "sqrt(n**2) = n"])
def test_n_has_no_hidden_domain(expression):
    result = math_identity_result(expression)
    assert result.developer_fields["is_valid"] is False, result.developer_fields
    assert admission_decision(result).value == "BLOCKED"


def test_n_is_a_plain_symbol():
    n = safe_parse_expr("n")
    assert n == sympy.Symbol("n")
    assert n.is_positive is None
    assert n.is_integer is None


@pytest.mark.parametrize(
    "expression",
    [
        "2+2 = 4",
        "x(x+1) = x^2 + x",
        "2(x+1) = 2x + 2",
        "2x + 3x = 5x",
        "sin x = sin(x)",
        "sin(x)^2 + cos(x)^2 = 1",
        "diff(x^2, x) = 2x",
        "factorial(5) = 120",
        "binomial(5, 2) = 10",
        "abs(-3) = 3",
        "log(E) = 1",
        "n + n = 2n",
        "x^2 - 1 = (x-1)(x+1)",
        "alpha + beta = beta + alpha",
        "pi(2) = 2pi",
        "(x)(x+1) = x^2 + x",
        "log^2(E) = 1",
    ],
)
def test_true_identities_in_the_usual_forms_are_still_admitted(expression):
    result = math_identity_result(expression)
    assert result.developer_fields["is_valid"] is True, result.developer_fields
    assert admission_decision(result).value == "ADMIT"


def test_a_multi_letter_name_is_one_symbol_not_a_product():
    assert safe_parse_expr("xy") == sympy.Symbol("xy")
    assert safe_parse_expr("2xy") == 2 * sympy.Symbol("xy")


# Differential check against SymPy's own reading (the advisory's property
# test), over a fixed grid so the run is deterministic: every supported
# function applied to every argument form, alone and in a product or a sum.
_FUNCTIONS = ["sin", "cos", "tan", "asin", "atan", "sinh", "cosh", "tanh", "log", "ln", "exp", "sqrt", "cbrt", "Abs", "abs", "factorial"]
_ARGUMENTS = ["0", "1", "2", "x", "x + 1", "2*x", "x**2", "y - x", "n"]
_SHAPES = ["{f}({a})", "2*{f}({a})", "{f}({a}) + x", "{f}({a})**2"]
_SYMPY_NAMES = {"ln": sympy.log, "abs": sympy.Abs, "n": sympy.Symbol("n")}


@pytest.mark.parametrize("function", _FUNCTIONS)
def test_safe_parse_expr_agrees_with_sympy_on_supported_functions(function):
    for argument in _ARGUMENTS:
        for shape in _SHAPES:
            text = shape.format(f=function, a=argument)
            assert safe_parse_expr(text) == sympy.sympify(text, locals=_SYMPY_NAMES), text
