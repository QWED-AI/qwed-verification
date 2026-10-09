"""Regression tests: a string literal nested in a container (or any non
safe-string-constructor position) must not reach SymPy's sympify() eval sink
through the local SDK math validator.

Advisory GHSA-4v5r-g7f4-vvgc (incomplete fix for GHSA-xmm6-8r3x-j567): the
original guard only inspected direct call arguments, so simplify(("x",)) and
similar container-wrapped strings were evaluated.
"""
import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import sympy

from qwed_sdk.qwed_local import (
    DisallowedExpressionError,
    _is_safe_sympy_expr,
    _safe_eval_sympy_expr,
)

NAMESPACE = {"sympy": sympy, "x": sympy.Symbol("x")}

# Strings that must never reach sympify(), in every nesting shape.
BLOCKED_EXPRESSIONS = [
    'sympy.simplify("1+1")',                      # direct (already covered historically)
    'sympy.simplify(("1+1",))',                   # tuple-wrapped (the GHSA-4v5r bypass)
    'sympy.simplify(["1+1"])',                    # list-wrapped
    'sympy.simplify((("1+1",),))',                # doubly nested
    'sympy.expand(["x*(x+1)"])',                  # different sympify-backed function
    'sympy.solve(("x",))',
    'sympy.simplify(("(1).__class__.__name__",))',  # dunder-traversal gadget, benign read
    'sympy.simplify(("len([1,2,3])",))',          # builtin access, benign read
    'sympy.simplify(x, nice=("1+1",))',           # keyword-nested string
    'sympy.Symbol(("x",))',                       # safe-string func, but string not a direct arg
]

# Expressions that must keep working after the fix.
ALLOWED_EXPRESSIONS = [
    ("1/10 + 2/10", sympy.Rational(3, 10)),
    ("2 + 2", sympy.Integer(4)),
    ("sympy.integrate(x, (x, 0, 1))", sympy.Rational(1, 2)),
    ("sympy.simplify(x + x)", 2 * sympy.Symbol("x")),
    ('sympy.Rational("1/3")', sympy.Rational(1, 3)),
    ('sympy.Symbol("y")', sympy.Symbol("y")),
    ('sympy.symbols("a b")', (sympy.Symbol("a"), sympy.Symbol("b"))),
    ('sympy.Integer("5")', sympy.Integer(5)),
]


@pytest.mark.parametrize("expr", BLOCKED_EXPRESSIONS)
def test_nested_string_is_rejected(expr):
    assert _is_safe_sympy_expr(expr) is False
    with pytest.raises(DisallowedExpressionError):
        _safe_eval_sympy_expr(expr, NAMESPACE)


@pytest.mark.parametrize("expr,expected", ALLOWED_EXPRESSIONS)
def test_legitimate_expression_still_evaluates(expr, expected):
    assert _is_safe_sympy_expr(expr) is True
    assert _safe_eval_sympy_expr(expr, NAMESPACE) == expected
