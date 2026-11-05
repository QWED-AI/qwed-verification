"""GHSA-w73j-4jjq-q53j: LogicVerifier proved false theorems because Python
computed number-only sub-expressions before Z3 saw them (1/3 as a float,
0.1 + 0.2 as 0.30000000000000004, 7/2 as 3.5) while the same operator on a Z3
variable stayed exact or was integer division. The DSL compiler did the same
for DIV.
"""
from fractions import Fraction

import pytest
from z3 import Int, Real, RealVal, is_rational_value, simplify

from qwed_new.core import z3_exact
from qwed_new.core.dsl.compiler import Z3Compiler
from qwed_new.core.logic_verifier import LogicVerifier
from qwed_new.core.safe_evaluator import SafeEvaluator


@pytest.fixture
def verifier():
    return LogicVerifier()


@pytest.mark.parametrize(
    ("variables", "premises", "conclusion"),
    [
        ({"x": "Real"}, ["x == 1/3"], "3 * x != 1"),
        ({"x": "Real"}, ["x == 0.1 + 0.2"], "x != 0.3"),
        ({"x": "Int"}, ["x == 7"], "x / 2 != 7 / 2"),
        ({"x": "Real"}, ["x == 2 ** -1"], "2 * x != 1"),
        # A bool is an int to Python, so True / 3 was the float 0.333...
        ({"x": "Real"}, ["x == True / 3"], "3 * x != 1"),
    ],
)
def test_false_theorems_are_not_proved(verifier, variables, premises, conclusion):
    assert verifier.prove_theorem(variables, premises, conclusion).status.value != "VERIFIED"


@pytest.mark.parametrize(
    ("variables", "premises", "conclusion"),
    [
        ({"x": "Real"}, ["3 * x == 1"], "x == 1/3"),
        ({"x": "Real"}, ["x == 0.1 + 0.2"], "x == 0.3"),
        ({"x": "Real"}, ["x == 2 ** -1"], "2 * x == 1"),
        ({"x": "Int"}, ["x == 7"], "x / 2 == 3"),
        ({"x": "Int"}, ["x == 6"], "x == 12 / 2"),
        ({"x": "Int"}, ["x == -7"], "x % -2 == 1"),
        ({"x": "Int"}, ["x > 5"], "x > 3"),
    ],
)
def test_true_theorems_are_proved(verifier, variables, premises, conclusion):
    assert verifier.prove_theorem(variables, premises, conclusion).status.value == "VERIFIED"


def test_equivalence_and_satisfiability_agree_with_exact_values(verifier):
    assert verifier.check_equivalence({"x": "Real"}, "3 * x == 1", "x == 1/3").status.value == "VERIFIED"
    assert verifier.verify_logic({"x": "Real"}, ["x == 1/3", "3 * x == 1"]).status.value == "VERIFIED"


def test_decimal_literals_are_the_value_written():
    expr = SafeEvaluator().safe_eval("x == 0.1 + 0.2", {"x": Real("x")})
    assert simplify(expr.arg(1)).eq(RealVal("3/10"))


def test_an_inexact_division_of_numbers_next_to_an_int_is_refused():
    evaluator, context = SafeEvaluator(), {"x": Int("x")}
    with pytest.raises(ValueError):
        evaluator.safe_eval("x != 7 / 2", context)


def test_integer_and_real_division_cannot_meet():
    evaluator, context = SafeEvaluator(), {"x": Int("x"), "y": Real("y")}
    with pytest.raises(ValueError):
        evaluator.safe_eval("x / y == 1", context)
    with pytest.raises(ValueError):
        evaluator.safe_eval("x / 0.5 == 1", context)


def test_the_helpers_cannot_be_named_by_a_constraint():
    evaluator, context = SafeEvaluator(), {"x": Real("x")}
    with pytest.raises(ValueError):
        evaluator.safe_eval("_qwed_divide(1, 3) == x", context)


def test_dsl_division_of_numbers_is_integer_division_like_an_int_variable():
    result = Z3Compiler().compile(["AND", ["EQ", "x", 7], ["NEQ", ["DIV", "x", 2], ["DIV", 7, 2]]])
    assert result.success
    from z3 import Solver, unsat
    solver = Solver()
    solver.add(result.compiled)
    assert solver.check() == unsat


def test_dsl_decimal_literals_are_exact():
    compiler = Z3Compiler()
    result = compiler.compile(["EQ", ["PLUS", 0.1, 0.2], 0.3])
    assert result.success
    assert simplify(result.compiled).eq(simplify(RealVal(1) == RealVal(1)))


def test_dsl_mixed_sort_division_is_refused():
    result = Z3Compiler().compile(["AND", ["VAR", "r", "Real"], ["EQ", ["DIV", "x", "r"], 1]])
    assert not result.success


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [(6, 3, 2), (7, -7, -1), (1, 3, Fraction(1, 3))],
)
def test_divide_numbers_exactly(left, right, expected):
    value = z3_exact.divide(left, right, int_context=False)
    if isinstance(expected, int):
        assert value == expected
    else:
        assert is_rational_value(value) and value.as_fraction() == expected


def test_divide_by_zero_is_refused():
    with pytest.raises(ValueError):
        z3_exact.divide(1, 0, int_context=False)
    with pytest.raises(ValueError):
        z3_exact.modulo(1, 0)
    with pytest.raises(ValueError):
        z3_exact.power(0, -1, int_context=False)


@pytest.mark.parametrize(("left", "right", "expected"), [(7, 2, 1), (-7, 2, 1), (7, -2, 1), (-7, -2, 1)])
def test_modulo_of_numbers_follows_z3(left, right, expected):
    assert z3_exact.modulo(left, right) == expected


@pytest.mark.parametrize("expression", ["x == True / 3", "x == False % 2", "x == True ** -1", "x == 3 / True"])
def test_arithmetic_on_a_boolean_is_refused(expression):
    # The DSL compiler already refuses it; the evaluator's helpers now do too.
    evaluator, context = SafeEvaluator(), {"x": Real("x")}
    with pytest.raises(ValueError):
        evaluator.safe_eval(expression, context)


def test_dsl_integer_division_by_zero_is_refused():
    with pytest.raises(ValueError):
        z3_exact.integer_divide(1, 0)


def test_a_non_arithmetic_term_is_not_a_mixed_sort():
    # A Boolean term is neither Int nor Real; Z3 refuses arithmetic on it.
    from z3 import Bool

    flag = Bool("flag")
    z3_exact.reject_mixed_sorts("Division", flag, Int("x"))
