"""#636: a decimal literal is the exact value its text writes.

The DSL parser read a decimal with ``float()`` and SafeEvaluator took it from
Python's parser as a float, so both were rounded to the nearest binary fraction
before the exact conversion: ``0.10000000000000001`` became ``0.1``,
``1e-400`` became ``0.0``. ``DSLLogicVerifier.prove_from_dsl`` and
``LogicVerifier.prove_theorem`` then proved ``0.1 == 0.10000000000000001``
and refuted ``1.00000000000000001 > 1``.
"""
import ast
import sys
import time
from fractions import Fraction

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from z3 import Real, RealVal, is_false, is_true, simplify

from qwed_new.core import z3_exact
from qwed_new.core.decimal_literal import MAX_DECIMAL_DIGITS, MAX_DECIMAL_TEXT, exact_decimal, names_a_non_finite_number
from qwed_new.core.dsl import parse_and_validate as parse_dsl
from qwed_new.core.dsl.compiler import SymPyCompiler
from qwed_new.core.dsl.parser import QWEDLogicDSL, parse_and_validate
from qwed_new.core.safe_evaluator import _ExactArithmetic
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.logic_verifier import LogicVerifier
from qwed_new.core.safe_evaluator import SafeEvaluator

PREMISE = "(GT x 5)"
X_INT = [{"name": "x", "type": "Int"}]


@pytest.fixture(scope="module")
def dsl():
    return DSLLogicVerifier()


@pytest.fixture(scope="module")
def logic():
    return LogicVerifier()


# --- the value of a literal -------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0.10000000000000001", Fraction(10000000000000001, 10**17)),
        ("0.1", Fraction(1, 10)),
        ("1e-400", Fraction(1, 10**400)),
        ("1e400", Fraction(10**400)),
        ("100000000000000000001.0", Fraction(100000000000000000001)),
        (".5", Fraction(1, 2)),
        ("5.", Fraction(5)),
        ("1E3", Fraction(1000)),
        ("+0.5", Fraction(1, 2)),
        ("-0.25", Fraction(-1, 4)),
        ("-0.0", Fraction(0)),
        ("1_000.5", Fraction(2001, 2)),
        # Python reads other scripts' digits as numbers; the value is exact.
        ("\uff11.\uff15", Fraction(3, 2)),
    ],
)
def test_a_decimal_is_the_value_written(text, expected):
    assert exact_decimal(text) == expected
    assert QWEDLogicDSL()._parse_atom(text) == expected


@pytest.mark.parametrize("text", ["inf", "-inf", "+inf", "Infinity", "nan", "NaN", "-nan"])
def test_a_number_that_is_not_finite_is_refused(text):
    with pytest.raises(ValueError):
        exact_decimal(text)
    # Python reads it as a number, so the parser does not take it as a name.
    assert parse_and_validate(f"(GT x {text})")["status"] == "PARSE_ERROR"


@pytest.mark.parametrize("text", ["x", "x1", "inf_rate", "nan_count", "rate"])
def test_names_stay_names(text):
    assert QWEDLogicDSL()._parse_atom(text) == text


def test_an_integer_stays_an_int():
    atom = QWEDLogicDSL()._parse_atom("10")
    assert atom == 10
    assert type(atom) is int


@pytest.mark.parametrize("text", ["sNaN", "-sNaN", "snan", "+sNaN", "sNaN123", "NaN5", "NaN\uff15", "sNaN\u0663"])
def test_a_signalling_nan_is_refused_not_taken_as_a_name(text):
    # float() does not read sNaN, but the decimal grammar does.
    assert names_a_non_finite_number(text)
    with pytest.raises(ValueError):
        exact_decimal(text)
    assert parse_and_validate(f"(GT x {text})")["status"] == "PARSE_ERROR"


@pytest.mark.parametrize("text", ["x", "rate", "e", "E5", "nan_count", "_1x", "_1", "_", "__x", "_1_000", "info", "nano"])
def test_a_name_stays_a_name(text):
    # The decimal grammar skips underscores and would read "_1" as 1.
    assert not names_a_non_finite_number(text)
    assert QWEDLogicDSL()._parse_atom(text) == text


def test_a_name_like_underscore_one_is_a_variable(dsl):
    assert dsl.verify_from_dsl("(GT _1 5)", [{"name": "_1", "type": "Int"}]).status == "SAT"


@pytest.mark.parametrize("text", ["abc", "", "1.2.3", "0x10"])
def test_text_that_is_not_a_number_is_refused(text):
    with pytest.raises(ValueError):
        exact_decimal(text)


def test_a_value_that_is_not_text_is_refused():
    with pytest.raises(ValueError):
        exact_decimal(None)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Zeros at the end of the coefficient cancel before the size check.
        ("1" + "0" * 5000 + "e-5000", Fraction(1)),
        ("10e-4000", Fraction(1, 10**3999)),
        ("0e999999999", Fraction(0)),
        ("0.000", Fraction(0)),
        ("-0e-999999999", Fraction(0)),
    ],
)
def test_zeros_that_cancel_do_not_count(text, expected):
    assert exact_decimal(text) == expected


def test_text_longer_than_the_bound_is_refused_before_it_is_read():
    start = time.monotonic()
    with pytest.raises(ValueError):
        exact_decimal("1" * (MAX_DECIMAL_TEXT + 1))
    with pytest.raises(ValueError):
        exact_decimal("1" * 10_000_000)
    assert time.monotonic() - start < 2


@pytest.mark.skipif(not hasattr(sys, "set_int_max_str_digits"), reason="Python 3.10.7 and later")
def test_int_text_limit_decides_a_coefficient_longer_than_the_bound():
    # The 4,001-digit even coefficient over 10 reduces to 4,000 digits over 5:
    # int() must read 4,001 digits first, so the process limit decides it.
    text = "1" + "0" * 3999 + "2e-1"
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4000)
        with pytest.raises(ValueError):
            exact_decimal(text)
        sys.set_int_max_str_digits(4001)
        assert exact_decimal(text) == Fraction(10**4000 + 2, 10)
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.skipif(not hasattr(sys, "set_int_max_str_digits"), reason="Python 3.10.7 and later")
def test_the_process_limit_for_integer_text_lowers_the_bound():
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        with pytest.raises(ValueError):
            exact_decimal("1e-700")
        assert exact_decimal("1e-600") == Fraction(1, 10**600)
        assert simplify(z3_exact.exact_real("1e-600")).eq(RealVal(f"1/{10**600}"))
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize(
    ("text", "allowed"),
    [
        ("1e3999", True),
        ("1e4000", False),
        ("1e-3999", True),
        ("1e-4000", False),
        ("1" * MAX_DECIMAL_DIGITS, True),
        ("1" * (MAX_DECIMAL_DIGITS + 1), False),
        ("0." + "1" * (MAX_DECIMAL_DIGITS - 1), True),
        ("0." + "1" * MAX_DECIMAL_DIGITS, False),
        ("1e999999999", False),
        ("1e-999999999", False),
        # The bound is on the reduced fraction: 5e-4000 is 1 / (2 * 10**3999).
        ("5e-4000", True),
        ("25e-4001", True),
        ("3e-4000", False),
        ("5555555555e-4005", False),
        # A 4,001-digit even coefficient over 10 reduces to 4,000 digits over 5.
        # Written as text, not str(int): a lower int text limit must not stop
        # the file being collected. Under such a limit int() cannot read the
        # coefficient, so the value is refused, as the limit asks.
        pytest.param(
            "1" + "0" * 3999 + "2e-1",
            True,
            marks=pytest.mark.skipif(
                hasattr(sys, "get_int_max_str_digits") and 0 < sys.get_int_max_str_digits() < 4001,
                reason="needs an int text limit of at least 4,001 digits",
            ),
        ),
        ("1" + "0" * 3999 + "1e-1", False),
    ],
)
def test_the_size_of_a_literal_is_bounded(text, allowed):
    if allowed:
        assert exact_decimal(text) == Fraction(text)
    else:
        with pytest.raises(ValueError):
            exact_decimal(text)


def test_a_huge_exponent_is_refused_quickly(dsl, logic):
    start = time.monotonic()
    assert dsl.prove_from_dsl(PREMISE, "(GT 1e999999999 1)", X_INT).status != "VALID"
    assert logic.prove_theorem({"x": "Real"}, ["x == 1"], "1e999999999 > x").status.value != "VERIFIED"
    assert time.monotonic() - start < 10


# --- the DSL engine ---------------------------------------------------------


@pytest.mark.parametrize(
    "claim",
    [
        "(EQ 0.1 0.10000000000000001)",
        "(EQ 100000000000000000001.0 100000000000000000000)",
        "(GT 1 1.00000000000000001)",
        "(EQ 1e-400 0)",
        "(LT 1e400 1)",
        "(EQ (PLUS 0.1 0.2) 0.30000000000000001)",
    ],
)
def test_a_false_decimal_claim_is_not_proved(dsl, claim):
    assert dsl.prove_from_dsl(PREMISE, claim, X_INT).status == "INVALID"


@pytest.mark.parametrize(
    "claim",
    [
        "(GT 1.00000000000000001 1)",
        "(NEQ 0.1 0.10000000000000001)",
        "(GT 1e-400 0)",
        "(GT 1e400 1)",
        "(EQ 0.1 0.10)",
        "(EQ (PLUS 0.1 0.2) 0.3)",
        "(EQ 2.0 2)",
    ],
)
def test_a_true_decimal_claim_is_proved(dsl, claim):
    assert dsl.prove_from_dsl(PREMISE, claim, X_INT).status == "VALID"


@pytest.mark.parametrize("claim", ["(GT inf 5)", "(EQ nan nan)", "(GT x -inf)"])
def test_a_number_that_is_not_finite_proves_nothing(dsl, claim):
    assert dsl.prove_from_dsl(PREMISE, claim, X_INT).status not in ("VALID", "INVALID")


def test_two_different_decimals_can_both_hold(dsl):
    program = "(AND (EQ y 0.1) (NEQ y 0.10000000000000001))"
    assert dsl.verify_from_dsl(program, [{"name": "y", "type": "Real"}]).status == "SAT"


# --- LogicVerifier and SafeEvaluator ----------------------------------------


@pytest.mark.parametrize(
    ("premises", "conclusion"),
    [
        (["x == 1"], "0.1 == 0.10000000000000001"),
        (["x == 0.1"], "x == 0.10000000000000001"),
        (["x == 1e-400"], "x == 0"),
        (["x == 100000000000000000001.0"], "x == 100000000000000000000"),
    ],
)
def test_a_false_theorem_is_not_proved(logic, premises, conclusion):
    assert logic.prove_theorem({"x": "Real"}, premises, conclusion).status.value != "VERIFIED"


@pytest.mark.parametrize(
    ("premises", "conclusion"),
    [
        (["x == 1"], "1.00000000000000001 > x"),
        (["x == 0.1"], "x != 0.10000000000000001"),
        (["x == 1"], "1e-400 > 0"),
        (["x == 0.1 + 0.2"], "x == 0.3"),
    ],
)
def test_a_true_theorem_is_proved(logic, premises, conclusion):
    assert logic.prove_theorem({"x": "Real"}, premises, conclusion).status.value == "VERIFIED"


def test_two_different_decimals_are_not_called_contradictory(logic):
    result = logic.verify_logic({"x": "Real"}, ["x == 0.1", "x != 0.10000000000000001"])
    assert result.status.value == "VERIFIED"


def _sides(expr):
    return [simplify(expr.arg(0)), simplify(expr.arg(1))]


def test_safe_eval_keeps_the_text_of_the_literal():
    # Z3 may put the number on either side of the equation.
    expr = SafeEvaluator().safe_eval("x == 0.10000000000000001", {"x": Real("x")})
    assert any(side.eq(RealVal("10000000000000001/100000000000000000")) for side in _sides(expr))
    expr = SafeEvaluator().safe_eval("x == -1e-400", {"x": Real("x")})
    assert any(side.eq(RealVal(f"-1/{10**400}")) for side in _sides(expr))


def test_a_float_built_by_hand_is_its_shortest_decimal():
    # An AST built in code, not parsed from text, may still hold a float.
    assert simplify(z3_exact.literal(0.1)).eq(RealVal("1/10"))
    assert simplify(z3_exact.literal(Fraction(1, 3))).eq(RealVal("1/3"))
    assert z3_exact.literal(7) == 7


# --- property tests ----------------------------------------------------------

_DIGITS = st.integers(min_value=0, max_value=10**25).map(str)
_EXPONENTS = st.one_of(st.just(""), st.integers(min_value=-450, max_value=450).map(lambda e: f"e{e}"))
_DECIMALS = st.builds(
    lambda sign, whole, fraction, exponent: f"{sign}{whole}.{fraction}{exponent}",
    st.sampled_from(["", "-"]),
    _DIGITS,
    _DIGITS,
    _EXPONENTS,
)


def _near(text: str, tail: str) -> str:
    """``text`` with digits added at the end of its fraction: a different
    value that a float often cannot tell from it or, with the tail "0", the
    same value written longer."""
    if "e" in text:
        mantissa, exponent = text.split("e")
        return f"{mantissa}{tail}e{exponent}"
    return f"{text}{tail}"


_PAIRS = st.one_of(
    st.tuples(_DECIMALS, _DECIMALS),
    st.builds(lambda text, tail: (text, _near(text, tail)), _DECIMALS, st.sampled_from(["0000000000000001", "00000000000000000001", "0"])),
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(pair=_PAIRS)
def test_dsl_proves_exactly_the_true_comparisons(dsl, pair):
    left, right = pair
    exact_left, exact_right = Fraction(left), Fraction(right)
    equal = dsl.prove_from_dsl(PREMISE, f"(EQ {left} {right})", X_INT).status
    greater = dsl.prove_from_dsl(PREMISE, f"(GT {left} {right})", X_INT).status
    assert equal == ("VALID" if exact_left == exact_right else "INVALID")
    assert greater == ("VALID" if exact_left > exact_right else "INVALID")


@settings(max_examples=100, deadline=None)
@given(pair=_PAIRS)
def test_safe_eval_decides_exactly_the_true_comparisons(pair):
    left, right = pair
    evaluator = SafeEvaluator()
    for operator, expected in (("==", Fraction(left) == Fraction(right)), (">", Fraction(left) > Fraction(right))):
        decided = simplify(evaluator.safe_eval(f"{left} {operator} {right}", {}))
        assert is_true(decided) if expected else is_false(decided)


# --- SafeEvaluator reads each literal once ------------------------------------


def test_many_decimals_are_read_in_linear_time():
    formula = "And(" + ", ".join(f"x != {i}.{i:05d}1" for i in range(2000)) + ")"
    start = time.monotonic()
    SafeEvaluator().safe_eval(formula, {"x": Real("x")})
    assert time.monotonic() - start < 5


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_a_literal_on_a_later_line_keeps_its_text(newline):
    formula = f"And(x != 1,{newline}x == 0.10000000000000001)"
    expr = SafeEvaluator().safe_eval(formula, {"x": Real("x")})
    second = expr.arg(1)
    assert any(side.eq(RealVal("10000000000000001/100000000000000000")) for side in _sides(second))


def test_a_literal_after_a_non_ascii_name_keeps_its_text():
    # The AST counts bytes; "\u00e9" takes two in UTF-8.
    name = "\u00e9t\u00e9"
    expr = SafeEvaluator().safe_eval(f"{name} == 0.10000000000000001", {name: Real(name)})
    assert any(side.eq(RealVal("10000000000000001/100000000000000000")) for side in _sides(expr))


def test_a_float_node_without_a_position_is_refused():
    transformer, node = _ExactArithmetic("x"), ast.Constant(0.5)
    with pytest.raises(ValueError):
        transformer.visit(node)


# --- the SymPy compiler bounds exact powers -----------------------------------


@pytest.mark.parametrize(
    "program",
    [
        "(GT (POW 9.0 1e1000) 1)",
        "(GT (POW 0.5 10000000000) 0)",
        "(GT (POW 9 (POW 9 9)) 1)",
        "(GT (POW 1.5 10001) 1)",
        "(GT (POW (POW 9.0 10000.0) 10000.0) 1)",
        "(GT (POW 9 1000000.5) 1)",
        # A fractional part asks SymPy for an exact root.
        "(GT (POW 2 1e-3999) 1)",
        "(GT (POW 2 1e-20) 1)",
        "(GT (POW " + "9" * 3999 + ".0 0.5) 1)",
        "(GT (POW " + "9" * 3999 + " 0.75) 1)",
        "(GT (POW " + "7" * 1000 + " 0.5) 1)",
        # An algebraic base: SymPy distributes the power over 2**4999 * sqrt(2).
        "(GT (POW (POW (POW (POW 2.0 0.5) 9999) 9999) 9999) 1)",
        "(GT (POW (POW (POW 2.0 0.5) 9999) 9999) 1)",
    ],
)
def test_a_huge_exact_power_is_refused_quickly(program):
    start = time.monotonic()
    result = SymPyCompiler().compile(parse_dsl(program)["ast"])
    assert not result.success
    assert time.monotonic() - start < 5


@pytest.mark.parametrize(
    "program",
    [
        "(EQ (POW 0.5 2) 0.25)",
        "(GT (POW x 1e1000) 1)",
        "(GT (POW 9 2.5) 1)",
        "(EQ (POW 1 1e1000) 1)",
        "(GT (POW 2 10000) 1)",
        # A fraction's numerator is not its size: 99999/100000 is below one.
        "(GT (POW 2 0.99999) 1)",
        "(GT (POW 3 10000.5) 1)",
        "(EQ (POW 4 0.5) 2)",
        "(GT (POW 2 1e-19) 1)",
        "(GT (POW " + "7" * 998 + "9 0.5) 1)",
        "(EQ (POW (POW 2.0 0.5) 2) 2)",
        "(GT (POW (POW 2.0 0.5) 9999) 1)",
        "(GT (POW (POW 3 0.5) (POW 2 0.5)) 1)",
        # SymPy combines (2**0.0001)**20000 into 2**2.
        "(EQ (POW (POW 2 0.0001) 20000) 4)",
    ],
)
def test_an_ordinary_exact_power_compiles(program):
    assert SymPyCompiler().compile(parse_dsl(program)["ast"]).success


# --- the direct reading of ASCII decimals agrees with Decimal ----------------

_ASCII_DECIMALS = st.builds(
    lambda sign, whole, point, fraction, exponent: f"{sign}{whole}{point}{fraction}{exponent}",
    st.sampled_from(["", "-", "+"]),
    st.one_of(st.just(""), st.integers(min_value=0, max_value=10**30).map(str), st.just("000")),
    st.sampled_from(["", "."]),
    st.one_of(st.just(""), st.integers(min_value=0, max_value=10**30).map(lambda n: str(n).zfill(3))),
    st.one_of(st.just(""), st.integers(min_value=-600, max_value=600).map(lambda e: f"e{e}"),
              st.integers(min_value=0, max_value=600).map(lambda e: f"E+{e:04d}")),
)


@settings(max_examples=500, deadline=None)
@given(text=_ASCII_DECIMALS)
def test_the_direct_reading_agrees_with_decimal(text):
    from decimal import Decimal, InvalidOperation

    try:
        expected = Fraction(Decimal(text))
    except InvalidOperation:
        expected = None
    try:
        got = exact_decimal(text)
    except ValueError:
        got = None
    # Every value drawn here is far inside the size bound, so a refusal of a
    # literal Decimal reads would be a false rejection.
    assert got == expected


def test_an_exponent_beyond_every_bound_is_refused_quickly():
    start = time.monotonic()
    for text in ["1e1234567890123456789", "1e-1234567890123456789", "1e" + "9" * 5000]:
        with pytest.raises(ValueError):
            exact_decimal(text)
    assert exact_decimal("1e" + "0" * 30 + "5") == Fraction(100000)
    # Leading zeros of the exponent do not count against Python's limit for
    # an integer written as text.
    assert exact_decimal("1e" + "0" * 5000 + "5") == Fraction(100000)
    assert exact_decimal("1e-" + "0" * 5000 + "5") == Fraction(1, 100000)
    assert time.monotonic() - start < 2
