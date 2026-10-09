"""Regression tests for GHSA-mxwv-x5qm-mrmf (compute-cost bypass / DoS).

1. safe_parse_expr skipped the #353/#354 cost gates for expressions that are not
   valid Python (implicit multiplication), e.g. "9^9^9 x".
2. The logic (SafeEvaluator) and DSL (POW) engines had no exponent bound, so
   "x == 9**9**9" / (EQ x (POW 9 (POW 9 9))) expanded a huge integer on the
   request thread.

Each test is a correctness assertion; the fix also makes them fast (the
unpatched code hangs well past any CI timeout).
"""
import pytest

from qwed_new.core.safe_parser import safe_parse_expr, SafeParserError


# --- Parser: implicit-multiplication cost-gate bypass ------------------------

@pytest.mark.parametrize(
    "expression",
    [
        "9^9^9 x",             # caret chain + implicit multiplication
        "2^20000 x",           # exponent over the magnitude bound
        "factorial(50000) x",  # factorial argument over the bound
    ],
)
def test_implicit_multiplication_dos_is_rejected(expression):
    with pytest.raises(SafeParserError):
        safe_parse_expr(expression)


@pytest.mark.parametrize(
    "expression",
    ["2x", "3x + 1", "2(x+1)", "sin x", "x^2 + 2x + 1", "9^9", "factorial(5)", "10*x"],
)
def test_legitimate_implicit_multiplication_still_parses(expression):
    # Must not raise.
    safe_parse_expr(expression)


# --- Logic engine: unbounded integer power -----------------------------------

def test_logic_unbounded_power_is_blocked():
    from qwed_new.core.logic_verifier import LogicVerifier
    from qwed_new.core.diagnostics import DiagnosticStatus

    result = LogicVerifier(timeout_ms=2000).verify_logic({"x": "Int"}, ["x == 9**9**9"])
    assert result.status is DiagnosticStatus.BLOCKED


def test_logic_small_power_still_verifies():
    from qwed_new.core.logic_verifier import LogicVerifier
    from qwed_new.core.diagnostics import DiagnosticStatus

    result = LogicVerifier(timeout_ms=2000).verify_logic({"x": "Int"}, ["x == 2**10"])
    assert result.status is DiagnosticStatus.VERIFIED


# --- DSL compiler: unbounded POW ---------------------------------------------

def test_dsl_unbounded_pow_is_rejected():
    from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier

    result = DSLLogicVerifier(timeout_ms=2000).verify_from_dsl("(EQ x (POW 9 (POW 9 9)))")
    assert result.status != "SAT"


def test_dsl_small_pow_is_sat():
    from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier

    result = DSLLogicVerifier(timeout_ms=2000).verify_from_dsl("(EQ x (POW 2 10))")
    assert result.status == "SAT"
