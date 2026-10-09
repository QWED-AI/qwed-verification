"""Regression tests: verify_math must not lose precision on values with more
than 15 significant digits.

Advisory GHSA-j622-qffp-rc27: the decimal path called ``expr.evalf()`` at the
SymPy default of 15 significant digits, so large integers were rounded before
the comparison — an incorrect claim could be marked VERIFIED and a correct one
rejected.
"""
import pytest

from qwed_new.core.verifier import VerificationEngine


@pytest.fixture
def engine():
    return VerificationEngine()


@pytest.mark.parametrize(
    "expression,claimed,expected_status",
    [
        # 17-significant-digit integer: off-by-one must be rejected...
        ("10000000000000001", 10000000000000000, "CORRECTION_NEEDED"),
        # ...and the exact claim verified.
        ("10000000000000001", 10000000000000001, "VERIFIED"),
        # 2**64 has 20 digits.
        ("2**64", 18446744073709551616, "VERIFIED"),
        ("2**64", 18446744073709551615, "CORRECTION_NEEDED"),
        # A larger power, still exact.
        ("10**30", 10 ** 30, "VERIFIED"),
        ("10**30", 10 ** 30 + 1, "CORRECTION_NEEDED"),
    ],
)
def test_large_integer_precision(engine, expression, claimed, expected_status):
    result = engine.verify_math(expression, claimed)
    assert result["status"] == expected_status, result


def test_large_integer_is_compared_exactly(engine):
    result = engine.verify_math("10000000000000001", 10000000000000001)
    assert result["status"] == "VERIFIED"
    assert result["calculated_precise"] == "10000000000000001.000000"


@pytest.mark.parametrize(
    "expression,claimed,expected_status",
    [
        ("2 * (5 + 10)", 30, "VERIFIED"),
        ("1/3", "0.333333", "VERIFIED"),
        ("0.1 + 0.2", "0.3", "VERIFIED"),
        ("sqrt(2)", "1.414214", "VERIFIED"),
        ("100 - 1", 98, "CORRECTION_NEEDED"),
    ],
)
def test_small_values_unchanged(engine, expression, claimed, expected_status):
    assert engine.verify_math(expression, claimed)["status"] == expected_status
