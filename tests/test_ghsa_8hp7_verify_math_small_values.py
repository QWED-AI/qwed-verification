"""GHSA-8hp7-jqjc-hrhf: verify_math returned VERIFIED for wrong results at small
magnitudes and for wrong digits after the sixth decimal place.

The computed value was rounded to 6 decimal places before the comparison and
the default tolerance was an absolute 1e-6, so any claim near 0 matched a
value below about 1e-6, and the 7th decimal was never checked. A caller's
tolerance=0 did not make the comparison exact, and the tolerance cap had a
0.01 floor however small the value.
"""
import time
from decimal import Decimal

import pytest

from qwed_new.core.verifier import (
    CLAIM_OUT_OF_RANGE_ERROR,
    INVALID_TOLERANCE_ERROR,
    TOLERANCE_POLICY_ERROR,
    VerificationEngine,
)


@pytest.fixture
def engine():
    return VerificationEngine()


@pytest.mark.parametrize(
    ("expression", "claimed", "kwargs"),
    [
        ("1/1000000000", 0, {}),
        ("1/1000000000", 0, {"tolerance": 0}),
        ("9/10000000", 0, {}),
        ("1/3", 0.3333329, {}),
        ("1/3", 0.3333323, {}),
        ("1/3", Decimal("0.3333330"), {}),
        ("sqrt(2)", 1.4142139, {}),
        ("2**-30", 0, {}),
        ("1/3000000", 0, {}),
    ],
)
def test_wrong_small_values_and_7th_digits_are_disproven(engine, expression, claimed, kwargs):
    result = engine.verify_math(expression, claimed, **kwargs)
    assert result["is_correct"] is False, result
    assert result["status"] == "DISPROVEN", result


def test_a_tolerance_wider_than_a_small_value_is_refused(engine):
    result = engine.verify_math("1/1000000000", 0.005, tolerance=0.01)
    assert result["status"] == "BLOCKED"
    assert result["error"] == TOLERANCE_POLICY_ERROR


def test_a_precise_claim_within_a_tight_tolerance_is_verified(engine):
    # Only the computed side was rounded, so a claim correct to 1.9e-17 was
    # rejected under tolerance=1e-7.
    result = engine.verify_math("1/3", 0.3333333333333333, tolerance=1e-7)
    assert result["status"] == "VERIFIED", result


@pytest.mark.parametrize(
    ("expression", "claimed", "kwargs"),
    [
        ("2+2", 4, {}),
        ("10000000000000001", 10000000000000001, {}),
        ("0.1 + 0.2", 0.3, {}),
        ("sqrt(2)", 1.4142135623730951, {}),
        ("1/3", 0.333333, {}),
        ("sqrt(2)", 1.414214, {}),
        ("100/3", 33.333333333, {}),
        ("sin(pi)", 0, {}),
        ("1000*1.05**10", 1628.894626777442, {}),
        ("10000 * (1 + 5/100)", 10540, {"tolerance": 50}),
        ("247 * 83", 20501, {"tolerance": 1.0}),
        ("0.25", 0.25, {"tolerance": 0.01}),
        ("1/3", Decimal("0.3333333"), {}),
    ],
)
def test_correct_and_correctly_rounded_claims_are_still_verified(engine, expression, claimed, kwargs):
    result = engine.verify_math(expression, claimed, **kwargs)
    assert result["status"] == "VERIFIED", result


@pytest.mark.parametrize(
    ("expression", "claimed"),
    [("2+2", 5), ("10000000000000001", 10000000000000000), ("100/3", 33.33)],
)
def test_existing_disproofs_are_unchanged(engine, expression, claimed):
    assert engine.verify_math(expression, claimed)["status"] == "DISPROVEN"


def test_tolerance_zero_is_exact(engine):
    assert engine.verify_math("1/4", 0.25, tolerance=0)["status"] == "VERIFIED"
    assert engine.verify_math("1/3", 0.3333333333333333, tolerance=0)["status"] == "DISPROVEN"


def test_the_reported_difference_is_the_exact_one(engine):
    result = engine.verify_math("1/1000000000", 0)
    assert result["diff"] == pytest.approx(1e-9)


@pytest.mark.parametrize("claimed", [Decimal("NaN"), Decimal("Infinity"), float("nan")])
def test_a_non_finite_claim_is_never_verified(engine, claimed):
    result = engine.verify_math("2", claimed)
    assert result["is_correct"] is False
    assert result["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize(
    "claimed",
    # Built from a digit tuple: Decimal("1000...") with 5,001 digits fails
    # on a build without _decimal (int() digit limit, #570).
    [Decimal("1.00000E-999999999"), Decimal("1E+999999999"), Decimal((0, (1,) + (0,) * 5000, 0))],
)
def test_an_out_of_range_claim_is_refused_quickly(engine, claimed):
    start = time.monotonic()
    result = engine.verify_math("1/3", claimed)
    assert time.monotonic() - start < 5
    assert result["is_correct"] is False
    assert result["error"] == CLAIM_OUT_OF_RANGE_ERROR


def test_the_float_mode_uses_the_same_comparison(engine):
    assert engine.verify_math("1/1000000000", 0, use_decimal=False)["status"] == "DISPROVEN"
    assert engine.verify_math("1/3", 0.333333, use_decimal=False)["status"] == "VERIFIED"


# The half-unit allowance for a claim's last digit is inclusive, and the result
# says which rule admitted the claim.
@pytest.mark.parametrize("claimed", [Decimal("0.123456"), Decimal("0.123457")])
def test_a_claim_exactly_half_a_unit_away_is_a_rounded_match(engine, claimed):
    # 0.1234565 lies exactly halfway between 0.123456 and 0.123457.
    result = engine.verify_math("1234565/10000000", claimed, use_decimal=True)
    assert result["status"] == "VERIFIED", result
    assert result["match"] == {"kind": "rounded_claim", "tolerance_used": "0.0000005"}


def test_a_claim_just_over_half_a_unit_away_is_disproven(engine):
    result = engine.verify_math("12345651/100000000", Decimal("0.123456"), use_decimal=True)
    assert result["status"] == "DISPROVEN", result
    assert result["match"] is None


def test_an_exact_claim_says_exact(engine):
    result = engine.verify_math("1/4", 0.25)
    assert result["status"] == "VERIFIED"
    assert result["match"] == {"kind": "exact"}


def test_a_claim_within_the_default_bound_says_so(engine):
    # Off by 1e-10 of a value near 1: inside 9 significant digits, so the
    # rounding allowance is not what admitted it.
    result = engine.verify_math("1/3", Decimal("0.3333333334"), use_decimal=True)
    assert result["status"] == "VERIFIED", result
    assert result["match"]["kind"] == "default_bound"


def test_a_caller_tolerance_is_reported(engine):
    result = engine.verify_math("1/3", 0.3333, tolerance=0.001)
    assert result["status"] == "VERIFIED", result
    assert result["match"] == {"kind": "caller_tolerance", "tolerance_used": "0.001"}


@pytest.mark.parametrize(
    "tolerance",
    [Decimal("1e-999999999"), "1e-99999999", Decimal((0, (1,), -4002)), Decimal((0, (1,) * 4002, -4001))],
)
def test_a_tolerance_too_small_or_too_long_to_compare_exactly_is_refused(engine, tolerance):
    # The comparison is exact, so 1e-999999999 would build an integer of a
    # billion digits; the tolerance is bounded as a claim is.
    started = time.monotonic()
    result = engine.verify_math("1/3", Decimal("0.3333333333"), tolerance=tolerance)
    assert time.monotonic() - started < 5
    assert result["status"] == "BLOCKED"
    assert result["error"] == INVALID_TOLERANCE_ERROR


def test_a_small_but_ordinary_tolerance_still_works(engine):
    result = engine.verify_math("1/3", Decimal("0.333333333333"), tolerance=Decimal("1e-12"))
    assert result["status"] == "VERIFIED", result


@pytest.mark.parametrize("symbol", ["x", "zoo"])
def test_a_value_that_is_not_a_finite_number_is_never_compared(engine, symbol):
    # The value has no integer part to size the precision with, and no
    # decimal value: comparing it fails rather than matching any claim.
    import sympy
    from decimal import InvalidOperation

    value, claim = sympy.sympify(symbol), Decimal(1)
    with pytest.raises(InvalidOperation):
        engine._claim_difference(value, claim)
