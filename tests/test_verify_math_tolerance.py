from decimal import Decimal

from qwed_new.core.verifier import (
    INVALID_TOLERANCE_ERROR,
    TOLERANCE_POLICY_ERROR,
    VerificationEngine,
)


def test_verify_math_blocks_oversized_tolerance():
    engine = VerificationEngine()

    result = engine.verify_math("1 + 1", expected_value=999, tolerance=1000)

    assert result["is_correct"] is False
    assert result["status"] == "BLOCKED"
    assert result["error"] == TOLERANCE_POLICY_ERROR
    assert result["requested_tolerance"] == "1000"
    assert result["max_allowed_tolerance"] == "0.02000000"
    assert result["calculated_value"] == "2.000000"


def test_verify_math_blocks_negative_tolerance():
    engine = VerificationEngine()

    result = engine.verify_math("2 + 2", expected_value=4, tolerance=-1)

    assert result["is_correct"] is False
    assert result["status"] == "BLOCKED"
    assert result["error"] == INVALID_TOLERANCE_ERROR


def test_verify_math_blocks_non_finite_tolerance():
    engine = VerificationEngine()

    result = engine.verify_math("2 + 2", expected_value=4, tolerance=float("inf"))

    assert result["is_correct"] is False
    assert result["status"] == "BLOCKED"
    assert result["error"] == INVALID_TOLERANCE_ERROR


def test_verify_math_blocks_malformed_tolerance():
    engine = VerificationEngine()

    result = engine.verify_math("2 + 2", expected_value=4, tolerance="not-a-number")

    assert result["is_correct"] is False
    assert result["status"] == "BLOCKED"
    assert result["error"] == INVALID_TOLERANCE_ERROR


def test_verify_math_allows_bounded_large_magnitude_tolerance():
    engine = VerificationEngine()

    result = engine.verify_math(
        "10000 * (1 + 5/100)",
        expected_value=10540,
        tolerance=50,
    )

    assert result["status"] == "VERIFIED"
    assert result["is_correct"] is True


def test_verify_math_float_mode_uses_same_tolerance_policy():
    engine = VerificationEngine()

    result = engine.verify_math(
        "100 / 3",
        expected_value=33.4,
        tolerance=1,
        use_decimal=False,
    )

    assert result["status"] == "BLOCKED"
    assert result["error"] == TOLERANCE_POLICY_ERROR


def test_verify_math_decimal_tolerance_still_allows_small_precision_checks():
    engine = VerificationEngine()

    result = engine.verify_math(
        "1/10 + 2/10",
        expected_value=Decimal("0.3"),
        tolerance=Decimal("0.001"),
    )

    assert result["status"] == "VERIFIED"
    assert result["is_correct"] is True


def test_verify_math_preserves_syntax_errors_for_invalid_expression():
    engine = VerificationEngine()

    result = engine.verify_math("x in y", expected_value=0)

    assert result["is_correct"] is False
    assert result["status"] == "SYNTAX_ERROR"
