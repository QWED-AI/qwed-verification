"""Regression tests: Money must reject non-finite amounts and verify_invoice_total must never raise."""

from decimal import Decimal

import pytest

from qwed_new.core.money import Money, verify_invoice_total


@pytest.mark.parametrize("amount", ["NaN", "sNaN", "Infinity", "-Infinity", float("nan"), float("inf"), Decimal("NaN")])
def test_money_rejects_non_finite_amount(amount):
    with pytest.raises(ValueError, match="finite"):
        Money(amount)


def test_money_accepts_finite_amount():
    assert Money("100.50").amount == Decimal("100.50")


def test_verify_invoice_total_non_finite_tolerance_returns_false():
    ok, message = verify_invoice_total(Money("100"), Money("18"), Money("118"), tolerance=Decimal("NaN"))
    assert ok is False
    assert message


def test_verify_invoice_total_invalid_input_returns_false():
    ok, message = verify_invoice_total(Money("100"), Money("18"), None)
    assert ok is False
    assert message
