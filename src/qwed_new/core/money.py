"""
Financial Precision Module.

This module provides enterprise-grade financial calculations using
Python's Decimal for exact arithmetic (no floating point errors).

QWED uses this for invoice verification where 0.1 + 0.2 MUST equal 0.3.
"""

from decimal import Decimal, ROUND_HALF_UP
from typing import Union


class UnitMismatchError(Exception):
    """
    Raised when attempting to combine amounts with different currencies.
    
    Example:
        >>> Money("100", "USD") + Money("50", "EUR")
        UnitMismatchError: Cannot add USD + EUR without conversion rate
    """
    pass


class Money:
    """
    Enterprise-grade monetary value with currency tracking.
    
    Uses Decimal internally to prevent floating-point precision errors
    that are common in finance (e.g., 0.1 + 0.2 != 0.3 in float).
    
    Attributes:
        amount: The monetary value as Decimal
        currency: ISO 4217 currency code (e.g., "INR", "USD", "EUR")
    
    Example:
        >>> price = Money("100.50", "INR")
        >>> tax = Money("18.09", "INR")
        >>> total = price + tax
        >>> print(total)  # Money(118.59, INR)
    """
    
    # Default precision: 2 decimal places for most currencies
    DEFAULT_PRECISION = Decimal("0.01")
    
    def __init__(self, amount: Union[str, int, float, Decimal], currency: str = "INR"):
        """
        Initialize a Money object.
        
        Args:
            amount: The monetary value. String recommended for precision.
            currency: ISO 4217 currency code (default: INR)
        
        Raises:
            InvalidOperation: If amount cannot be converted to Decimal
        """
        if isinstance(amount, float):
            # Convert float to string first to avoid precision loss
            amount = str(amount)
        
        self.amount = Decimal(str(amount))
        self.currency = currency.upper()
    
    def __add__(self, other: "Money") -> "Money":
        """Add two Money objects (must have same currency)."""
        self._validate_currency(other)
        return Money(
            str(self.amount + other.amount),
            self.currency
        )
    
    def __sub__(self, other: "Money") -> "Money":
        """Subtract two Money objects (must have same currency)."""
        self._validate_currency(other)
        return Money(
            str(self.amount - other.amount),
            self.currency
        )
    
    def __mul__(self, multiplier: Union[int, float, Decimal]) -> "Money":
        """Multiply Money by a scalar (e.g., quantity)."""
        result = self.amount * Decimal(str(multiplier))
        return Money(str(result), self.currency)
    
    def __truediv__(self, divisor: Union[int, float, Decimal]) -> "Money":
        """Divide Money by a scalar."""
        if divisor == 0:
            raise ZeroDivisionError("Cannot divide money by zero")
        result = self.amount / Decimal(str(divisor))
        return Money(str(result), self.currency)
    
    def __eq__(self, other: "Money") -> bool:
        """Check equality (amount and currency must match)."""
        if not isinstance(other, Money):
            return False
        return self.amount == other.amount and self.currency == other.currency
    
    def __lt__(self, other: "Money") -> bool:
        """Less than comparison."""
        self._validate_currency(other)
        return self.amount < other.amount
    
    def __le__(self, other: "Money") -> bool:
        """Less than or equal comparison."""
        self._validate_currency(other)
        return self.amount <= other.amount
    
    def __gt__(self, other: "Money") -> bool:
        """Greater than comparison."""
        self._validate_currency(other)
        return self.amount > other.amount
    
    def __ge__(self, other: "Money") -> bool:
        """Greater than or equal comparison."""
        self._validate_currency(other)
        return self.amount >= other.amount
    
    def __repr__(self) -> str:
        """String representation."""
        return f"Money({self.amount}, {self.currency})"
    
    def __str__(self) -> str:
        """Human-readable string."""
        return f"{self.currency} {self.amount:.2f}"
    
    def _validate_currency(self, other: "Money") -> None:
        """Ensure both Money objects have the same currency."""
        if self.currency != other.currency:
            raise UnitMismatchError(
                f"Cannot combine {self.currency} with {other.currency}. "
                f"Use convert() to change currency first."
            )
    
    def round(self, precision: Decimal = None) -> "Money":
        """
        Round the amount to specified precision.
        
        Args:
            precision: Decimal precision (default: 0.01 for 2 decimal places)
        
        Returns:
            New Money object with rounded amount
        """
        precision = precision or self.DEFAULT_PRECISION
        rounded = self.amount.quantize(precision, rounding=ROUND_HALF_UP)
        return Money(str(rounded), self.currency)
    
    def to_float(self) -> float:
        """
        Convert to float (LOSSY - use only for display).
        
        Warning: This loses precision. Use only for UI display,
        never for calculations.
        """
        return float(self.amount)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary (for JSON)."""
        return {
            "amount": str(self.amount),
            "currency": self.currency
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Money":
        """Deserialize from dictionary."""
        return cls(data["amount"], data["currency"])


# Utility function for invoice verification
def verify_invoice_total(
    subtotal: Money,
    tax: Money,
    claimed_total: Money,
    tolerance: Decimal = Decimal("0.01")
) -> tuple[bool, str]:
    """
    Verify that an invoice total is mathematically correct.
    
    Args:
        subtotal: The pre-tax amount
        tax: The tax amount
        claimed_total: The total claimed on the invoice
        tolerance: Allowed rounding difference (default: 0.01)
    
    Returns:
        Tuple of (is_valid, message)
    
    Example:
        >>> subtotal = Money("1000.00", "INR")
        >>> tax = Money("180.00", "INR")
        >>> total = Money("1180.00", "INR")
        >>> verify_invoice_total(subtotal, tax, total)
        (True, "Invoice total is correct")
    """
    try:
        calculated = subtotal + tax
        diff = abs(calculated.amount - claimed_total.amount)
        
        if diff <= tolerance:
            return True, "Invoice total is correct"
        else:
            return False, (
                f"Math error detected: {subtotal} + {tax} = {calculated}, "
                f"but invoice claims {claimed_total}. Difference: {diff}"
            )
    except UnitMismatchError as e:
        return False, f"Currency mismatch: {str(e)}"
