"""
Exact arithmetic for numbers written in logic constraints (GHSA-w73j).

Python computes an operation whose operands are both plain numbers before Z3
sees it: ``1/3`` becomes the float 0.333..., ``0.1 + 0.2`` becomes
0.30000000000000004 and ``7/2`` becomes 3.5. The same operator on a Z3
variable stays exact (Real) or is integer division (Int), so one formula could
use two arithmetics and prove a false statement. These helpers keep every
number exact and every division under one rule.
"""
from fractions import Fraction
from typing import Any

from z3 import IntVal, RealVal, is_arith


def _is_number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _sort(value: Any) -> str:
    """"number" for a Python int, "int" or "real" for a Z3 arithmetic term."""
    if _is_number(value):
        return "number"
    if is_arith(value):
        return "int" if value.is_int() else "real"
    return "other"


def exact_real(text: str) -> Any:
    """The decimal literal ``text`` as written (0.1 is 1/10), as a Z3 Real."""
    value = Fraction(text)
    return RealVal(f"{value.numerator}/{value.denominator}")


def literal(value: Any) -> Any:
    """A number written in a formula: an int as it is, a float as the exact
    decimal it was written as."""
    return exact_real(repr(value)) if isinstance(value, float) else value


def reject_booleans(operator: str, *operands: Any) -> None:
    """A Python bool is an int to Python, so True / 3 was computed as the
    float 0.333... before Z3 saw it. The DSL compiler already refuses
    arithmetic on a Boolean; the evaluator's helpers do the same."""
    if any(isinstance(operand, bool) for operand in operands):
        raise ValueError(f"{operator} applies arithmetic to a Boolean value")


def reject_mixed_sorts(operator: str, left: Any, right: Any) -> None:
    """An Int term combined with a Real one is coerced by Z3 (ToReal), so
    integer and real division can meet in one formula. Refuse it."""
    if {_sort(left), _sort(right)} == {"int", "real"}:
        raise ValueError(f"{operator} mixes an Int term with a Real term; make both the same sort")


def rational(value: Fraction, int_context: bool, operator: str) -> Any:
    """``value`` as an int when whole, else as an exact Z3 Real. Next to Int
    variables an inexact result is refused: whether ``/`` meant integer or
    real division there is not known."""
    if value.denominator == 1:
        return value.numerator
    if int_context:
        raise ValueError(f"{operator} of two numbers is not whole next to Int variables; write the value exactly")
    return RealVal(f"{value.numerator}/{value.denominator}")


def divide(left: Any, right: Any, int_context: bool) -> Any:
    """``left / right`` with numbers divided exactly, not as Python floats."""
    reject_booleans("Division", left, right)
    if _is_number(left) and _is_number(right):
        if right == 0:
            raise ValueError("division by zero")
        return rational(Fraction(left, right), int_context, "Division")
    reject_mixed_sorts("Division", left, right)
    return left / right


def modulo(left: Any, right: Any) -> Any:
    """``left % right`` as Z3 computes it (the remainder is never negative),
    which Python's ``%`` does not for a negative divisor."""
    reject_booleans("Modulo", left, right)
    if _is_number(left) and _is_number(right):
        if right == 0:
            raise ValueError("modulo by zero")
        return left % abs(right)
    reject_mixed_sorts("Modulo", left, right)
    return left % right


def power(base: Any, exponent: Any, int_context: bool) -> Any:
    """``base ** exponent``; a negative whole power of a number is exact."""
    reject_booleans("Power", base, exponent)
    if _is_number(base) and _is_number(exponent) and exponent < 0:
        if base == 0:
            raise ValueError("zero to a negative power")
        return rational(Fraction(base) ** exponent, int_context, "Power")
    return base ** exponent


def integer_divide(left: Any, right: Any) -> Any:
    """DSL DIV: two integer literals divide as Z3 Ints, as an Int variable
    would, so (DIV 7 2) and (DIV x 2) with x = 7 agree."""
    reject_booleans("DIV", left, right)
    if _is_number(left) and _is_number(right):
        if right == 0:
            raise ValueError("division by zero")
        return IntVal(left) / IntVal(right)
    reject_mixed_sorts("DIV", left, right)
    return left / right
