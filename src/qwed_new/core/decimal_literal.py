"""
The exact value of a decimal literal, read from its text (#636).

Read as a Python float, a decimal is first rounded to the nearest binary
fraction: ``0.10000000000000001`` becomes ``0.1``, ``1e-400`` becomes ``0.0``
and ``1e400`` becomes ``inf``. Turning that float into an exact number
afterwards is too late, as two different values have already become one, so a
formula could prove ``0.1 == 0.10000000000000001``. The value is therefore
read from the text as written.
"""
import sys
from decimal import Decimal, InvalidOperation
from fractions import Fraction

# A literal whose exact value would need more digits than this, above or below
# the fraction line, is refused, so a short text such as ``1e999999999``
# cannot build a huge integer. It stays below Python's default limit (4,300)
# for writing an integer as text, which Z3 values are built from.
MAX_DECIMAL_DIGITS = 4_000
# Longer text is refused before it is read at all. A literal within the digit
# bound is far shorter, even with underscores, zeros that cancel and an
# exponent.
MAX_DECIMAL_TEXT = 3 * MAX_DECIMAL_DIGITS


def _digit_limit() -> int:
    """MAX_DECIMAL_DIGITS, or the process's own lower limit for writing an
    integer as text (``sys.set_int_max_str_digits``), if one is set."""
    get_limit = getattr(sys, "get_int_max_str_digits", None)
    limit = get_limit() if get_limit is not None else 0
    return min(MAX_DECIMAL_DIGITS, limit) if limit else MAX_DECIMAL_DIGITS


def _read(text: str) -> Decimal:
    if not isinstance(text, str) or len(text) > MAX_DECIMAL_TEXT:
        raise ValueError(f"Not a decimal number QWED reads: {str(text)[:40]!r}")
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError):
        raise ValueError(f"Not a decimal number: {text[:40]!r}") from None


def reads_as_decimal(text: str) -> bool:
    """True when ``text`` is a number in Python's decimal grammar, finite or not
    (``sNaN`` is one that ``float()`` does not read)."""
    try:
        _read(text)
    except ValueError:
        return False
    return True


def exact_decimal(text: str) -> Fraction:
    """The exact value ``text`` writes: ``"0.1"`` is 1/10.

    Raises ValueError when ``text`` is not a finite decimal (``inf``, ``nan``
    and ``sNaN`` are refused), is longer than MAX_DECIMAL_TEXT, or when its
    exact value as a fraction would need more than MAX_DECIMAL_DIGITS digits
    (or the process's lower limit) in the numerator or the denominator.
    """
    sign, digits, exponent = _read(text).as_tuple()
    if not isinstance(exponent, int):
        # 'n', 'N' or 'F': a NaN, a signalling NaN or an infinity.
        raise ValueError(f"Not a finite number: {text[:40]!r}")
    # Zeros at the end of the coefficient cancel: 1000e-3 is 1, 0e99 is 0.
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant == 1 and digits[0] == 0:
        return Fraction(0)
    exponent += len(digits) - significant
    numerator_digits = significant + max(exponent, 0)
    denominator_digits = max(-exponent, 0) + 1
    limit = _digit_limit()
    if max(numerator_digits, denominator_digits) > limit:
        raise ValueError(f"A decimal literal may need at most {limit} digits: {text[:40]!r}")
    coefficient = int("".join(map(str, digits[:significant])))
    if sign:
        coefficient = -coefficient
    if exponent >= 0:
        return Fraction(coefficient * 10**exponent)
    return Fraction(coefficient, 10**-exponent)
