"""
The exact value of a decimal literal, read from its text (#636).

Read as a Python float, a decimal is first rounded to the nearest binary
fraction: ``0.10000000000000001`` becomes ``0.1``, ``1e-400`` becomes ``0.0``
and ``1e400`` becomes ``inf``. Turning that float into an exact number
afterwards is too late, as two different values have already become one, so a
formula could prove ``0.1 == 0.10000000000000001``. The value is therefore
read from the text as written.
"""
from decimal import Decimal, InvalidOperation
from fractions import Fraction

# A literal whose exact value would need more digits than this, above or below
# the fraction line, is refused, so a short text such as ``1e999999999``
# cannot build a huge integer. It stays below Python's default limit (4,300)
# for writing an integer as text, which Z3 values are built from.
MAX_DECIMAL_DIGITS = 4_000


def exact_decimal(text: str) -> Fraction:
    """The exact value ``text`` writes: ``"0.1"`` is 1/10.

    Raises ValueError when ``text`` is not a finite decimal (``inf`` and
    ``nan`` are refused), or when its exact value as a fraction would need
    more than MAX_DECIMAL_DIGITS digits in the numerator or the denominator.
    """
    try:
        value = Decimal(text)
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError(f"Not a decimal number: {text[:40]!r}") from None
    _sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        # 'n', 'N' or 'F': a NaN, a signalling NaN or an infinity.
        raise ValueError(f"Not a finite number: {text[:40]!r}")
    numerator_digits = len(digits) + max(exponent, 0)
    denominator_digits = max(-exponent, 0) + 1
    if max(numerator_digits, denominator_digits) > MAX_DECIMAL_DIGITS:
        raise ValueError(
            f"A decimal literal may need at most {MAX_DECIMAL_DIGITS} digits: {text[:40]!r}"
        )
    return Fraction(value)
