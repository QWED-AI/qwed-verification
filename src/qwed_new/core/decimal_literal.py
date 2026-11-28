"""
The exact value of a decimal literal, read from its text (#636).

Read as a Python float, a decimal is first rounded to the nearest binary
fraction: ``0.10000000000000001`` becomes ``0.1``, ``1e-400`` becomes ``0.0``
and ``1e400`` becomes ``inf``. Turning that float into an exact number
afterwards is too late, as two different values have already become one, so a
formula could prove ``0.1 == 0.10000000000000001``. The value is therefore
read from the text as written.
"""
import re
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


def _process_int_limit() -> int:
    """The process's limit on digits when an integer is read from or written
    as text (``sys.set_int_max_str_digits``, Python 3.11 and later); 0 for
    none."""
    if sys.version_info >= (3, 11):
        return sys.get_int_max_str_digits()
    return 0


def _digit_limit() -> int:
    """MAX_DECIMAL_DIGITS, or the process's own lower limit for writing an
    integer as text, if one is set."""
    limit = _process_int_limit()
    return min(MAX_DECIMAL_DIGITS, limit) if limit else MAX_DECIMAL_DIGITS


def _int_text_limit() -> int:
    """The most digits int() reads from text in this process."""
    return _process_int_limit() or MAX_DECIMAL_TEXT


def _read(text: str) -> Decimal:
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError):
        raise ValueError(f"Not a decimal number: {text[:40]!r}") from None


# The spellings of a NaN or an infinity that Python reads, payload digits
# (of any script, as Decimal reads them) included. float() reads all of them
# but the signalling NaN (sNaN) and a NaN with a payload.
_NON_FINITE = re.compile(r"[+-]?(?:s?nan\d*|inf(?:inity)?)", re.IGNORECASE)
_NON_FINITE_FIRST = ("s", "S", "n", "N", "i", "I")


def names_a_non_finite_number(text: str) -> bool:
    """True when ``text`` spells a NaN or an infinity, ``sNaN`` included.
    Matched by its spelling alone: the decimal grammar also skips underscores,
    so it would read the name ``_1`` as the number 1."""
    first = text[1:2] if text[:1] in ("+", "-") else text[:1]
    # Most names cannot be one: the first letter settles it without the pattern.
    return first in _NON_FINITE_FIRST and _NON_FINITE.fullmatch(text) is not None


# A decimal in ASCII digits, the usual form, is read directly; any other form
# (underscores, digits of other scripts, a NaN) goes through Decimal.
# re.ASCII: here \d is 0-9 only.
_PLAIN = re.compile(r"([+-]?)(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?", re.ASCII)
# An exponent with more digits than this is far beyond every bound.
_MAX_EXPONENT_DIGITS = 18


def _power(exponent: str | None, text: str) -> int:
    """The exponent written after ``e``, or 0. Leading zeros are dropped
    first: int() counts them against Python's limit for an integer written
    as text."""
    if exponent is None:
        return 0
    magnitude = exponent.lstrip("+-").lstrip("0") or "0"
    if len(magnitude) > _MAX_EXPONENT_DIGITS:
        raise ValueError(f"A decimal literal's exponent is too large: {text[:40]!r}")
    return -int(magnitude) if exponent.startswith("-") else int(magnitude)


def _parts(text: str) -> tuple[bool, str, int]:
    """(negative, coefficient digits, exponent) of a finite decimal."""
    if not isinstance(text, str) or len(text) > MAX_DECIMAL_TEXT:
        raise ValueError(f"Not a decimal number QWED reads: {str(text)[:40]!r}")
    plain = _PLAIN.fullmatch(text)
    if plain is not None and (plain.group(2) or plain.group(3)):
        sign, whole, fraction, exponent = plain.groups()
        fraction = fraction or ""
        return sign == "-", whole + fraction, _power(exponent, text) - len(fraction)
    sign, digits, exponent = _read(text).as_tuple()
    if not isinstance(exponent, int):
        # 'n', 'N' or 'F': a NaN, a signalling NaN or an infinity.
        raise ValueError(f"Not a finite number: {text[:40]!r}")
    return bool(sign), "".join(map(str, digits)), exponent


def exact_decimal(text: str) -> Fraction:
    """The exact value ``text`` writes: ``"0.1"`` is 1/10.

    Raises ValueError when ``text`` is not a finite decimal (``inf``, ``nan``
    and ``sNaN`` are refused), is longer than MAX_DECIMAL_TEXT, or when its
    exact value as a reduced fraction would need more than MAX_DECIMAL_DIGITS
    digits (or the process's lower limit) in the numerator or the denominator.
    """
    negative, digits, exponent = _parts(text)
    # Zeros at the end of the coefficient cancel (1000e-3 is 1, 0e99 is 0),
    # and zeros at its start count for nothing.
    trimmed = digits.rstrip("0")
    exponent += len(digits) - len(trimmed)
    trimmed = trimmed.lstrip("0")
    if not trimmed:
        return Fraction(0)
    limit = _digit_limit()
    too_large = f"A decimal literal may need at most {limit} digits: {text[:40]!r}"
    if exponent >= 0:
        # A whole number: exactly len(trimmed) + exponent digits.
        if len(trimmed) + exponent > limit:
            raise ValueError(too_large)
        coefficient = int(trimmed)
        return Fraction(-coefficient * 10**exponent if negative else coefficient * 10**exponent)
    # Factors of 2 and 5 in the coefficient cancel against 10**k. The reduced
    # numerator keeps at least len(trimmed) - k digits and the reduced
    # denominator at least k + 1 - len(trimmed): past either, the value cannot
    # fit and nothing is built. int() also has a limit of its own.
    k = -exponent
    if len(trimmed) - k > limit or k + 1 - len(trimmed) > limit or len(trimmed) > _int_text_limit():
        raise ValueError(too_large)
    coefficient = int(trimmed)
    value = Fraction(-coefficient if negative else coefficient, 10**k)
    bound = 10**limit
    if abs(value.numerator) >= bound or value.denominator >= bound:
        raise ValueError(too_large)
    return value
