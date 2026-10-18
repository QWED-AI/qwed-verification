"""
Enterprise Math Verification Engine.

The deterministic core. It does not guess. It calculates.
Uses Symbolic Math (SymPy) to verify mathematical assertions.

Enterprise Features:
- Calculus (derivatives, integrals, limits)
- Matrix/Linear Algebra
- Financial Formulas (NPV, IRR, compound interest)
- Statistics (mean, stddev, variance, correlation)
- Unit Conversion
- Decimal precision for financial calculations
"""

from sympy import (
    Symbol, Matrix, Integer, Rational, Float, Poly, Integral, factor_list,
    diff, integrate, limit, oo,
    simplify, expand, evaluate
)
from sympy.core.assumptions import check_assumptions
from qwed_new.core.safe_parser import (
    check_closed_expression_cost,
    get_safe_symbol,
    safe_parse_expr,
)
from sympy.parsing.sympy_parser import standard_transformations, implicit_multiplication_application
from typing import Any, Dict, List, Optional
from decimal import Decimal, ROUND_HALF_UP, localcontext
from fractions import Fraction
from dataclasses import dataclass
import ast
import re
import unicodedata
import math

INVALID_TEMPERATURE_UNIT_ERROR = "Invalid temperature unit"
INVALID_TOLERANCE_ERROR = "Invalid tolerance"
TOLERANCE_POLICY_ERROR = "Tolerance exceeds deterministic verification bound"
VERIFY_LOGIC_RULE_DEPRECATED_ERROR = (
    "verify_logic_rule is deprecated and fail-closed; use LogicVerifier instead"
)

# Legacy status for a claim the engine deterministically proved FALSE (#437).
# It is a decided verdict, not an inconclusive one: consumers map it to
# DiagnosticStatus.VERIFIED with is_valid False, so admission is DENY.
DISPROVEN_STATUS = "DISPROVEN"
# Legacy status when the engine could neither prove nor disprove the claim
# (e.g. simplify() did not reduce a symbolic difference to a decided value).
INCONCLUSIVE_STATUS = "INCONCLUSIVE"


def _is_finite_value(value: Any) -> bool:
    """True when a computed or claimed value is a finite number."""
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return True  # exact; math.isfinite would overflow on huge ints
    if isinstance(value, Decimal):
        return value.is_finite()
    if isinstance(value, float):
        return math.isfinite(value)
    return getattr(value, "is_finite", None) is True


def _numeric_status(is_correct: bool, *values: Any) -> str:
    """Status for a claim decided by a concrete computation.

    The computation that would justify VERIFIED on a match equally justifies
    DISPROVEN on a mismatch, so a mismatch is a decided verdict. A mismatch
    involving a non-finite value (an overflowed sum, a NaN claim) is a failed
    computation, not a counter-proof, so it stays INCONCLUSIVE.
    """
    if is_correct:
        return "VERIFIED"
    if not all(_is_finite_value(value) for value in values):
        return INCONCLUSIVE_STATUS
    return DISPROVEN_STATUS


# Rounding window around an exact matrix entry that is not a double: a float
# claim inside it cannot be told apart from rounding, so it is undecided (never
# accepted). Relative to the magnitude, with an absolute floor against zero.
_MATRIX_FLOAT_REL_TOLERANCE = Decimal("1e-9")
_MATRIX_FLOAT_ABS_TOLERANCE = Decimal("1e-12")


def _exact_claim(entry: Any) -> Any:
    """A claimed Float as the decimal the caller wrote (0.3 -> 3/10).

    ``repr(float)`` is the shortest decimal that round-trips the double, so it
    recovers the written literal instead of the binary approximation.
    """
    return Rational(repr(float(entry))) if entry.is_Float else entry


def _decimal_parts(entry: Any, precision: int = 30) -> Optional[tuple]:
    """Real and imaginary parts as Decimals, evaluated in SymPy (never through
    a binary double, which overflows past 1.8e308); None if not numeric or
    not finite."""
    real, imag = entry.evalf(precision).as_real_imag()
    try:
        parts = Decimal(str(real)), Decimal(str(imag))
    except ArithmeticError:
        return None
    return parts if all(part.is_finite() for part in parts) else None


def _decimals_close(a: Decimal, b: Decimal) -> bool:
    """Relative closeness; the absolute floor applies only against zero, so
    it never swamps the relative bound for small non-zero values."""
    if a == 0 or b == 0:
        return abs(a - b) <= _MATRIX_FLOAT_ABS_TOLERANCE
    return abs(a - b) <= _MATRIX_FLOAT_REL_TOLERANCE * max(abs(a), abs(b))


def _floats_close(computed: Any, claimed: Any) -> Optional[bool]:
    computed_parts, claimed_parts = _decimal_parts(computed), _decimal_parts(claimed)
    if computed_parts is None or claimed_parts is None:
        return None
    for a, b in zip(computed_parts, claimed_parts):
        if not _decimals_close(a, b):
            return False
    return True


def _nearest_double(value: Any) -> Optional[float]:
    """The correctly rounded double of an exact rational, or None."""
    if not value.is_Rational:
        return None
    try:
        nearest = float(Fraction(int(value.p), int(value.q)))
    except OverflowError:
        return None
    return nearest if math.isfinite(nearest) else None


def _exact_vs_float_claim(computed: Any, claimed: Any) -> Optional[bool]:
    """Compare an exact computed entry with a Float claim.

    - An exact integer, or an exact value that is a double: the claim holds
      when its written decimal or its double is exactly that value. A claim
      whose double only rounds to the same double (1000000000000000001.0 and
      1e18 are one double) cannot be told apart from rounding, so it is
      undecided, never accepted and never disproven.
    - A fractional value that is not a double (1/3): the best a float claim
      can say is the correctly rounded double, which is accepted. Another
      claim inside the rounding window is undecided.
    - Anything outside those is a decided mismatch.
    """
    nearest = _nearest_double(computed)
    if computed.is_Integer or (nearest is not None and Rational(nearest) == computed):
        if (computed - _exact_claim(claimed)).equals(0) or Rational(float(claimed)) == computed:
            return True
        if nearest is not None and float(claimed) == nearest:
            return None
        return False
    if nearest is not None and nearest != 0 and float(claimed) == nearest:
        # A non-zero value that underflows to 0.0 never accepts a 0.0 claim:
        # that claim falls through to the window check and stays undecided.
        return True
    close = _floats_close(computed, claimed)
    return None if close else close


def _matrix_entry_match(computed: Any, claimed: Any) -> Optional[bool]:
    """True / False when decided, None when undecided.

    Computed entries are exact: element-wise operations run on the inputs
    read as the decimals the caller wrote.
    """
    if claimed.is_Float:
        return _exact_vs_float_claim(computed, claimed)
    return (computed - claimed).equals(0)


def _matrix_comparison_status(result: Any, expected: Any) -> str:
    """Status for comparing a computed matrix with the claimed one.

    - A shape mismatch is a decided disproof.
    - A non-finite entry on either side (inf, nan) is a failed computation or
      claim, not a counter-proof: INCONCLUSIVE.
    - Each entry is compared on its own. Computed entries are exact (inputs
      are read as the decimals the caller wrote). A float claim of an exact
      entry holds only when its decimal or its double is exactly that value,
      or when it is the correctly rounded double of a fraction that is not a
      double; a claim that only rounds to it, or lies inside the rounding
      window, is undecided.
    - One decided mismatch disproves the claim; any undecided entry otherwise
      leaves it INCONCLUSIVE.
    """
    if result.shape != expected.shape:
        return DISPROVEN_STATUS
    if any(entry.is_finite is not True for entry in (*result, *expected)):
        return INCONCLUSIVE_STATUS
    matches = [_matrix_entry_match(a, b) for a, b in zip(result, expected)]
    if any(match is False for match in matches):
        return DISPROVEN_STATUS
    if all(match is True for match in matches):
        return "VERIFIED"
    return INCONCLUSIVE_STATUS


# Absolute tolerance for a numeric value (definite integral, eigenvalue)
# against its claim.
_SCALAR_TOLERANCE = Decimal("0.000001")
# Relative spacing of a binary double (2**-52): the claim's own representation
# error is at most this times its magnitude.
_DOUBLE_SPACING = Decimal(2) ** -52
# Past this many significant digits a numeric difference is too costly to
# establish to 1e-6, so the comparison stays undecided.
_MAX_SCALAR_PRECISION = 120


def _magnitude(value: Any) -> Optional[Decimal]:
    parts = _decimal_parts(value)
    return None if parts is None else max(abs(part) for part in parts)


def _scalar_status(actual: Any, claimed: Any) -> str:
    """Status for a computed number against a claimed number.

    - A non-finite value (a divergent integral) is INCONCLUSIVE.
    - Exact on both sides (no Float, no unevaluated Integral): decided exactly.
    - Otherwise the DIFFERENCE is evaluated at a precision scaled to the
      magnitude, so rounding never hides a mismatch above the 1e-6 tolerance
      (10**400 + 1 vs 1e400 differs by 1, not 0) and never invents one.
      A mismatch beyond the tolerance but within the claim's own double
      representation error cannot be told apart from rounding, so it is
      INCONCLUSIVE; anything larger is a decided mismatch.
    """
    if actual.is_finite is False or claimed.is_finite is False:
        return INCONCLUSIVE_STATUS
    if not (actual.has(Float, Integral) or claimed.has(Float)):
        return symbolic_difference_status(simplify(actual - claimed))
    magnitudes = [_magnitude(actual), _magnitude(claimed)]
    if None in magnitudes:
        return INCONCLUSIVE_STATUS
    magnitude = max(magnitudes)
    window = _SCALAR_TOLERANCE + magnitude * _float_spacing(actual, claimed)
    digits = magnitude.adjusted() + 1 if magnitude else 1
    precision = max(30, digits + 15)
    if precision > _MAX_SCALAR_PRECISION:
        return _coarse_scalar_status(actual, claimed, window)
    # Subtract with every Float replaced by its exact value: SymPy would
    # otherwise round the exact side to the Float's precision first, so
    # 2**53 + 1 minus 9007199254740992.0 would come out as 0.
    parts = _decimal_parts(_exact_floats(actual) - _exact_floats(claimed), precision)
    if parts is None:
        return INCONCLUSIVE_STATUS
    differences = [abs(part) for part in parts]
    if all(difference <= _SCALAR_TOLERANCE for difference in differences):
        return "VERIFIED"
    if all(difference <= window for difference in differences):
        return INCONCLUSIVE_STATUS
    return DISPROVEN_STATUS


# SymPy parses a 16-17 digit string (how Python's repr writes a double) at up
# to 60 bits, so a Float at or below this may be a double and is treated as one.
_DOUBLE_REPR_MAX_PRECISION = 60


def _float_spacing(*values: Any) -> Decimal:
    """Relative representation error of the least precise Float involved.

    - Up to 60 bits, a double's 2**-52 is the floor: a claim like
      "3141592653589.793" is the repr of a double, parsed at 56 bits, and a
      narrower window would turn the double's own rounding into a
      counter-proof. A Float deliberately less precise than a double
      (``Float(1/3, 3)``) keeps its own, wider spacing.
    - Above 60 bits (a 30-digit claim) the Float is clearly more precise
      than any double repr and gets its own, narrower spacing.
    - With no Float atom, a double's spacing is used.
    """
    precisions = [f._prec for value in values for f in value.atoms(Float)]
    if not precisions:
        return _DOUBLE_SPACING
    own_spacing = Decimal(2) ** -(min(precisions) - 1)
    if min(precisions) <= _DOUBLE_REPR_MAX_PRECISION:
        return max(own_spacing, _DOUBLE_SPACING)
    return own_spacing


def _exact_floats(value: Any) -> Any:
    """``value`` with each Float replaced by the exact rational it stores."""
    return value.xreplace({f: Rational(f) for f in value.atoms(Float)})


def _coarse_scalar_status(actual: Any, claimed: Any, window: Decimal) -> str:
    """Decide a mismatch too large in magnitude to subtract at full precision.

    At 30 digits the evaluation error is ~1e-29 of the magnitude, far below
    the claim's double spacing (~2.2e-16 of it). A gap wider than a thousand
    windows is therefore a decided mismatch (2e200 vs 1e200); anything closer
    stays undecided. Agreement is never decided here.
    """
    actual_parts = _decimal_parts(actual)
    if actual_parts is None:
        return INCONCLUSIVE_STATUS
    claimed_parts = _decimal_parts(claimed)
    if claimed_parts is None:
        return INCONCLUSIVE_STATUS
    gaps = [abs(a - c) for a, c in zip(actual_parts, claimed_parts)]
    if any(gap > 1000 * window for gap in gaps):
        return DISPROVEN_STATUS
    return INCONCLUSIVE_STATUS


# Upper bound on step halvings per Newton iteration in the IRR solver.
_MAX_IRR_STEP_HALVINGS = 200


# Exact points tried, in order, when looking for a counterexample to a
# symbolic claim. Integers and rationals keep the evaluation exact.
_WITNESS_POINTS = (Integer(1), Integer(2), Integer(-1), Integer(3), Rational(1, 2), Integer(0))

# Bounds for deciding a polynomial difference by full expansion. Past them the
# expansion is itself unbounded work, so the witness search decides instead.
_MAX_POLYNOMIAL_DEGREE = 64
_MAX_POLYNOMIAL_TERMS = 2_000


def _polynomial_degree_bound(expr: Any, symbols: Any) -> Optional[int]:
    """Upper bound on the total degree of ``expr`` in ``symbols``, read from
    the tree without expanding it; None when it cannot be bounded."""
    if expr in symbols:
        return 1
    if not expr.has(*symbols):
        return 0
    if expr.is_Add or expr.is_Mul:
        degrees = [_polynomial_degree_bound(arg, symbols) for arg in expr.args]
        if any(degree is None for degree in degrees):
            return None
        return max(degrees) if expr.is_Add else sum(degrees)
    if expr.is_Pow and expr.exp.is_Integer and expr.exp >= 0:
        base = _polynomial_degree_bound(expr.base, symbols)
        return None if base is None else base * int(expr.exp)
    return None


def _polynomial_status(difference: Any, symbols: Any) -> Optional[str]:
    """Decide a polynomial difference through its coefficients, or None.

    The difference is identically zero iff every coefficient is zero. A
    non-zero polynomial has finitely many roots, so it is non-zero somewhere
    in every infinite domain, including the positive integers ``n`` ranges
    over. Coefficients may be irrational constants (``sqrt(2) + sqrt(3) -
    sqrt(5 + 2*sqrt(6))`` is 0), and expansion cannot see that, so a
    coefficient counts as non-zero only when SymPy decides ``is_zero is
    False``. Anything undecided returns None for the witness search.
    """
    if not difference.is_polynomial(*symbols):
        return None
    degree = _polynomial_degree_bound(difference, symbols)
    if degree is None or degree > _MAX_POLYNOMIAL_DEGREE:
        return None
    if math.comb(degree + len(symbols), len(symbols)) > _MAX_POLYNOMIAL_TERMS:
        return None
    coefficients = Poly(expand(difference), *symbols).coeffs()
    if all(coefficient == 0 for coefficient in coefficients):
        return "VERIFIED"
    if any(coefficient.is_zero is False for coefficient in coefficients):
        return DISPROVEN_STATUS
    return None


DOMAIN_RESTRICTED_IDENTITY = "math.domain_restricted_identity"


def _denominator_sources(expression: str) -> Optional[List[str]]:
    """Source text of every denominator written in ``expression``.

    Read from the Python AST, before SymPy evaluates anything: ``x/x``
    parses straight to ``1`` and the excluded point x = 0 is lost. Covers
    the right side of each ``/`` and the base of each power (``**`` or ``^``,
    which the parser reads as a power) whose exponent is not provably
    non-negative. None when the text is not Python-parseable (implicit
    multiplication) or an exponent cannot be read.
    """
    # The parser reads "^" as a power (convert_xor); Python's AST would read
    # it as XOR with looser precedence, so "x^2 - 9" would become x^(2 - 9).
    normalized = expression.replace("^", "**")
    try:
        tree = ast.parse(normalized, mode="eval")
    except SyntaxError:
        return None
    sources = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        if isinstance(node.op, ast.Div):
            sources.append(ast.get_source_segment(normalized, node.right))
        elif isinstance(node.op, ast.Pow):
            nonnegative = _exponent_is_nonnegative(ast.get_source_segment(normalized, node.right))
            if nonnegative is None:
                return None
            if not nonnegative:
                sources.append(ast.get_source_segment(normalized, node.left))
    return sources


def _exponent_is_nonnegative(source: str) -> Optional[bool]:
    try:
        exponent = safe_parse_expr(source)
    except ValueError:
        return None
    return exponent.is_nonnegative is True


# Parser functions whose own domain has poles or a singular point (tan at
# pi/2, log at 0, factorial at negative integers). Their names are read from
# the text: "tan(x) - tan(x)" cancels to 0 before any parsed tree is seen.
_DOMAIN_RESTRICTED_FUNCTIONS = frozenset({
    "tan", "cot", "sec", "csc", "asin", "acos", "atan", "atan2", "tanh",
    "log", "ln", "factorial", "binomial",
})
# Every parser name that is not a symbol: functions, constructors, constants.
_NON_SYMBOL_NAMES = _DOMAIN_RESTRICTED_FUNCTIONS | frozenset({
    "sin", "cos", "exp", "sinh", "cosh", "sqrt", "cbrt", "abs", "Abs",
    "Integer", "Float", "Rational", "pi", "E", "I", "oo",
})


def _singular_factors(expression: str) -> Optional[frozenset]:
    """The distinct factors whose zeros make ``expression`` undefined, or
    None when they cannot be determined cheaply and exactly."""
    # Scan the text the parser reads: safe_parse_expr applies NFKC first, so
    # a fullwidth "x／x" parses as x/x (issue #330).
    expression = unicodedata.normalize("NFKC", expression).strip()
    names = set(re.findall(r"[A-Za-z_]\w*", expression))
    # A closed constant (factorial(5), log(1), tan(pi/4)) has no domain to
    # restrict. Symbols are read from the text too, since the parsed tree of
    # "tan(x) - tan(x) + 1" no longer contains x.
    if names & _DOMAIN_RESTRICTED_FUNCTIONS and names - _NON_SYMBOL_NAMES:
        return None
    sources = _denominator_sources(expression)
    if sources is None:
        # Unreadable text can only be trusted to have no singular points
        # when it has no division and no power at all.
        if any(token in expression for token in ("/", "**", "^")):
            return None
        return frozenset()
    factors = set()
    for source in sources:
        denominator_factors = _denominator_factors(safe_parse_expr(source))
        if denominator_factors is None:
            return None
        factors |= denominator_factors
    return frozenset(factors)


def _denominator_factors(denominator: Any) -> Optional[set]:
    """Distinct factors of one denominator that can be zero, or None when
    they cannot be found within the factoring budget."""
    # A constant, or a denominator the symbols' assumptions rule out as zero
    # (n is a positive integer), excludes no point.
    if denominator.is_number or denominator.is_nonzero is True:
        return set()
    symbols = sorted(denominator.free_symbols, key=str)
    if not denominator.is_polynomial(*symbols):
        return {denominator}
    degree = _polynomial_degree_bound(denominator, set(symbols))
    if degree is None or degree > _MAX_POLYNOMIAL_DEGREE:
        return None
    return {
        Poly(factor, *symbols).monic().as_expr()
        for factor, _ in factor_list(denominator, *symbols)[1]
        if factor.is_nonzero is not True
    }


def identity_domains_match(lhs: str, rhs: str) -> bool:
    """True when both sides of an identity are undefined at the same points.

    ``simplify`` cancels removable singularities, so ``x/x - 1`` simplifies
    to 0 although the left side is undefined at x = 0 (#429). An identity is
    only established unconditionally when both sides have the same singular
    factors; otherwise, or when they cannot be determined, it holds only on
    a restricted domain and must not be VERIFIED.
    """
    lhs_factors, rhs_factors = _singular_factors(lhs), _singular_factors(rhs)
    return lhs_factors is not None and lhs_factors == rhs_factors


def symbolic_difference_status(difference: Any) -> str:
    """Status for a claim decided by ``simplify(actual - claimed)``.

    ``simplify`` is incomplete: a non-zero result does not prove the two sides
    differ. The claim is DISPROVEN only when SymPy decides the difference is
    non-zero: outright (``is_zero is False``), by exact polynomial expansion,
    or at an exact witness point where it evaluates to a finite non-zero
    number. Anything undecided is INCONCLUSIVE.

    - Float literals carry binary rounding residue (``0.1 + 0.2 - 0.3`` is
      5.55e-17), so a non-zero difference containing a Float proves nothing.
    - A witness outside a symbol's declared domain (``n`` is a positive
      integer) is not a counterexample, so it is skipped.
    - A witness can turn a lazy symbolic power into an exact one SymPy expands
      eagerly (``9**9**9**x`` at x=1 is a ~370M-digit integer). Each witness
      is substituted WITHOUT evaluation and held to safe_parser's expansion
      budget first; a witness over budget is skipped, never expanded.

    Skipping a witness only loses a possible disproof, so the result stays
    fail-closed.
    """
    if difference == 0:
        return "VERIFIED"
    if difference.has(Float):
        return INCONCLUSIVE_STATUS
    if getattr(difference, "is_zero", None) is False:
        return DISPROVEN_STATUS
    symbols = getattr(difference, "free_symbols", set())
    if not symbols:
        return INCONCLUSIVE_STATUS
    polynomial_status = _polynomial_status(difference, symbols)
    if polynomial_status is not None:
        return polynomial_status
    for point in _WITNESS_POINTS:
        if not all(check_assumptions(point, sym) is True for sym in symbols):
            continue
        value = _witness_value(difference, symbols, point)
        if value is not None and value.is_number and value.is_finite and value.is_zero is False:
            return DISPROVEN_STATUS
    return INCONCLUSIVE_STATUS


def _witness_value(difference: Any, symbols: Any, point: Any) -> Any:
    """The difference evaluated at ``point``, or None when it cannot be.

    Substitution can fail inside SymPy (an unevaluated ``Derivative(re(x), x)``
    cannot be taken with respect to a number) or exceed the expansion budget.
    Either way the witness proves nothing, so it is skipped: the verdict stays
    INCONCLUSIVE, never VERIFIED.
    """
    try:
        with evaluate(False):
            candidate = difference.xreplace(dict.fromkeys(symbols, point))
        check_closed_expression_cost(candidate)
        return candidate.doit()
    except (ValueError, TypeError, ArithmeticError, NotImplementedError):
        # ValueError includes SafeParserError (over the expansion budget).
        return None


@dataclass
class VerificationResult:
    """Result of a verification operation."""
    is_correct: bool
    status: str
    calculated_value: Any = None
    claimed_value: Any = None
    error: Optional[str] = None
    details: Optional[Dict] = None


class VerificationEngine:
    """
    Enterprise-Grade Mathematical Verification Engine.
    
    Uses SymPy for deterministic symbolic computation.
    Supports: Arithmetic, Algebra, Calculus, Matrix, Financial, Statistics.
    """
    
    # Parsing transformations for more natural input
    TRANSFORMATIONS = standard_transformations + (implicit_multiplication_application,)
    MAX_VERIFY_MATH_TOLERANCE_RATIO = Decimal("0.01")
    MIN_VERIFY_MATH_TOLERANCE_CAP = Decimal("0.01")
    
    def __init__(self):
        """Initialize the verification engine."""
        # Pre-define common symbols for faster parsing
        self.common_symbols = {
            'x': Symbol('x'),
            'y': Symbol('y'),
            'z': Symbol('z'),
            'n': Symbol('n', integer=True, positive=True),
            't': Symbol('t'),
            'r': Symbol('r'),
        }

    def _parse_tolerance(self, tolerance: float | Decimal) -> Decimal:
        """Parse and validate caller-provided tolerance deterministically."""
        try:
            tolerance_decimal = Decimal(str(tolerance))
        except Exception as exc:
            raise ValueError(INVALID_TOLERANCE_ERROR) from exc

        if not tolerance_decimal.is_finite() or tolerance_decimal < 0:
            raise ValueError(INVALID_TOLERANCE_ERROR)

        return tolerance_decimal

    def _max_verify_math_tolerance(self, calculated_value: Decimal) -> Decimal:
        """Bound tolerance as a deterministic function of computed magnitude."""
        magnitude = abs(calculated_value)
        dynamic_cap = magnitude * self.MAX_VERIFY_MATH_TOLERANCE_RATIO
        return max(self.MIN_VERIFY_MATH_TOLERANCE_CAP, dynamic_cap)

    # Decimal places retained when comparing a computed value with a claim.
    _VERIFY_MATH_QUANTUM = Decimal("0.000001")

    def _quantize(self, value: Decimal) -> Decimal:
        """Quantize to the comparison quantum in a context wide enough for the
        value's magnitude (the default 28-digit context raises InvalidOperation
        for large integers like 10**30)."""
        int_digits = len(str(abs(int(value)))) if value else 1
        with localcontext() as ctx:
            ctx.prec = int_digits + 12
            return value.quantize(self._VERIFY_MATH_QUANTUM, rounding=ROUND_HALF_UP)

    def _calc_decimal(self, expr: Any) -> Decimal:
        """Evaluate ``expr`` to a Decimal without losing precision on large values.

        ``SymPy.evalf()`` defaults to 15 significant digits, so a value with
        more than 15 significant digits was silently rounded *before* the
        comparison — e.g. ``10000000000000001`` collapsed to
        ``10000000000000000`` and an incorrect claim was marked VERIFIED
        (GHSA-j622-qffp-rc27). Exact integers are converted exactly; every
        other number is evaluated at a precision scaled to its own magnitude.
        """
        if getattr(expr, "is_Integer", False):
            return self._quantize(Decimal(int(expr)))

        # Significant digits needed = integer digits + fractional guard.
        try:
            int_part = int(abs(expr))
        except (TypeError, ValueError):
            int_part = 0
        int_digits = len(str(int_part)) if int_part else 1
        precision = max(30, int_digits + 15)
        raw_value = expr.evalf(precision)
        return self._quantize(Decimal(str(raw_value)))
    
    # =========================================================================
    # Core Math Verification
    # =========================================================================
    
    def verify_math(
        self, 
        expression: str, 
        expected_value: float | Decimal, 
        tolerance: float = 1e-6,
        use_decimal: bool = True
    ) -> Dict[str, Any]:
        """
        Verifies if a mathematical expression evaluates to the expected value.
        
        Args:
            expression: The math string (e.g., "2 * (5 + 10)")
            expected_value: The value the LLM claims it is (e.g., 30 or Decimal("30"))
            tolerance: Floating point tolerance
            use_decimal: If True, use Decimal for exact arithmetic (financial)
            
        Returns:
            Dict containing is_correct, calculated_value, and status.
        """
        try:
            tolerance_decimal = self._parse_tolerance(tolerance)
        except ValueError as e:
            return {
                "is_correct": False,
                "error": str(e),
                "status": "BLOCKED"
            }

        try:
            # 1. Parse the expression safely
            expr = safe_parse_expr(expression)
            
            # 2. Evaluate deterministically
            if use_decimal:
                calculated_value = self._calc_decimal(expr)
                expected_decimal = Decimal(str(expected_value))
                max_tolerance = self._max_verify_math_tolerance(calculated_value)

                if tolerance_decimal > max_tolerance:
                    return {
                        "is_correct": False,
                        "error": TOLERANCE_POLICY_ERROR,
                        "requested_tolerance": str(tolerance_decimal),
                        "max_allowed_tolerance": str(max_tolerance),
                        "calculated_value": str(calculated_value),
                        "precision_mode": "decimal",
                        "status": "BLOCKED",
                    }
                
                diff = abs(calculated_value - expected_decimal)
                is_correct = diff <= tolerance_decimal
                
                return {
                    "is_correct": is_correct,
                    "calculated_value": float(calculated_value),
                    "calculated_precise": str(calculated_value),
                    "claimed_value": expected_value,
                    "diff": float(diff),
                    "precision_mode": "decimal",
                    "status": _numeric_status(is_correct, calculated_value, expected_decimal)
                }

            calculated_value = float(expr.evalf())
            max_tolerance = self._max_verify_math_tolerance(Decimal(str(calculated_value)))

            if tolerance_decimal > max_tolerance:
                return {
                    "is_correct": False,
                    "error": TOLERANCE_POLICY_ERROR,
                    "requested_tolerance": str(tolerance_decimal),
                    "max_allowed_tolerance": str(max_tolerance),
                    "calculated_value": str(calculated_value),
                    "precision_mode": "float",
                    "status": "BLOCKED",
                }

            diff = abs(calculated_value - expected_value)
            is_correct = diff <= float(tolerance_decimal)
            
            return {
                "is_correct": is_correct,
                "calculated_value": calculated_value,
                "claimed_value": expected_value,
                "diff": diff,
                "precision_mode": "float",
                "status": _numeric_status(is_correct, calculated_value, expected_value)
            }
        except Exception as e:
            return {
                "is_correct": False,
                "error": str(e),
                "status": "SYNTAX_ERROR"
            }
    
    def verify_identity(self, lhs: str, rhs: str) -> Dict[str, Any]:
        """
        Verify if two expressions are mathematically equivalent.
        
        Examples:
            verify_identity("(x+1)**2", "x**2 + 2*x + 1")  # True
            verify_identity("sin(x)**2 + cos(x)**2", "1")  # True
        """
        try:
            left = safe_parse_expr(lhs)
            right = safe_parse_expr(rhs)
            
            # Method 1: Simplify difference
            diff = simplify(left - right)
            method = None
            if diff == 0:
                method = "algebraic_simplification"
            # Method 2: Try expanding both sides
            elif simplify(expand(left) - expand(right)) == 0:
                method = "expansion"
            if method is not None:
                if not identity_domains_match(lhs, rhs):
                    # Equal only after cancelling a removable singularity
                    # (x**2/x vs x at x = 0): not an unconditional identity.
                    return {
                        "is_equivalent": False,
                        "status": INCONCLUSIVE_STATUS,
                        "method": method,
                        "reason": "domain_mismatch",
                        "constraint_id": DOMAIN_RESTRICTED_IDENTITY,
                    }
                return {
                    "is_equivalent": True,
                    "status": "VERIFIED",
                    "method": method,
                }
            
            # Method 3: Numerical evaluation at random points
            x = Symbol('x')
            test_values = [0.5, 1, 2, -1, 0.1]
            matches = 0
            evaluated_points = 0
            for val in test_values:
                try:
                    left_val = float(left.subs(x, val).evalf())
                    right_val = float(right.subs(x, val).evalf())
                    evaluated_points += 1
                    if abs(left_val - right_val) < 1e-10:
                        matches += 1
                except Exception:
                    # Some sample points may be outside the domain; skip those values.
                    pass
            
            if evaluated_points > 0 and matches == evaluated_points:
                return {
                    "is_equivalent": False,
                    "status": "BLOCKED",
                    "method": "numerical_sampling_rejected",
                    "confidence": 0.0,
                    "reason": (
                        "Numerical sampling matched at fixed points, but no formal proof "
                        "was established"
                    ),
                }
            
            return {
                "is_equivalent": False,
                "status": "NOT_EQUIVALENT",
                "simplified_lhs": str(simplify(left)),
                "simplified_rhs": str(simplify(right))
            }
            
        except Exception as e:
            return {
                "is_equivalent": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    # =========================================================================
    # Calculus Operations
    # =========================================================================
    
    def verify_derivative(
        self, 
        expression: str, 
        variable: str, 
        expected: str,
        order: int = 1
    ) -> Dict[str, Any]:
        """
        Verify a derivative calculation.
        
        Args:
            expression: The function to differentiate (e.g., "x**3 + 2*x")
            variable: The variable to differentiate with respect to
            expected: The claimed derivative
            order: Order of derivative (1 for first, 2 for second, etc.)
        """
        try:
            expr = safe_parse_expr(expression)
            var = get_safe_symbol(variable)
            expected_expr = safe_parse_expr(expected)
            
            # Calculate derivative
            actual_derivative = diff(expr, var, order)
            
            # Compare
            difference = simplify(actual_derivative - expected_expr)
            status = symbolic_difference_status(difference)
            is_correct = status == "VERIFIED"
            
            return {
                "is_correct": is_correct,
                "status": status,
                "calculated_derivative": str(actual_derivative),
                "claimed_derivative": expected,
                "expression": expression,
                "variable": variable,
                "order": order
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    def verify_integral(
        self, 
        expression: str, 
        variable: str, 
        expected: str,
        lower_bound: Optional[str] = None,
        upper_bound: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify an integral calculation (definite or indefinite).
        
        Args:
            expression: The integrand
            variable: The variable of integration
            expected: The claimed integral
            lower_bound: Lower bound for definite integral
            upper_bound: Upper bound for definite integral
        """
        try:
            expr = safe_parse_expr(expression)
            var = get_safe_symbol(variable)
            expected_expr = safe_parse_expr(expected)
            
            if lower_bound is not None and upper_bound is not None:
                # Definite integral
                lower = safe_parse_expr(lower_bound)
                upper = safe_parse_expr(upper_bound)
                actual_integral = integrate(expr, (var, lower, upper))
                
                # For definite integrals, compare values
                status = _scalar_status(actual_integral, expected_expr)
                is_correct = status == "VERIFIED"
            else:
                # Indefinite integral
                actual_integral = integrate(expr, var)
                
                # For indefinite, derivatives should match (accounts for +C)
                deriv_actual = diff(actual_integral, var)
                deriv_expected = diff(expected_expr, var)
                status = symbolic_difference_status(simplify(deriv_actual - deriv_expected))
                is_correct = status == "VERIFIED"
            
            return {
                "is_correct": is_correct,
                "status": status,
                "calculated_integral": str(actual_integral),
                "claimed_integral": expected,
                "integral_type": "definite" if lower_bound else "indefinite"
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    def verify_limit(
        self, 
        expression: str, 
        variable: str, 
        point: str, 
        expected: str,
        direction: str = "+-"
    ) -> Dict[str, Any]:
        """
        Verify a limit calculation.
        
        Args:
            expression: The expression
            variable: The variable approaching the point
            point: The point being approached (can be "oo" for infinity)
            expected: The claimed limit
            direction: "+" for right, "-" for left, "+-" for both
        """
        try:
            expr = safe_parse_expr(expression)
            var = get_safe_symbol(variable)
            expected_expr = safe_parse_expr(expected)
            
            # Parse the point (handle infinity)
            if point.lower() in ['oo', 'inf', 'infinity']:
                pt = oo
            elif point.lower() in ['-oo', '-inf', '-infinity']:
                pt = -oo
            else:
                pt = safe_parse_expr(point)
            
            # Calculate limit
            actual_limit = limit(expr, var, pt, dir=direction)
            
            # Compare
            status = symbolic_difference_status(simplify(actual_limit - expected_expr))
            is_correct = status == "VERIFIED"
            
            return {
                "is_correct": is_correct,
                "status": status,
                "calculated_limit": str(actual_limit),
                "claimed_limit": expected,
                "expression": expression,
                "point": point
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    # =========================================================================
    # Matrix/Linear Algebra
    # =========================================================================
    
    def verify_matrix_operation(
        self, 
        operation: str,
        matrices: Dict[str, List[List[float]]],
        expected: List[List[float]] | float | List[float]
    ) -> Dict[str, Any]:
        """
        Verify matrix operations.
        
        Args:
            operation: One of "add", "multiply", "determinant", "inverse", "transpose", "eigenvalues"
            matrices: Dict of matrix names to their values, e.g., {"A": [[1,2],[3,4]], "B": [[5,6],[7,8]]}
            expected: The expected result
        """
        try:
            # Convert to SymPy matrices
            sympy_matrices = {name: Matrix(mat) for name, mat in matrices.items()}
            # Element-wise results are computed exactly: each float input is
            # read as the decimal the caller wrote (0.1 -> 1/10), so 0.1 + 0.2
            # is exactly 3/10 and no rounding residue needs a tolerance.
            exact_mats = [mat.applyfunc(_exact_claim) for mat in sympy_matrices.values()]

            if operation == "add":
                if len(sympy_matrices) != 2:
                    return {"is_correct": False, "status": "ERROR", "error": "Addition requires exactly 2 matrices"}
                result = exact_mats[0] + exact_mats[1]
                expected_mat = Matrix(expected)

            elif operation == "multiply":
                if len(sympy_matrices) != 2:
                    return {"is_correct": False, "status": "ERROR", "error": "Multiplication requires exactly 2 matrices"}
                result = exact_mats[0] * exact_mats[1]
                expected_mat = Matrix(expected)
                
            elif operation == "determinant":
                # Exact determinant compared like a 1x1 matrix entry: no
                # absolute window that accepts -2.0000001 for -2 or misses
                # rounding at large magnitudes.
                result = exact_mats[0].det()
                status = _matrix_comparison_status(Matrix([[result]]), Matrix([[expected]]))
                return {
                    "is_correct": status == "VERIFIED",
                    "status": status,
                    "calculated_determinant": float(result),
                    "claimed_determinant": expected
                }
                
            elif operation == "inverse":
                result = exact_mats[0].inv()
                expected_mat = Matrix(expected)

            elif operation == "transpose":
                result = exact_mats[0].T
                expected_mat = Matrix(expected)
                
            elif operation == "eigenvalues":
                # Exact eigenvalues of the exact matrix, expanded by algebraic
                # multiplicity so repeated roots are counted, sorted by value.
                eigen_multiset = exact_mats[0].eigenvals()
                eigenvals = sorted(
                    (v for v, m in eigen_multiset.items() for _ in range(m)),
                    key=lambda v: complex(v.evalf(30)).real,
                )
                eigenvals_float = [complex(v.evalf()).real for v in eigenvals]
                expected_sorted = sorted(expected)
                # Cardinality check: claim must match exact eigenvalue count (Issue #130)
                if len(eigenvals_float) != len(expected_sorted):
                    return {
                        "is_correct": False,
                        "status": DISPROVEN_STATUS,
                        "error": (
                            f"Eigenvalue cardinality mismatch: matrix has "
                            f"{len(eigenvals_float)} eigenvalue(s) (counting "
                            f"multiplicity) but {len(expected_sorted)} claimed. "
                            f"All eigenvalues including repeated roots must be "
                            f"specified for verification."
                        ),
                        "calculated_eigenvalues": eigenvals_float,
                        "claimed_eigenvalues": list(expected),
                        "calculated_count": len(eigenvals_float),
                        "claimed_count": len(expected_sorted),
                    }
                # Each exact eigenvalue against its claim: the difference is
                # evaluated at a precision scaled to the magnitude, so 15-digit
                # rounding of a large irrational root never flips the verdict.
                statuses = [
                    _scalar_status(value, Matrix([[claim]])[0])
                    for value, claim in zip(eigenvals, expected_sorted)
                ]
                if DISPROVEN_STATUS in statuses:
                    status = DISPROVEN_STATUS
                elif all(s == "VERIFIED" for s in statuses):
                    status = "VERIFIED"
                else:
                    status = INCONCLUSIVE_STATUS
                return {
                    "is_correct": status == "VERIFIED",
                    "status": status,
                    "calculated_eigenvalues": eigenvals_float,
                    "claimed_eigenvalues": list(expected)
                }
            else:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown operation: {operation}"}
            
            status = _matrix_comparison_status(result, expected_mat)
            is_correct = status == "VERIFIED"
            
            return {
                "is_correct": is_correct,
                "status": status,
                "calculated_result": result.tolist(),
                "claimed_result": expected,
                "operation": operation
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    # =========================================================================
    # Financial Formulas
    # =========================================================================
    
    def verify_compound_interest(
        self,
        principal: float,
        rate: float,
        time: float,
        n: int,  # Compounding frequency per year
        expected: float,
        tolerance: float = 0.01
    ) -> Dict[str, Any]:
        """
        Verify compound interest calculation.
        
        Formula: A = P(1 + r/n)^(nt)
        """
        try:
            # Use Decimal for precision
            P = Decimal(str(principal))
            r = Decimal(str(rate))
            t = Decimal(str(time))
            n_dec = Decimal(str(n))
            
            # Calculate: A = P(1 + r/n)^(nt)
            A = P * (1 + r/n_dec) ** (n_dec * t)
            A = float(A.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
            
            is_correct = abs(A - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": _numeric_status(is_correct, A, expected),
                "calculated_amount": A,
                "claimed_amount": expected,
                "principal": principal,
                "annual_rate": rate,
                "time_years": time,
                "compounding_frequency": n,
                "formula": "A = P(1 + r/n)^(nt)"
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def verify_npv(
        self,
        rate: float,
        cash_flows: List[float],
        expected: float,
        tolerance: float = 0.01
    ) -> Dict[str, Any]:
        """
        Verify Net Present Value calculation.
        
        Formula: NPV = Σ(CF_t / (1+r)^t) for t = 0 to n
        """
        try:
            r = Decimal(str(rate))
            npv = Decimal("0")
            
            for t, cf in enumerate(cash_flows):
                cf_dec = Decimal(str(cf))
                npv += cf_dec / ((1 + r) ** t)
            
            npv = float(npv.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
            is_correct = abs(npv - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": _numeric_status(is_correct, npv, expected),
                "calculated_npv": npv,
                "claimed_npv": expected,
                "discount_rate": rate,
                "cash_flows": cash_flows,
                "formula": "NPV = Σ(CF_t / (1+r)^t)"
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    @staticmethod
    def _count_sign_changes(cash_flows: List[float]) -> int:
        """Count sign changes in cash flows, skipping zeros (Descartes' rule)."""
        sign_changes = 0
        last_sign = 0
        for cf in cash_flows:
            if cf > 0:
                if last_sign < 0:
                    sign_changes += 1
                last_sign = 1
            elif cf < 0:
                if last_sign > 0:
                    sign_changes += 1
                last_sign = -1
        return sign_changes

    @staticmethod
    def _find_irr_newton(cash_flows: List[float]) -> Dict[str, Any]:
        """Run Newton-Raphson to find IRR. Returns result dict with convergence info.

        Convergence is decided on the rate step, not on an absolute NPV
        residual: with small cash flows the NPV is tiny everywhere, so an
        absolute residual bound would stop at the initial guess and the
        mismatch would be reported as a counter-proof.
        """
        r = Decimal("0.1")
        step_threshold = Decimal("1e-12")
        max_iterations = 100

        for iteration in range(max_iterations):
            npv, npv_derivative = VerificationEngine._npv_and_derivative(cash_flows, r)
            if npv == 0:
                return {"converged": True, "irr": float(r), "iterations": iteration + 1}
            if npv_derivative == 0:
                return {
                    "converged": False,
                    "reason": "derivative_stall",
                    "iterations": iteration + 1,
                    "r": float(r),
                }

            step, failure = VerificationEngine._damped_irr_step(r, npv / npv_derivative)
            if failure is not None:
                return {
                    "converged": False,
                    "reason": failure,
                    "iterations": iteration + 1,
                    "residual": float(abs(npv)),
                }
            r = r - step
            if abs(step) < step_threshold:
                return {"converged": True, "irr": float(r), "iterations": iteration + 1}

        return {
            "converged": False,
            "reason": "max_iterations",
            "iterations": max_iterations,
            "residual": float(abs(npv)),
        }

    @staticmethod
    def _npv_and_derivative(cash_flows: List[float], r: Decimal) -> tuple:
        """NPV of ``cash_flows`` at rate ``r`` and its derivative in ``r``."""
        npv = Decimal("0")
        npv_derivative = Decimal("0")
        for t, cf in enumerate(cash_flows):
            cf_dec = Decimal(str(cf))
            npv += cf_dec / ((1 + r) ** t)
            if t > 0:
                npv_derivative -= t * cf_dec / ((1 + r) ** (t + 1))
        return npv, npv_derivative

    @staticmethod
    def _damped_irr_step(r: Decimal, step: Decimal) -> tuple:
        """The Newton step to take from ``r``, or a failure reason.

        Stay where the rate means something (1 + r > 0): a full step can jump
        past -100% to a spurious root (-1.358 for [-100, 20, 20], whose IRR is
        -0.4417), so it is halved until the next iterate stays in range. The
        halving is bounded, and a non-finite step is refused outright.
        """
        if not step.is_finite():
            return step, "non_finite_step"
        halvings = 0
        while r - step <= -1 and halvings < _MAX_IRR_STEP_HALVINGS:
            step /= 2
            halvings += 1
        if r - step <= -1:
            return step, "out_of_domain"
        return step, None

    def verify_irr(
        self,
        cash_flows: List[float],
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify Internal Rate of Return calculation.
        
        IRR is the rate where NPV = 0.
        Fail-closed: non-convergence, derivative stall, and ambiguous
        (multi-root) cash flow patterns are blocked, not verified.
        """
        try:
            if not cash_flows or len(cash_flows) < 2:
                return {"is_correct": False, "status": "ERROR", "error": "Need at least 2 cash flows"}

            # A non-finite cash flow has no IRR to compute; it would only feed
            # infinities into the solver.
            if not all(_is_finite_value(cf) for cf in cash_flows):
                return {
                    "is_correct": False,
                    "status": "BLOCKED",
                    "error": "IRR is undefined: a cash flow is not a finite number.",
                    "cash_flows": cash_flows,
                }

            # All-zero cash flows: IRR is mathematically undefined
            if all(cf == 0 for cf in cash_flows):
                return {
                    "is_correct": False,
                    "status": "BLOCKED",
                    "error": "IRR is undefined: all cash flows are zero. Any rate satisfies NPV=0.",
                    "cash_flows": cash_flows,
                }

            # Descartes' rule of signs: detect multi-root or no-root ambiguity
            sign_changes = self._count_sign_changes(cash_flows)

            if sign_changes == 0:
                return {
                    "is_correct": False,
                    "status": "BLOCKED",
                    "error": "No real IRR exists: all cash flows have the same sign (zero sign changes).",
                    "sign_changes": 0,
                    "cash_flows": cash_flows,
                }

            if sign_changes > 1:
                return {
                    "is_correct": False,
                    "status": "BLOCKED",
                    "error": (
                        f"Ambiguous IRR: {sign_changes} sign changes in cash flows "
                        f"implies up to {sign_changes} possible roots. Cannot "
                        f"deterministically verify a unique IRR."
                    ),
                    "sign_changes": sign_changes,
                    "cash_flows": cash_flows,
                }

            # Newton-Raphson to find IRR
            newton_result = self._find_irr_newton(cash_flows)

            if not newton_result["converged"]:
                if newton_result["reason"] == "derivative_stall":
                    error_msg = (
                        f"IRR verification failed: derivative is zero at "
                        f"iteration {newton_result['iterations']} (r={newton_result['r']:.6f}). "
                        f"Newton-Raphson cannot converge from this path."
                    )
                else:
                    error_msg = (
                        f"IRR verification failed: Newton-Raphson did not converge "
                        f"within {newton_result['iterations']} iterations. Final NPV residual: "
                        f"{newton_result['residual']:.8f}."
                    )
                return {
                    "is_correct": False,
                    "status": "BLOCKED",
                    "error": error_msg,
                    "iterations_used": newton_result["iterations"],
                    "cash_flows": cash_flows,
                }

            irr = newton_result["irr"]
            is_correct = abs(irr - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": _numeric_status(is_correct, irr, expected),
                "calculated_irr": irr,
                "claimed_irr": expected,
                "converged": True,
                "iterations_used": newton_result["iterations"],
                "cash_flows": cash_flows
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def verify_percentage(
        self,
        value: float,
        percentage: float,
        expected: float,
        operation: str = "of",
        tolerance: float = 0.01
    ) -> Dict[str, Any]:
        """
        Verify percentage calculations.
        
        Operations:
        - "of": X% of Y (e.g., 15% of 200 = 30)
        - "increase": Y increased by X%
        - "decrease": Y decreased by X%
        - "change": Percentage change from value to expected
        """
        try:
            if operation == "of":
                # X% of Y
                calculated = value * (percentage / 100)
            elif operation == "increase":
                calculated = value * (1 + percentage / 100)
            elif operation == "decrease":
                calculated = value * (1 - percentage / 100)
            elif operation == "change":
                # Calculate what percentage change from value to expected
                if value == 0:
                    return {"is_correct": False, "status": "ERROR", "error": "Cannot calculate percentage change from 0"}
                calculated = ((expected - value) / value) * 100
                # In this case, we're checking if the claimed percentage is correct
                is_correct = abs(calculated - percentage) <= tolerance
                return {
                    "is_correct": is_correct,
                    "status": _numeric_status(is_correct, calculated, percentage),
                    "calculated_percentage_change": calculated,
                    "claimed_percentage_change": percentage,
                    "from_value": value,
                    "to_value": expected
                }
            else:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown operation: {operation}"}
            
            is_correct = abs(calculated - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": _numeric_status(is_correct, calculated, expected),
                "calculated_result": round(calculated, 2),
                "claimed_result": expected,
                "value": value,
                "percentage": percentage,
                "operation": operation
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def verify_statistics(
        self,
        data: List[float],
        statistic: str,
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify statistical calculations.
        
        Statistics supported:
        - mean, median, mode
        - variance, std (standard deviation)
        - min, max, range
        - sum, count
        - percentile_25, percentile_50, percentile_75
        """
        try:
            n = len(data)
            if n == 0:
                return {"is_correct": False, "status": "ERROR", "error": "Empty dataset"}
            
            sorted_data = sorted(data)
            
            if statistic == "mean":
                calculated = sum(data) / n
            elif statistic == "median":
                if n % 2 == 0:
                    calculated = (sorted_data[n//2 - 1] + sorted_data[n//2]) / 2
                else:
                    calculated = sorted_data[n//2]
            elif statistic == "mode":
                from collections import Counter
                counter = Counter(data)
                max_freq = max(counter.values())
                modes = [val for val, freq in counter.items() if freq == max_freq]
                if len(modes) > 1:
                    return {
                        "is_correct": False,
                        "status": "BLOCKED",
                        "error": (
                            f"Ambiguous mode: {len(modes)} values share the maximum "
                            f"frequency ({max_freq}). Cannot deterministically verify "
                            f"a single mode. Modes: {sorted(modes, key=str)}"
                        ),
                        "statistic": statistic,
                        "data_points": n,
                        "ambiguous_modes": sorted(modes, key=str),
                    }
                calculated = modes[0]
            elif statistic == "variance":
                mean = sum(data) / n
                calculated = sum((x - mean) ** 2 for x in data) / n
            elif statistic == "std":
                mean = sum(data) / n
                variance = sum((x - mean) ** 2 for x in data) / n
                calculated = math.sqrt(variance)
            elif statistic == "min":
                calculated = min(data)
            elif statistic == "max":
                calculated = max(data)
            elif statistic == "range":
                calculated = max(data) - min(data)
            elif statistic == "sum":
                calculated = sum(data)
            elif statistic == "count":
                calculated = n
            elif statistic.startswith("percentile_"):
                p = int(statistic.split("_")[1])
                k = (n - 1) * (p / 100)
                f = math.floor(k)
                c = math.ceil(k)
                if f == c:
                    calculated = sorted_data[int(k)]
                else:
                    calculated = sorted_data[f] * (c - k) + sorted_data[c] * (k - f)
            else:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown statistic: {statistic}"}
            
            is_correct = abs(calculated - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": _numeric_status(is_correct, calculated, expected),
                "calculated_value": round(calculated, 6),
                "claimed_value": expected,
                "statistic": statistic,
                "data_points": n
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def verify_correlation(
        self,
        x_data: List[float],
        y_data: List[float],
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify Pearson correlation coefficient.
        """
        try:
            n = len(x_data)
            if n != len(y_data):
                return {"is_correct": False, "status": "ERROR", "error": "Data arrays must have same length"}
            
            mean_x = sum(x_data) / n
            mean_y = sum(y_data) / n
            
            numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(x_data, y_data))
            
            sum_sq_x = sum((x - mean_x) ** 2 for x in x_data)
            sum_sq_y = sum((y - mean_y) ** 2 for y in y_data)
            
            denominator = math.sqrt(sum_sq_x * sum_sq_y)
            
            if denominator == 0:
                return {"is_correct": False, "status": "ERROR", "error": "Cannot calculate correlation (no variance)"}
            
            r = numerator / denominator
            is_correct = abs(r - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": _numeric_status(is_correct, r, expected),
                "calculated_correlation": round(r, 6),
                "claimed_correlation": expected,
                "data_points": n
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    # =========================================================================
    # Unit Conversion
    # =========================================================================
    
    # Conversion factors to base units, as exact decimal strings. Every factor
    # is the legal definition (1 lb = 0.45359237 kg, 1 US gal = 3.785411784 L),
    # so a correct claim is never disproven by a truncated constant.
    UNIT_CONVERSIONS = {
        # Length (base: meters)
        "m": "1", "meter": "1", "meters": "1",
        "km": "1000", "kilometer": "1000", "kilometers": "1000",
        "cm": "0.01", "centimeter": "0.01", "centimeters": "0.01",
        "mm": "0.001", "millimeter": "0.001", "millimeters": "0.001",
        "mi": "1609.344", "mile": "1609.344", "miles": "1609.344",
        "ft": "0.3048", "foot": "0.3048", "feet": "0.3048",
        "in": "0.0254", "inch": "0.0254", "inches": "0.0254",
        "yd": "0.9144", "yard": "0.9144", "yards": "0.9144",

        # Weight (base: kilograms)
        "kg": "1", "kilogram": "1", "kilograms": "1",
        "g": "0.001", "gram": "0.001", "grams": "0.001",
        "mg": "0.000001", "milligram": "0.000001",
        "lb": "0.45359237", "pound": "0.45359237", "pounds": "0.45359237",
        "oz": "0.028349523125", "ounce": "0.028349523125", "ounces": "0.028349523125",

        # Temperature handled separately

        # Volume (base: liters; US customary units)
        "l": "1", "liter": "1", "liters": "1", "L": "1",
        "ml": "0.001", "milliliter": "0.001", "milliliters": "0.001",
        "gal": "3.785411784", "gallon": "3.785411784", "gallons": "3.785411784",
        "qt": "0.946352946", "quart": "0.946352946",
        "pt": "0.473176473", "pint": "0.473176473",
        "cup": "0.2365882365", "cups": "0.2365882365",

        # Time (base: seconds)
        "s": "1", "sec": "1", "second": "1", "seconds": "1",
        "min": "60", "minute": "60", "minutes": "60",
        "h": "3600", "hr": "3600", "hour": "3600", "hours": "3600",
        "d": "86400", "day": "86400", "days": "86400",
        "wk": "604800", "week": "604800", "weeks": "604800",
    }

    # Physical dimension of each unit: converting across dimensions (metres to
    # kilograms) is meaningless and must never produce a verdict.
    UNIT_DIMENSIONS = {
        **dict.fromkeys(("m", "meter", "meters", "km", "kilometer", "kilometers",
                         "cm", "centimeter", "centimeters", "mm", "millimeter",
                         "millimeters", "mi", "mile", "miles", "ft", "foot", "feet",
                         "in", "inch", "inches", "yd", "yard", "yards"), "length"),
        **dict.fromkeys(("kg", "kilogram", "kilograms", "g", "gram", "grams", "mg",
                         "milligram", "lb", "pound", "pounds", "oz", "ounce",
                         "ounces"), "mass"),
        **dict.fromkeys(("l", "liter", "liters", "L", "ml", "milliliter", "milliliters",
                         "gal", "gallon", "gallons", "qt", "quart", "pt", "pint",
                         "cup", "cups"), "volume"),
        **dict.fromkeys(("s", "sec", "second", "seconds", "min", "minute", "minutes",
                         "h", "hr", "hour", "hours", "d", "day", "days", "wk", "week",
                         "weeks"), "time"),
    }

    def verify_unit_conversion(
        self,
        value: float,
        from_unit: str,
        to_unit: str,
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify unit conversion calculations.

        The conversion runs in Decimal with the exact unit definitions; inputs
        are read through ``Decimal(str(...))``. Units of different dimensions
        are BLOCKED, and a non-finite input is INCONCLUSIVE.
        """
        try:
            from_unit = from_unit.lower()
            to_unit = to_unit.lower()
            # Validated before any branch, so no path compares against an
            # invalid (negative or NaN) tolerance.
            tolerance_decimal = self._parse_tolerance(tolerance)

            # Handle temperature separately
            if from_unit in ['c', 'celsius'] or to_unit in ['c', 'celsius']:
                return self._verify_temperature_conversion(value, from_unit, to_unit, expected, tolerance_decimal)

            if from_unit not in self.UNIT_CONVERSIONS:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown unit: {from_unit}"}
            if to_unit not in self.UNIT_CONVERSIONS:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown unit: {to_unit}"}
            if self.UNIT_DIMENSIONS[from_unit] != self.UNIT_DIMENSIONS[to_unit]:
                return {
                    "is_correct": False,
                    "status": "BLOCKED",
                    "error": (
                        f"Incompatible units: {from_unit} is "
                        f"{self.UNIT_DIMENSIONS[from_unit]}, {to_unit} is "
                        f"{self.UNIT_DIMENSIONS[to_unit]}"
                    ),
                }

            value_decimal = Decimal(str(value))
            expected_decimal = Decimal(str(expected))
            if not (value_decimal.is_finite() and expected_decimal.is_finite()):
                return {"is_correct": False, "status": INCONCLUSIVE_STATUS,
                        "error": "Non-finite value or claim"}

            # Convert: value * (from_factor / to_factor)
            with localcontext() as ctx:
                ctx.prec = 50
                calculated = (
                    value_decimal
                    * Decimal(self.UNIT_CONVERSIONS[from_unit])
                    / Decimal(self.UNIT_CONVERSIONS[to_unit])
                )
                if expected_decimal != 0:
                    is_correct = abs(calculated - expected_decimal) <= tolerance_decimal * abs(expected_decimal)
                else:
                    is_correct = abs(calculated) <= tolerance_decimal

            return {
                "is_correct": is_correct,
                "status": _numeric_status(is_correct, calculated, expected_decimal),
                "calculated_value": round(float(calculated), 6),
                "claimed_value": expected,
                "from_unit": from_unit,
                "to_unit": to_unit
            }

        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}

    def _verify_temperature_conversion(
        self, value: float, from_unit: str, to_unit: str, expected: float, tolerance: Decimal
    ) -> Dict[str, Any]:
        """Handle temperature conversions in Decimal.

        ``tolerance`` is already validated. Inputs are read through
        ``Decimal(str(...))`` so 300 K is exactly 26.85 C, not
        26.850000000000023; a non-finite input is INCONCLUSIVE.
        """
        from_unit = from_unit.lower()
        to_unit = to_unit.lower()
        
        # Normalize unit names
        unit_map = {
            'c': 'celsius', 'celsius': 'celsius',
            'f': 'fahrenheit', 'fahrenheit': 'fahrenheit',
            'k': 'kelvin', 'kelvin': 'kelvin'
        }
        
        from_u = unit_map.get(from_unit)
        to_u = unit_map.get(to_unit)
        
        if not from_u or not to_u:
            return {"is_correct": False, "status": "ERROR", "error": INVALID_TEMPERATURE_UNIT_ERROR}

        value_decimal = Decimal(str(value))
        expected_decimal = Decimal(str(expected))
        if not (value_decimal.is_finite() and expected_decimal.is_finite()):
            return {"is_correct": False, "status": INCONCLUSIVE_STATUS,
                    "error": "Non-finite value or claim"}

        kelvin_offset = Decimal("273.15")
        with localcontext() as ctx:
            ctx.prec = 50
            # Convert to Celsius first
            celsius = {
                'celsius': value_decimal,
                'fahrenheit': (value_decimal - 32) * 5 / 9,
                'kelvin': value_decimal - kelvin_offset,
            }[from_u]

            # Convert from Celsius to target
            calculated = {
                'celsius': celsius,
                'fahrenheit': celsius * 9 / 5 + 32,
                'kelvin': celsius + kelvin_offset,
            }[to_u]

            is_correct = abs(calculated - expected_decimal) <= tolerance

        return {
            "is_correct": is_correct,
            "status": _numeric_status(is_correct, calculated, expected_decimal),
            "calculated_value": round(float(calculated), 2),
            "claimed_value": expected,
            "from_unit": from_unit,
            "to_unit": to_unit
        }
    
    # =========================================================================
    # Legacy method for compatibility
    # =========================================================================
    
    def verify_logic_rule(self, rule: str, context: Dict[str, Any]) -> bool:
        """
        Legacy placeholder. Hard-fail closed and direct callers to LogicVerifier.
        """
        _ = (rule, context)
        raise NotImplementedError(VERIFY_LOGIC_RULE_DEPRECATED_ERROR)
