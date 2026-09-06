"""
Safe SymPy expression parser.

Wraps sympy.parsing.sympy_parser.parse_expr with input validation,
a denylist for dangerous constructs, and a restricted evaluation
namespace.  This module is the ONLY approved entry point for parsing
user-supplied math expressions in production code.

Security boundary (structural, in order):
    1. NFKC-normalize the input so the filters see exactly what the
       compiler will see (PEP 3131 normalizes identifiers at compile
       time; without this, compatibility-equivalent codepoints bypass
       every string filter — see issue #330).
    2. Charset allowlist: only arithmetic operators, decimal digits,
       names, and whitespace. A '.' is only legal as a decimal point
       between two digits, so attribute access is structurally
       impossible in input that does not parse as Python (implicit
       multiplication path, where no AST check can run).
    3. Denylist for known-dangerous constructs (defense in depth).
    4. AST node-type allowlist: input that parses as Python may only
       contain arithmetic expression nodes — Attribute, Subscript,
       string constants, lambdas, comprehensions, comparisons, etc.
       are rejected before parse_expr's eval can run (see issue #329).
    5. __builtins__ removed from the eval global dict; allowlisted
       math symbols, constants, and functions only.
    6. Enforce basic input validation (type, length, empty check).
    7. Computational-cost bounds (#353): integer-literal magnitude cap and
       static exponent / exact-expansion-call argument bounds, so an
       expression cannot demand unbounded exact-integer expansion at
       evaluation time (SymPy expands Integer powers eagerly — see the
       measured 9**9**9**9 hang).

The denylist alone can never defend an eval sink — layers 2 and 4 are
the structural guarantee; layer 3 catches residual non-expression
names early with a clearer error.

CWE-95 mitigation -- see PR #200 for the original security analysis
and issues #329/#330 for the bypasses this structure closes.
"""

import ast
import math
import operator
import re
import unicodedata
from decimal import Decimal
from fractions import Fraction
from typing import Any, Dict, Optional, Tuple

import sympy
from sympy import (
    E, I, Integer, Float, Rational, Symbol, oo, pi,
)
from sympy.parsing.sympy_parser import (
    convert_xor,
    parse_expr,
    standard_transformations,
    implicit_multiplication_application,
)

__all__ = ["safe_parse_expr", "validate_variable_name", "get_safe_symbol", "SafeParserError"]

MAX_EXPRESSION_LENGTH = 5_000
_AST_MAX_DEPTH = 30

# Computational-cost bounds (#353): the character/depth gates above bound
# PARSING cost, but not EVALUATION cost. SymPy computes exact Integer
# powers eagerly — ``9**9**9**9`` is 10 characters, shallow, charset-clean,
# and its evalf() expands a ~370-million-digit integer (measured: hangs
# past 20s). The gates below bound the magnitude of exact-integer
# expansion instead of trusting depth or length.
_MAX_INTEGER_LITERAL = 10**300
_MAX_EXPONENT_MAGNITUDE = 10_000
_MAX_EXPANSION_DIGITS = 100_000
# factorial/binomial expand their exact-integer arguments the same way Pow
# expands its exact-integer exponent. Integer/Float/Rational are cheap
# constructors — an explosive ARGUMENT is itself a static Pow/factorial
# subtree caught by its own node check (CodeAnt on PR #354: bounding them
# rejected inexpensive inputs like Rational(10001, 3)).
_EXACT_EXPANSION_CALLS = frozenset({"factorial", "binomial"})

_DENYLIST_PATTERN = re.compile(
    r"(?:"
    r"__import__|__builtins__|__subclasses__|__globals__|__locals__"
    r"|__getattr__|__setattr__|__delattr__|__class__|__bases__|__mro__"
    r"|\beval\b|\bexec\b|\bcompile\b|\bgetattr\b|\bsetattr\b|\bdelattr\b"
    r"|\bimport\b|\bimportlib\b"
    r"|\bos\b|\bsys\b|\bsubprocess\b|\bshutil\b|\bsocket\b"
    r"|\bpopen\b|\bsystem\b|\bspawn\b"
    r"|\bopen\b|\bfile\b|\bpath\b|\bglob\b"
    r"|\bchr\b|\bord\b|\bhex\b|\btype\b|\bvars\b|\bdir\b|\brepr\b"
    r"|\binput\b|\bprint\b|\bbreakpoint\b|\bexit\b|\bquit\b"
    r"|\bcodecs\b|\bcode\b|\bctypes\b"
    r")",
    re.IGNORECASE,
)

# Charset allowlist applied after NFKC normalization. Quotes, brackets,
# braces, semicolons, backslashes, comparison/boolean operators and '='
# cannot appear at all: without them, string concatenation, subscripts,
# and statement injection are structurally impossible.
_CHARSET_PATTERN = re.compile(r"^[A-Za-z0-9_+\-*/().,^%\s]+$", re.ASCII)

# A '.' is only legal as a decimal point with a digit on BOTH sides.
# This rejects every attribute access (``x.__class__``, ``2 .real``)
# and bare decimal forms like ``.5`` (write ``0.5`` instead).
# re.ASCII pins \d to [0-9] so NFKC-surviving unicode digits cannot
# satisfy the lookarounds.
_BAD_DECIMAL_DOT = re.compile(r"(?<!\d)\.|\.(?!\d)", re.ASCII)

# AST node-type allowlist for input that parses as Python. Implicit
# multiplication expressions (``2x``, ``sin x``) fail ast.parse and are
# covered by the charset gate instead.
_ALLOWED_AST_NODES = frozenset(
    {
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.Call,
        ast.Name,
        ast.Load,
        ast.Constant,
        ast.keyword,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.USub,
        ast.UAdd,
        # ``^`` is converted to ``**`` by sympy's convert_xor, which the
        # default pipeline below includes — caret exponentiation parses
        # instead of failing with a TypeError at eval time.
        ast.BitXor,
    }
)

_SAFE_GLOBAL_DICT_TEMPLATE: Dict[str, Any] = {"__builtins__": {}}


_BINOP_EVALUATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}


def _check_node_shape(node: ast.AST) -> None:
    """Node-allowlist + numeric-constant shape check (#329/#330)."""
    if type(node) not in _ALLOWED_AST_NODES:
        raise SafeParserError(
            f"Expression contains disallowed syntax: {type(node).__name__}. "
            "Only arithmetic expressions are supported."
        )
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SafeParserError(
                f"Expression contains disallowed constant of type "
                f"{type(value).__name__}; only numeric literals are supported."
            )


def _check_constant_magnitude(node: ast.AST) -> None:
    """A literal large enough to BE its own expansion cost is rejected."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and abs(node.value) > _MAX_INTEGER_LITERAL:
        raise SafeParserError(
            "Expression contains an integer literal exceeding "
            f"{_MAX_INTEGER_LITERAL}; exact expansion is unbounded."
        )


def _check_pow_cost(node: ast.AST) -> None:
    """Bound statically-known ** powers: sympy expands Integer**Integer
    eagerly, so the exponent AND the base's own magnitude decide the cost."""
    if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow)):
        return
    base = _static_value(node.left)
    exponent = _static_value(node.right)
    if exponent is not None and abs(exponent) > _MAX_EXPONENT_MAGNITUDE:
        raise SafeParserError(
            f"Exponent exceeds the maximum magnitude of "
            f"{_MAX_EXPONENT_MAGNITUDE}; exact-integer expansion "
            "would be unbounded."
        )
    if base is None:
        return
    if base == _ASTRONOMICAL:
        # the base subtree itself demands unbounded expansion
        # (e.g. (9**9**9)**2 — the bomb lives in the base)
        raise SafeParserError(
            "Power base exceeds the expansion budget; exact-integer "
            "expansion would be unbounded."
        )
    if exponent is None:
        return  # symbolic exponent keeps the power lazy
    # CodeRabbit on PR #354: sympy expands (Integer**Integer)**Integer
    # STEPWISE, so nested powers multiply the base's magnitude into the
    # cost — ((9**9)**9999)**9999 has every immediate exponent inside the
    # bound yet still expands to a ~400M-digit integer. Estimate the
    # result's digit count and hold it to the same budget the evaluator
    # itself obeys.
    base_digits = _magnitude_digits(base)
    # exact arithmetic: an exponent may be a float — int x float would
    # decide the admission bound in binary floating-point (CodeRabbit)
    if base_digits * _exact_magnitude(abs(exponent)) > _MAX_EXPANSION_DIGITS:
        raise SafeParserError(
            f"Power expansion would exceed the {_MAX_EXPANSION_DIGITS} "
            "digit budget; exact-integer expansion is too costly."
        )


def _check_caret_chain_cost(node: ast.AST) -> None:
    """Bound caret chains: convert_xor maps ^ to ** in sympy-land, where **
    is RIGHT-associative — but Python's ^ is LEFT-associative, so the
    Python AST cannot know which operand ends up as an exponent: 9^9^9
    parses as ((9^9)^9) here but evaluates as 9**(9**9) sympy-side.
    Flatten the chain and bound every right-assoc suffix fold — each one
    is an exponent after reassociation. A symbolic operand anywhere in the
    chain keeps every enclosing power lazy on the sympy side, so
    fully-static chains only."""
    if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor)):
        return
    values = [_static_value(operand) for operand in _flatten_caret_chain(node)]
    if None in values:
        return
    exponent = _right_assoc_fold(values[1:])
    if exponent is not None and abs(exponent) > _MAX_EXPONENT_MAGNITUDE:
        raise SafeParserError(
            f"Caret-chain exponent exceeds the maximum magnitude of "
            f"{_MAX_EXPONENT_MAGNITUDE}; ^ is parsed as right-associative "
            "exponentiation by sympy."
        )
    if exponent is None:
        return
    # Sentry CRITICAL on PR #354: the first operand's magnitude multiplies
    # into the expansion cost exactly like a ** base — (9**9999)^9999 has a
    # cheap inner power (9543 digits) and an in-bound exponent, yet sympy
    # eagerly expands the ~95M-digit result. Same budget as **.
    base = values[0]
    if base == _ASTRONOMICAL:
        raise SafeParserError(
            "Caret-chain base exceeds the expansion budget; exact-integer "
            "expansion would be unbounded."
        )
    if _magnitude_digits(base) * _exact_magnitude(abs(exponent)) > _MAX_EXPANSION_DIGITS:
        raise SafeParserError(
            f"Caret expansion would exceed the {_MAX_EXPANSION_DIGITS} "
            "digit budget; exact-integer expansion is too costly."
        )


def _check_exact_expansion_call_cost(node: ast.AST) -> None:
    """factorial/binomial expand their exact-integer arguments the same way
    Pow expands its exact-integer exponent — bound those arguments even at
    top level (the result there is not in an exponent position, but sympy
    still materializes it exactly)."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in _EXACT_EXPANSION_CALLS):
        return
    for arg in node.args:
        value = _static_value(arg)
        if value is not None and abs(value) > _MAX_EXPONENT_MAGNITUDE:
            raise SafeParserError(
                f"{node.func.id}() argument exceeds the maximum magnitude "
                f"of {_MAX_EXPONENT_MAGNITUDE}; exact expansion would be "
                "unbounded."
            )


def _check_ast_safety(expression: str) -> None:
    """Reject Python-parseable expressions that use non-arithmetic syntax,
    exceed max AST depth, or demand unbounded exact-integer expansion
    (issues #329/#330/#353).

    Expressions using implicit multiplication (e.g. 2x, sin x) fail
    ast.parse and skip this check — they are caught by the charset gate
    and the post-parse sympy depth check.
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return
    depth = _ast_node_depth(tree)
    if depth > _AST_MAX_DEPTH:
        raise SafeParserError(
            f"Expression AST depth {depth} exceeds limit of {_AST_MAX_DEPTH}"
        )
    for node in ast.walk(tree):
        _check_node_shape(node)
        _check_constant_magnitude(node)
        _check_pow_cost(node)
        _check_caret_chain_cost(node)
        _check_exact_expansion_call_cost(node)


_ASTRONOMICAL = float("inf")


def _exact_magnitude(value):
    """Admission-comparison operand: floats convert via Decimal(str(...))
    so the bound never runs in binary float (CodeRabbit on PR #354);
    int/Decimal/Fraction pass through exactly (Fraction compares exactly
    against ints — Decimal(str(Fraction)) would be ConversionSyntax)."""
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def _magnitude_digits(value) -> int:
    """Upper-bound digit count of |value| WITHOUT int->str conversion —
    Python 3.11+ raises ValueError past 4300 digits, which would turn this
    cost guard into the crash it exists to prevent. The bit-length estimate
    may overshoot by a digit; that only makes the budget stricter."""
    if isinstance(value, Decimal):
        if not value.is_finite():
            return _MAX_EXPANSION_DIGITS * 2
        return max(value.adjusted() + 1, 1)
    if isinstance(value, Fraction):
        bits = abs(value.numerator).bit_length()
    elif isinstance(value, float):
        if not math.isfinite(value) or value == 0:
            return _MAX_EXPANSION_DIGITS * 2
        return max(int(math.log10(abs(value))) + 1, 1)
    else:
        bits = value.bit_length()
    return max((bits * 30103) // 100000 + 1, 1)


def _flatten_caret_chain(node: ast.BinOp) -> list:
    """Collect the operands of a caret chain into source order.

    Python's ^ is left-assoc, so a chain nests on the left; explicit
    parentheses are indistinguishable from chain nesting in the AST, so
    flattening assumes the sympy-side worst case (right-assoc fold).
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
        return _flatten_caret_chain(node.left) + _flatten_caret_chain(node.right)
    return [node]


def _static_pow(left, right):
    """Exact-int pow behind an affordability gate — the evaluator must never
    expand what it cannot afford (decide by digit estimate, not by trying).

    Non-integer operands go through Decimal(str(...)), never binary float:
    CodeRabbit on PR #354 — float(x) rounding let 10000.0000000000001 pass
    the 10_000 admission bound as 10000.0. Decimal preserves the value the
    user wrote; anything non-finite or unrepresentable fails closed.
    """
    if isinstance(left, int) and isinstance(right, int) \
            and abs(right) <= _MAX_EXPONENT_MAGNITUDE \
            and _magnitude_digits(left) * abs(right) <= _MAX_EXPANSION_DIGITS:
        return left ** right
    try:
        result = Decimal(str(left)) ** Decimal(str(right))
    except (ArithmeticError, TypeError, ValueError):
        return _ASTRONOMICAL
    if not result.is_finite():
        return _ASTRONOMICAL
    return result


def _right_assoc_fold(values):
    """Right-assoc static evaluation: v0 ** (v1 ** (...))."""
    result = values[-1]
    for value in reversed(values[:-1]):
        result = _static_pow(value, result)
    return result


def _bounded_factorial(value):
    if isinstance(value, float) or value < 0 or value > _MAX_EXPONENT_MAGNITUDE:
        return _ASTRONOMICAL
    return math.factorial(value)


def _bounded_binomial(n, k):
    if isinstance(n, float) or isinstance(k, float) \
            or min(n, k) < 0 or max(n, k) > _MAX_EXPONENT_MAGNITUDE:
        return _ASTRONOMICAL
    return math.comb(n, k)


def _rational(numerator, denominator=None):
    if denominator is None:
        return Fraction(numerator)
    return Fraction(numerator, denominator)


# Concrete-valued allowlisted calls: sympy evaluates these eagerly, so a
# result in an exponent position is NOT symbolic and must be bounded
# (Greptile P1 / CodeRabbit on PR #354: 2**abs(-100000) and
# 2**factorial(10000) previously slipped through as 'symbolic').
_STATIC_EVALUABLE_CALLS = {
    "abs": abs,
    "factorial": _bounded_factorial,
    "binomial": _bounded_binomial,
    "Integer": int,
    "Float": float,
    "Rational": _rational,
}


def _static_constant(node: ast.Constant):
    if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
        return None
    return node.value


def _static_unary(node: ast.UnaryOp):
    operand = _static_value(node.operand)
    if operand is None:
        return None
    if isinstance(node.op, ast.USub):
        return -operand
    return operand  # UAdd — Invert never reaches here (node allowlist)


def _static_binop(node: ast.BinOp):
    left = _static_value(node.left)
    right = _static_value(node.right)
    if left is None or right is None:
        return None
    try:
        if isinstance(node.op, (ast.Pow, ast.BitXor)):
            # ^ counts as exponentiation on purpose: sympy's convert_xor
            # turns it into **, so the sympy-side cost is the power cost.
            return _static_pow(left, right)
        evaluate = _BINOP_EVALUATORS.get(type(node.op))
        if evaluate is None:
            return None
        return evaluate(left, right)
    except (ArithmeticError, TypeError, ValueError):
        # div-by-zero, Decimal/float mix, overflow — magnitude unknowable,
        # fail closed
        return _ASTRONOMICAL


def _static_call(node: ast.Call):
    """Evaluate allowlisted concrete-valued calls; symbolic-argument calls
    (sin(x)...) and non-allowlisted names stay exempt (None = symbolic)."""
    if not isinstance(node.func, ast.Name) or node.func.id not in _STATIC_EVALUABLE_CALLS:
        return None
    args = [_static_value(arg) for arg in node.args]
    if any(value is None for value in args):
        return None
    try:
        return _STATIC_EVALUABLE_CALLS[node.func.id](*args)
    except (ArithmeticError, TypeError, ValueError):
        return _ASTRONOMICAL


def _static_value(node: ast.AST):
    """Statically evaluate a subtree of numeric constants, arithmetic
    operators, and concrete-valued allowlisted calls, for the #353
    computational-cost bounds.

    Returns an int/float/Decimal/Fraction when the subtree is fully static,
    _ASTRONOMICAL when it is static but its exact value is intentionally
    NOT expanded (magnitude beyond the evaluator's own expansion budget),
    and None when anything symbolic (a name, or a call with symbolic
    arguments) is present — the caller fails closed on a static oversized
    value and lets symbolic expressions through (sympy handles symbolic
    magnitudes lazily).
    """
    if isinstance(node, ast.Constant):
        return _static_constant(node)
    if isinstance(node, ast.UnaryOp):
        return _static_unary(node)
    if isinstance(node, ast.BinOp):
        return _static_binop(node)
    if isinstance(node, ast.Call):
        return _static_call(node)
    return None


def _ast_node_depth(node: ast.AST, current: int = 0) -> int:
    max_depth = current
    for child in ast.iter_child_nodes(node):
        child_depth = _ast_node_depth(child, current + 1)
        if child_depth > max_depth:
            max_depth = child_depth
    return max_depth


_SYMPY_MAX_DEPTH = 40


def _sympy_tree_depth(expr: Any, current: int = 0) -> int:
    """Compute nesting depth of a SymPy expression tree."""
    max_depth = current
    for arg in getattr(expr, "args", ()):
        child_depth = _sympy_tree_depth(arg, current + 1)
        if child_depth > max_depth:
            max_depth = child_depth
    return max_depth


def _validate_sympy_result(result: Any) -> None:
    """Ensure parse_expr returned a valid SymPy expression within depth limits."""
    import sympy
    if not isinstance(result, sympy.Expr):
        raise SafeParserError(
            f"Parsed result is not a supported arithmetic expression, got {type(result).__name__}"
        )
    depth = _sympy_tree_depth(result)
    if depth > _SYMPY_MAX_DEPTH:
        raise SafeParserError(
            f"Expression tree depth {depth} exceeds limit of {_SYMPY_MAX_DEPTH}"
        )


def _build_safe_local_dict(
    extra_symbols: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    safe: Dict[str, Any] = {
        "x": Symbol("x"), "y": Symbol("y"), "z": Symbol("z"),
        "a": Symbol("a"), "b": Symbol("b"), "c": Symbol("c"),
        "d": Symbol("d"), "f": Symbol("f"), "g": Symbol("g"),
        "h": Symbol("h"), "k": Symbol("k"), "m": Symbol("m"),
        "n": Symbol("n", integer=True, positive=True),
        "p": Symbol("p"), "q": Symbol("q"), "r": Symbol("r"),
        "s": Symbol("s"), "t": Symbol("t"), "u": Symbol("u"),
        "v": Symbol("v"), "w": Symbol("w"),
        "alpha": Symbol("alpha"), "beta": Symbol("beta"),
        "gamma": Symbol("gamma"), "delta": Symbol("delta"),
        "epsilon": Symbol("epsilon"), "zeta": Symbol("zeta"),
        "eta": Symbol("eta"), "theta": Symbol("theta"),
        "iota": Symbol("iota"), "kappa": Symbol("kappa"),
        "mu": Symbol("mu"), "nu": Symbol("nu"),
        "xi": Symbol("xi"), "omicron": Symbol("omicron"),
        "rho": Symbol("rho"), "sigma": Symbol("sigma"),
        "tau": Symbol("tau"), "phi": Symbol("phi"),
        "chi": Symbol("chi"), "psi": Symbol("psi"),
        "omega": Symbol("omega"),
        "pi": pi, "E": E, "I": I, "oo": oo,
        "sin": sympy.sin, "cos": sympy.cos, "tan": sympy.tan,
        "cot": sympy.cot, "sec": sympy.sec, "csc": sympy.csc,
        "asin": sympy.asin, "acos": sympy.acos, "atan": sympy.atan,
        "atan2": sympy.atan2,
        "sinh": sympy.sinh, "cosh": sympy.cosh, "tanh": sympy.tanh,
        "log": sympy.log, "ln": sympy.log, "exp": sympy.exp,
        "sqrt": sympy.sqrt, "cbrt": sympy.cbrt,
        "abs": sympy.Abs, "Abs": sympy.Abs,
        "factorial": sympy.factorial, "binomial": sympy.binomial,
        "Integer": Integer, "Float": Float, "Rational": Rational,
        # Symbol is required because SymPy standard_transformations may emit
        # Symbol('name') during evaluation. This allows users to create symbols
        # with arbitrary names — the charset/AST gates and stripped builtins
        # mitigate downstream attribute-access risks on resulting objects.
        "Symbol": Symbol,
    }
    if extra_symbols:
        for key, value in extra_symbols.items():
            if not isinstance(key, str):
                raise SafeParserError(
                    f"extra_symbols keys must be strings, got {type(key).__name__}"
                )
            # Raw-key ASCII identifier check: no normalization, so a
            # fullwidth key can never NFKC-alias a built-in name at compile
            # time (PEP 3131). re.ASCII pins \w to [A-Za-z0-9_].
            if not re.match(r"^[A-Za-z_]\w*$", key, re.ASCII):
                raise SafeParserError(
                    f"extra_symbols key {key!r} is not a plain ASCII identifier"
                )
            if _DENYLIST_PATTERN.search(key):
                raise SafeParserError(
                    f"extra_symbols key {key!r} contains disallowed construct"
                )
            if not isinstance(value, (Symbol, sympy.Basic)):
                raise SafeParserError(
                    f"extra_symbols[{key!r}] must be a SymPy Symbol or Basic, "
                    f"got {type(value).__name__}"
                )
            safe[key] = value
    return safe


class SafeParserError(ValueError):
    pass


def safe_parse_expr(
    expression: str,
    *,
    extra_symbols: Optional[Dict[str, Any]] = None,
    transformations: Optional[Tuple] = None,
) -> Any:
    if not isinstance(expression, str):
        raise SafeParserError(
            f"Expression must be a string, got {type(expression).__name__}"
        )
    # NFKC before every filter: PEP 3131 normalizes identifiers at compile
    # time, so the filters must operate on what the compiler will see
    # (issue #330 — fullwidth/bold codepoints bypassed the ASCII denylist).
    stripped = unicodedata.normalize("NFKC", expression.strip())
    if not stripped:
        raise SafeParserError("Expression is empty")
    if len(stripped) > MAX_EXPRESSION_LENGTH:
        raise SafeParserError(
            f"Expression exceeds maximum length of {MAX_EXPRESSION_LENGTH} characters"
        )
    if not _CHARSET_PATTERN.match(stripped):
        raise SafeParserError(
            "Expression contains disallowed characters. Only arithmetic "
            "operators, decimal numbers, identifiers, and whitespace are supported."
        )
    if _BAD_DECIMAL_DOT.search(stripped):
        raise SafeParserError(
            "Expression contains disallowed use of '.': it may only appear "
            "as a decimal point between digits (attribute access is not supported)."
        )
    match = _DENYLIST_PATTERN.search(stripped)
    if match:
        raise SafeParserError(
            f"Expression contains disallowed construct: {match.group()!r}"
        )
    _check_ast_safety(stripped)
    local_dict = _build_safe_local_dict(extra_symbols)
    if transformations is None:
        transformations = standard_transformations + (
            convert_xor,
            implicit_multiplication_application,
        )
    global_dict = dict(_SAFE_GLOBAL_DICT_TEMPLATE)
    try:
        result = parse_expr(
            stripped,
            local_dict=local_dict,
            global_dict=global_dict,
            transformations=transformations,
        )
        _validate_sympy_result(result)
        return result
    except SafeParserError:
        raise
    except Exception as exc:
        raise SafeParserError(f"Failed to parse expression: {exc}") from exc


def validate_variable_name(variable: str) -> str:
    if not isinstance(variable, str):
        raise SafeParserError(
            f"Variable name must be a string, got {type(variable).__name__}"
        )
    stripped = unicodedata.normalize("NFKC", variable.strip())
    if not stripped:
        raise SafeParserError("Variable name is empty")
    if len(stripped) > 50:
        raise SafeParserError("Variable name is too long")
    if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", stripped):
        raise SafeParserError(
            f"Invalid variable name: {stripped!r}. "
            "Must start with a letter and contain only alphanumeric characters."
        )
    match = _DENYLIST_PATTERN.search(stripped)
    if match:
        raise SafeParserError(
            f"Variable name contains disallowed construct: {match.group()!r}"
        )
    return stripped


def get_safe_symbol(name: str) -> Symbol:
    """Return a Symbol consistent with safe_parse_expr's namespace.

    Ensures calculus operation variables match any special assumptions
    (e.g. Symbol(\"n\", integer=True, positive=True)) applied during parsing,
    preventing symbol mismatch in diff/integrate/limit.
    """
    name = validate_variable_name(name)
    safe = _build_safe_local_dict()
    if name in safe:
        sym = safe[name]
        if isinstance(sym, Symbol):
            return sym
    return Symbol(name)
