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
       measured 9**9**9**9 hang). diff/Derivative share one order budget
       per parse (#522).

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

__all__ = [
    "safe_parse_expr",
    "validate_variable_name",
    "get_safe_symbol",
    "check_sympy_expansion_cost",
    "check_closed_expression_cost",
    "SafeParserError",
    "DerivativeNotationError",
    "DERIVATIVE_NOTATION_MESSAGE",
]

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
# diff/Derivative (#522): each order multiplies the size of the result, and
# simplify then works on that (measured: order 3 of exp(x*sin(x)*cos(x)*tan(x))
# simplifies in ~2.5s, order 4 in ~7.7s, order 10 differentiates alone in
# ~18s). The bound is on the total order across one parse, so nesting
# diff(diff(...)) cannot get around it.
_MAX_DERIVATIVE_ORDER = 3

_DERIVATIVE_CALLS = frozenset({"diff", "Derivative"})

# Leibniz notation (#522): d/dx(x^2), d(x^2)/dx, dy/(2*dx), d/d(x)(x^2). The
# parser would read d and dx as symbols (d/dx(x^2) is x**3), so the claim it
# decides is not the one written. Two shapes give it away, wherever they
# stand (/dx, /(-2*dfoo), x*dx): a name that starts with "d" and that the
# parser does not know (dx, dtheta, d2y, dfoo), which it would split into
# letters anyway; and a lone "d" a denominator applies to a variable (d(x),
# d x). A "d" name the parser knows (delta, diff, a caller's symbol) or keeps
# whole (distance_m, which has "_") is not a differential.
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*", re.ASCII)
_DIVIDED_BY_LONE_D = re.compile(r"/\s*(?:\(\s*)?d\b\s*[(A-Za-z]", re.ASCII)

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


_DERIVATIVE_POSITION_MESSAGE = (
    "A derivative cannot appear in a power, factorial or binomial: its value "
    "is only known once it is evaluated, so its expansion cannot be bounded"
)


def _is_derivative_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _DERIVATIVE_CALLS


def _check_derivative_position(node: ast.AST) -> None:
    """The gates read a derivative as symbolic, but it evaluates first and
    can return a number: 2**(diff(10000*x, x)**9) is 2**(10000**9) (#522).
    Keep derivatives out of everything that expands eagerly."""
    expands = (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow)) or (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in _EXACT_EXPANSION_CALLS
    )
    if expands and any(_is_derivative_call(child) for child in ast.walk(node)):
        raise SafeParserError(_DERIVATIVE_POSITION_MESSAGE)


def _check_derivative_positions(expression: str) -> None:
    """:func:`_check_derivative_position` over the expression with ^ read
    as SymPy reads it. Python gives ^ the lowest precedence, so in
    diff(x^3, x) - 3*x^2 the derivative would sit inside the XOR (Sentry
    on PR #558); as ** it binds only x and 2."""
    if not any(name in expression for name in _DERIVATIVE_CALLS):
        return
    for node in ast.walk(ast.parse(expression.replace("^", "**"), mode="eval")):
        _check_derivative_position(node)


# Stands in for diff/Derivative in the unevaluated cost parse. An undefined
# function takes any arguments, so an order SymPy cannot read there
# (diff(x, x, 1+0)) cannot make that parse fail and skip the gates.
_UNEVALUATED_DERIVATIVE = sympy.Function("unevaluated_derivative")


def _check_unevaluated_derivative_position(expr: Any, expanding: bool = False) -> None:
    """:func:`_check_derivative_position` on an unevaluated SymPy tree.

    Unevaluated, a/b is Mul(a, Pow(b, -1)) and sqrt(b) is Pow(b, 1/2): a
    reciprocal or a root expands nothing, so only other powers count."""
    if expanding and isinstance(expr, _UNEVALUATED_DERIVATIVE):
        raise SafeParserError(_DERIVATIVE_POSITION_MESSAGE)
    if isinstance(expr, sympy.Pow):
        exponent = expr.exp
        expanding = expanding or not (exponent.is_Rational and abs(exponent.p) == 1)
    else:
        expanding = expanding or isinstance(expr, (sympy.factorial, sympy.binomial))
    for arg in getattr(expr, "args", ()):
        _check_unevaluated_derivative_position(arg, expanding)


def _unevaluated_derivative(*args: Any, **_kwargs: Any) -> Any:
    return _UNEVALUATED_DERIVATIVE(*args)


def _fold_exact(node: Any):
    """Fold an exact-number SymPy subtree to an int or Fraction WITHOUT letting
    SymPy evaluate it, raising the moment a power would exceed the expansion
    bounds. Returns None for any subtree that is not an exact number (symbols,
    floats, transcendental constants), so symbolic powers stay lazy.

    Check Pow BEFORE is_Integer: an unevaluated Pow like 9**(9**9) reports
    is_Integer == True, and int() on it would force the full expansion this
    gate exists to prevent. Powers are handled structurally via base/exp.
    """
    if isinstance(node, sympy.Pow):
        return _fold_exact_pow(node)
    if node.is_Integer:
        return int(node)
    if node.is_Rational:
        return Fraction(int(node.p), int(node.q))
    if isinstance(node, (sympy.Add, sympy.Mul)):
        return _fold_exact_sum_or_product(node)
    return None


def _check_expansion_digits(value) -> None:
    if value != 0 and _exact_digits(value) > _MAX_EXPANSION_DIGITS:
        raise SafeParserError("Expression demands unbounded exact-integer expansion")


def _fold_exact_pow(node: Any):
    base = _fold_exact(node.base)
    exponent = _fold_exact(node.exp)
    if exponent is not None and abs(exponent) > _MAX_EXPONENT_MAGNITUDE:
        # Whatever the base (Integer, Rational, sqrt(2), ...), SymPy
        # expands an exact power with an exponent this large eagerly.
        raise SafeParserError(
            f"Exponent exceeds the maximum magnitude of {_MAX_EXPONENT_MAGNITUDE}"
        )
    if base is None or exponent is None:
        return None
    if base != 0 and _exact_digits(base) * abs(exponent) > _MAX_EXPANSION_DIGITS:
        raise SafeParserError("Expression demands unbounded exact-integer expansion")
    if not isinstance(exponent, int):
        return None  # irrational result (e.g. 9**(1/2)): not an exact number
    if exponent >= 0:
        return base ** exponent
    return None if base == 0 else Fraction(base) ** exponent


def _fold_exact_sum_or_product(node: Any):
    is_add = isinstance(node, sympy.Add)
    acc = 0 if is_add else 1
    for arg in node.args:
        value = _fold_exact(arg)
        if value is None:
            return None
        acc = acc + value if is_add else acc * value
        _check_expansion_digits(acc)
    return acc


def _exact_digits(value) -> int:
    """Upper-bound digit count of an int or Fraction (largest of its parts)."""
    if isinstance(value, Fraction):
        return max(_magnitude_digits(value.numerator), _magnitude_digits(value.denominator))
    return _magnitude_digits(value)


def check_sympy_expansion_cost(expr: Any) -> None:
    """Reject a SymPy tree whose evaluation would demand unbounded expansion.

    The tree must be UNEVALUATED (built with ``evaluate=False``): SymPy
    expands exact-integer powers and factorials eagerly, so the check has to
    run before evaluation does. Walks ``.args`` manually — do NOT use
    sympy.preorder_traversal here: iterating it forces evaluation of nested
    Pow nodes and re-triggers the very expansion this gate prevents.

    Raises:
        SafeParserError: if any power, product, factorial or binomial in the
            tree exceeds the expansion bounds.
    """
    if isinstance(expr, sympy.Pow):
        _fold_exact(expr)
    elif isinstance(expr, (sympy.Add, sympy.Mul)):
        _fold_exact(expr)
    elif isinstance(expr, (sympy.factorial, sympy.binomial, sympy.gamma)):
        for arg in expr.args:
            value = _fold_exact(arg)
            if value is not None and abs(value) > _MAX_EXPONENT_MAGNITUDE:
                raise SafeParserError(
                    f"{type(expr).__name__} argument exceeds the maximum magnitude "
                    f"of {_MAX_EXPONENT_MAGNITUDE}"
                )
    for arg in getattr(expr, "args", ()):
        check_sympy_expansion_cost(arg)


# Functions whose value grows like exp(arg): a tower of them is as explosive
# as a tower of powers once evaluated numerically.
_EXP_GROWTH_FUNCTIONS = (sympy.exp, sympy.sinh, sympy.cosh)


def check_closed_expression_cost(expr: Any) -> None:
    """Reject a symbol-free SymPy tree that is unsafe to evaluate.

    For a closed expression that is about to be evaluated (e.g. a symbolic
    claim with a witness point substituted in). The tree must be UNEVALUATED.
    On top of :func:`check_sympy_expansion_cost`, every power exponent and
    every exp/sinh/cosh argument must fold to an exact rational within
    ``_MAX_EXPONENT_MAGNITUDE``. An exponent that does not fold (``9**(33/4)``,
    ``sin(1)``, ``pi``) cannot be bounded statically, and a tower built from
    one can make even a numeric ``is_zero`` check hang, so it is rejected.

    Raises:
        SafeParserError: if the tree has free symbols or fails a bound.
    """
    if getattr(expr, "free_symbols", None):
        raise SafeParserError("Expression is not closed: it still has free symbols")
    check_sympy_expansion_cost(expr)
    _check_closed_growth(expr)


def _check_closed_growth(node: Any) -> None:
    if isinstance(node, sympy.Pow):
        operand = _fold_exact(node.exp)
    elif isinstance(node, _EXP_GROWTH_FUNCTIONS):
        operand = _fold_exact(node.args[0])
    else:
        operand = 0
    if operand is None or abs(operand) > _MAX_EXPONENT_MAGNITUDE:
        raise SafeParserError(
            "Growth operand is not an exact number within the maximum magnitude "
            f"of {_MAX_EXPONENT_MAGNITUDE}; evaluation cannot be bounded"
        )
    for arg in getattr(node, "args", ()):
        _check_closed_growth(arg)


def _check_unevaluated_sympy_cost(expression: str) -> None:
    """Cost-gate an expression that is not valid Python (implicit multiplication).

    ``9^9^9 x`` fails ast.parse, so the AST cost gates were skipped entirely and
    the expression went straight to ``parse_expr`` which expands the exact
    integer power eagerly (#353 bypass). Parse it WITHOUT evaluation (cheap,
    measured sub-10ms) and reject any Pow / factorial / binomial whose operands
    are concrete integers beyond the expansion bounds, before the eager
    evaluation can run.
    """
    # Cheap pre-screen on the RAW string before parse_expr, which itself evaluates
    # factorial/binomial eagerly even with evaluate=False — so a bomb like
    # factorial(10**9) would DoS the cost checker itself. Reject oversized numeric
    # arguments to the exact-expansion calls, and oversized bare integer literals,
    # up front.
    for call_match in re.finditer(r"\b(factorial|binomial)\s*\(([^()]*)\)", expression):
        for num in re.findall(r"\d+", call_match.group(2)):
            if int(num) > _MAX_EXPONENT_MAGNITUDE:
                raise SafeParserError(
                    f"{call_match.group(1)} argument exceeds the maximum magnitude "
                    f"of {_MAX_EXPONENT_MAGNITUDE}"
                )
    for num in re.findall(r"\d+", expression):
        if len(num) > len(str(_MAX_INTEGER_LITERAL)):
            raise SafeParserError(
                "Expression contains an integer literal that is too large"
            )

    try:
        import sympy
        from sympy.parsing.sympy_parser import (
            parse_expr,
            standard_transformations,
            convert_xor,
            implicit_multiplication_application,
        )
        transformations = standard_transformations + (
            convert_xor,
            implicit_multiplication_application,
        )
        # NB: a restricted global_dict (empty __builtins__) makes
        # parse_expr(evaluate=False) raise, so use sympy's default namespace —
        # this call only inspects structure for cost, it does not feed the result
        # to the engine (safe_parse_expr re-parses with the hardened namespace).
        # diff/Derivative stay unevaluated here (#522): evaluating them is
        # what the order budget in the main parse bounds.
        expr = parse_expr(
            expression,
            local_dict={"diff": _unevaluated_derivative, "Derivative": _unevaluated_derivative},
            transformations=transformations,
            evaluate=False,
        )
    except SafeParserError:
        raise
    except Exception:
        # Not parseable even by sympy — let the main parse path raise.
        return

    check_sympy_expansion_cost(expr)
    _check_unevaluated_derivative_position(expr)


def _run_cost_gates(tree: ast.AST) -> None:
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


def _check_ast_safety(expression: str) -> None:
    """Reject Python-parseable expressions that use non-arithmetic syntax,
    exceed max AST depth, or demand unbounded exact-integer expansion
    (issues #329/#330/#353).

    Expressions using implicit multiplication (e.g. 2x, sin x) are not valid
    Python, so ast.parse fails. Rather than skip the cost gates (which let
    ``9^9^9 x`` through — #353 bypass), re-derive the source sympy will
    evaluate and run the gates on that. Node-shape checks are not applied to
    the transformed source because sympy emits Symbol('x')/Integer(...) call
    wrappers that are not part of the user's grammar; the charset gate already
    bounds the raw input, and the cost gates are what matter here.
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        # Implicit-multiplication input (e.g. "9^9^9 x") is not valid Python.
        # Gate it on the unevaluated sympy tree instead of skipping (#353 bypass).
        _check_unevaluated_sympy_cost(expression)
        return
    _run_cost_gates(tree)
    _check_derivative_positions(expression)


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


def _bounded_derivative():
    """Return a diff/Derivative for one parse, with its own order budget.

    Both names evaluate the derivative, so ``Derivative(x**2, x)`` reads as
    ``2*x``. The order is counted on the unevaluated Derivative before any
    differentiation runs, and the budget is shared by every call in the
    parse, nested ones included.
    """
    budget = [_MAX_DERIVATIVE_ORDER]

    def derivative(expr: Any, *variables: Any) -> Any:
        unevaluated = sympy.Derivative(expr, *variables, evaluate=False)
        if not isinstance(unevaluated, sympy.Derivative):
            return unevaluated  # a zero order leaves the expression as it is
        order = unevaluated.derivative_count
        if not order.is_Integer or order > budget[0]:
            raise SafeParserError(
                f"Derivative order exceeds the maximum of {_MAX_DERIVATIVE_ORDER} "
                "in one expression"
            )
        budget[0] -= int(order)
        return unevaluated.doit()

    return derivative


def _build_safe_local_dict(
    extra_symbols: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    derivative = _bounded_derivative()
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
        "diff": derivative, "Derivative": derivative,
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


DERIVATIVE_NOTATION_MESSAGE = (
    "Expression uses d/dx notation, which cannot be read unambiguously; "
    "write diff(f, x) instead"
)


class DerivativeNotationError(SafeParserError):
    """Leibniz notation (d/dx, dy/dx), refused rather than misread (#522)."""


def _leibniz_differential(expression: str, names: Dict[str, Any]) -> Optional[str]:
    """The first differential written in ``expression``, or None."""
    lone_d = _DIVIDED_BY_LONE_D.search(expression)
    if lone_d:
        return lone_d.group()
    tokens = _IDENTIFIER.findall(expression)
    for token in tokens:
        if not token.startswith("d") or len(token) == 1 or token in names:
            continue
        # SymPy keeps a name with "_" whole (distance_m is one symbol), so it
        # is a differential only when its tail is a variable used beside it
        # (dx_1 next to x_1, Gitar on PR #558).
        if "_" not in token or token[1:] in tokens or token[1:] in names:
            return token
    return None


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
    local_dict = _build_safe_local_dict(extra_symbols)
    leibniz = _leibniz_differential(stripped, local_dict)
    if leibniz:
        raise DerivativeNotationError(f"{DERIVATIVE_NOTATION_MESSAGE}: {leibniz!r}")
    _check_ast_safety(stripped)
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
