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

The denylist alone can never defend an eval sink — layers 2 and 4 are
the structural guarantee; layer 3 catches residual non-expression
names early with a clearer error.

CWE-95 mitigation -- see PR #200 for the original security analysis
and issues #329/#330 for the bypasses this structure closes.
"""

import ast
import re
import unicodedata
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


def _check_ast_safety(expression: str) -> None:
    """Reject Python-parseable expressions that use non-arithmetic syntax
    or exceed max AST depth (issues #329/#330).

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
