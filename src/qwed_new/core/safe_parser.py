"""
Safe SymPy expression parser.

Wraps sympy.parsing.sympy_parser.parse_expr with input validation,
a denylist for dangerous constructs, and a restricted evaluation
namespace.  This module is the ONLY approved entry point for parsing
user-supplied math expressions in production code.

Security boundary:
    1. Reject known-dangerous Python/OS constructs (denylist).
    2. Remove __builtins__ from the eval global dict.
    3. Allow-list only expected math symbols, constants, and functions.
    4. Enforce basic input validation (type, length, empty check).

CWE-95 mitigation -- see PR #200 for full security analysis.
"""

import ast
import re
from typing import Any, Dict, Optional, Tuple

import sympy
from sympy import (
    E, I, Integer, Float, Rational, Symbol, oo, pi,
)
from sympy.parsing.sympy_parser import (
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

_SAFE_GLOBAL_DICT_TEMPLATE: Dict[str, Any] = {"__builtins__": {}}


def _check_ast_depth(expression: str) -> None:
    """Reject Python-parseable expressions exceeding max AST depth (DoS defence).

    Expressions using implicit multiplication (e.g. 2x, sin x) fail ast.parse
    and skip this check — they are caught by the post-parse sympy depth check.
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
    if not isinstance(result, sympy.Basic):
        raise SafeParserError(
            f"Parsed result is not a valid SymPy expression, got {type(result).__name__}"
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
        "pi": pi, "e": E, "E": E, "I": I, "oo": oo,
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
        # with arbitrary names — the denylist and stripped builtins mitigate
        # downstream attribute-access risks on resulting objects.
        "Symbol": Symbol,
    }
    if extra_symbols:
        for key, value in extra_symbols.items():
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
    stripped = expression.strip()
    if not stripped:
        raise SafeParserError("Expression is empty")
    if len(stripped) > MAX_EXPRESSION_LENGTH:
        raise SafeParserError(
            f"Expression exceeds maximum length of {MAX_EXPRESSION_LENGTH} characters"
        )
    match = _DENYLIST_PATTERN.search(stripped)
    if match:
        raise SafeParserError(
            f"Expression contains disallowed construct: {match.group()!r}"
        )
    _check_ast_depth(stripped)
    local_dict = _build_safe_local_dict(extra_symbols)
    if transformations is None:
        transformations = standard_transformations + (
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
    except Exception:
        raise SafeParserError("Failed to parse expression") from None


def validate_variable_name(variable: str) -> str:
    if not isinstance(variable, str):
        raise SafeParserError(
            f"Variable name must be a string, got {type(variable).__name__}"
        )
    stripped = variable.strip()
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
