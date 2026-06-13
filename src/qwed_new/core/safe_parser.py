"""
Safe wrapper around sympy's parse_expr to prevent code execution.

sympy.parsing.sympy_parser.parse_expr() uses Python eval() internally.
Without restrictions on local_dict/global_dict, an attacker can execute
arbitrary code via crafted math expressions (CWE-95).

This module provides safe_parse_expr() which:
1. Validates input against a denylist of dangerous patterns
2. Restricts the eval namespace to only known-safe sympy objects
3. Strips Python builtins from the global namespace

Usage:
    from qwed_new.core.safe_parser import safe_parse_expr
    expr = safe_parse_expr("x**2 + 2*x + 1")
"""

import re
import logging
from typing import Optional, Dict, Any

import sympy
from sympy import (
    Symbol, Integer, Float, Rational,
    pi, E, oo, I,
)
from sympy.parsing.sympy_parser import (
    parse_expr,
    standard_transformations,
    implicit_multiplication_application,
)

logger = logging.getLogger(__name__)

# Transformations that enable natural math input (e.g. "2x" → "2*x")
SAFE_TRANSFORMATIONS = standard_transformations + (implicit_multiplication_application,)

# Patterns that must never appear in math expressions.
# Checked before the string reaches parse_expr / eval.
_DANGEROUS_PATTERNS = re.compile(
    r"__\w+__|"         # dunder attributes (__import__, __class__, …)
    r"\bimport\b|"      # import keyword
    r"\bexec\b|"        # exec()
    r"\beval\b|"        # eval()
    r"\bgetattr\b|"     # getattr()
    r"\bsetattr\b|"     # setattr()
    r"\bdelattr\b|"     # delattr()
    r"\bglobals\b|"     # globals()
    r"\blocals\b|"      # locals()
    r"\bcompile\b|"     # compile()
    r"\bopen\b|"        # open()
    r"\bbreakpoint\b|"  # breakpoint()
    r"\bprint\b|"       # print()
    r"\binput\b|"       # input()
    r"\bvars\b|"        # vars()
    r"\bdir\b|"         # dir()
    r"\btype\b|"        # type()
    r"\bsuper\b|"       # super()
    r"\bsubclasses\b|"  # __subclasses__()
    r"\bmro\b|"         # mro()
    r"\bbases\b|"       # __bases__
    r"\bos\b|"          # os module
    r"\bsys\b|"         # sys module
    r"\bsubprocess\b",  # subprocess module
    re.IGNORECASE,
)

# Regex for validating variable names passed to Symbol().
# Allows single-letter, Greek names, and conventional multi-letter math
# variable names.  Must start with a letter and contain only alphanumerics
# and underscores, with a reasonable length cap.
_SAFE_VARIABLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,49}$")


def validate_variable_name(name: str) -> None:
    """
    Validate a user-supplied variable name before it reaches Symbol().

    Applies the same length cap, denylist, and character-set checks that
    safe_parse_expr applies to full expressions, keeping the hardened
    boundary consistent across all user-controlled string inputs.

    Raises:
        ValueError: If the name is invalid or contains dangerous patterns.
    """
    if not isinstance(name, str):
        raise ValueError("Variable name must be a string")

    stripped = name.strip()
    if not stripped:
        raise ValueError("Variable name must not be empty")

    if not _SAFE_VARIABLE_RE.match(stripped):
        raise ValueError(
            "Variable name must start with a letter, contain only "
            "alphanumerics/underscores, and be at most 50 characters"
        )

    if _DANGEROUS_PATTERNS.search(stripped):
        raise ValueError("Variable name contains disallowed constructs")


def _build_safe_local_dict(extra_symbols: Optional[Dict[str, Any]] = None) -> dict:
    """
    Build the allow-listed local namespace for parse_expr.

    Only mathematical symbols, constants, functions, and the internal
    sympy types that parse_expr's transformations emit are included.
    Includes common Greek-letter and multi-letter symbolic variable names
    used in standard mathematical and scientific notation.
    """
    safe = {
        # Common single-letter symbolic variables
        "x": Symbol("x"),
        "y": Symbol("y"),
        "z": Symbol("z"),
        "a": Symbol("a"),
        "b": Symbol("b"),
        "c": Symbol("c"),
        "n": Symbol("n", integer=True, positive=True),
        "t": Symbol("t"),
        "r": Symbol("r"),
        "k": Symbol("k"),
        "m": Symbol("m"),
        "p": Symbol("p"),
        "q": Symbol("q"),
        "u": Symbol("u"),
        "v": Symbol("v"),
        "w": Symbol("w"),
        # Greek-letter symbolic variables (common in verification workloads)
        "alpha": Symbol("alpha"),
        "beta": Symbol("beta"),
        "gamma": Symbol("gamma"),
        "delta": Symbol("delta"),
        "epsilon": Symbol("epsilon"),
        "zeta": Symbol("zeta"),
        "eta": Symbol("eta"),
        "theta": Symbol("theta"),
        "iota": Symbol("iota"),
        "kappa": Symbol("kappa"),
        "mu": Symbol("mu"),
        "nu": Symbol("nu"),
        "xi": Symbol("xi"),
        "omicron": Symbol("omicron"),
        "rho": Symbol("rho"),
        "sigma": Symbol("sigma"),
        "tau": Symbol("tau"),
        "upsilon": Symbol("upsilon"),
        "phi": Symbol("phi"),
        "chi": Symbol("chi"),
        "psi": Symbol("psi"),
        "omega": Symbol("omega"),
        # Capital Greek letters commonly used as symbols
        "Alpha": Symbol("Alpha"),
        "Beta": Symbol("Beta"),
        "Gamma": Symbol("Gamma"),
        "Delta": Symbol("Delta"),
        "Theta": Symbol("Theta"),
        "Lambda": Symbol("Lambda"),
        "Sigma": Symbol("Sigma"),
        "Phi": Symbol("Phi"),
        "Psi": Symbol("Psi"),
        "Omega": Symbol("Omega"),
        # Mathematical constants
        "pi": pi,
        "e": E,
        "E": E,
        "I": I,
        "oo": oo,
        # Trigonometric functions
        "sin": sympy.sin,
        "cos": sympy.cos,
        "tan": sympy.tan,
        "cot": sympy.cot,
        "sec": sympy.sec,
        "csc": sympy.csc,
        # Inverse trigonometric
        "asin": sympy.asin,
        "acos": sympy.acos,
        "atan": sympy.atan,
        "atan2": sympy.atan2,
        # Hyperbolic
        "sinh": sympy.sinh,
        "cosh": sympy.cosh,
        "tanh": sympy.tanh,
        # Logarithmic / exponential
        "log": sympy.log,
        "ln": sympy.log,
        "exp": sympy.exp,
        # Roots and absolute value
        "sqrt": sympy.sqrt,
        "cbrt": sympy.cbrt,
        "abs": sympy.Abs,
        "Abs": sympy.Abs,
        # Combinatorial
        "factorial": sympy.factorial,
        "binomial": sympy.binomial,
        # Sympy internal types emitted by standard_transformations
        "Integer": Integer,
        "Float": Float,
        "Rational": Rational,
        "Symbol": Symbol,
    }

    if extra_symbols:
        # Only allow Symbol instances or sympy types as overrides
        for key, value in extra_symbols.items():
            if isinstance(value, (Symbol, sympy.Basic)):
                safe[key] = value

    return safe


# Pre-built global dict that strips builtins.
# IMPORTANT: A shallow copy is made per invocation (see safe_parse_expr)
# to prevent cross-call mutation by SymPy transformations.
_SAFE_GLOBAL_DICT: dict = {"__builtins__": {}}


def safe_parse_expr(
    expression: str,
    *,
    transformations=SAFE_TRANSFORMATIONS,
    extra_symbols: Optional[Dict[str, Any]] = None,
) -> sympy.Basic:
    """
    Safely parse a mathematical expression string into a sympy expression.

    Raises ValueError if the expression contains dangerous patterns or
    cannot be parsed.

    Args:
        expression: The math expression string to parse.
        transformations: sympy transformations to apply (default includes
            implicit multiplication).
        extra_symbols: Additional Symbol mappings to include in the
            local namespace.

    Returns:
        A sympy expression object.

    Raises:
        ValueError: If the expression is rejected by safety checks or
            cannot be parsed.
    """
    if not isinstance(expression, str):
        raise ValueError("Expression must be a string")

    stripped = expression.strip()
    if not stripped:
        raise ValueError("Expression must not be empty")

    # Length limit to prevent resource exhaustion
    if len(stripped) > 5000:
        raise ValueError("Expression too long (max 5000 characters)")

    # Deny-list check: reject expressions with dangerous patterns
    if _DANGEROUS_PATTERNS.search(stripped):
        raise ValueError("Expression contains disallowed constructs")

    local_dict = _build_safe_local_dict(extra_symbols)

    try:
        return parse_expr(
            stripped,
            local_dict=local_dict,
            global_dict=dict(_SAFE_GLOBAL_DICT),
            transformations=transformations,
        )
    except Exception as exc:
        raise ValueError(f"Failed to parse expression: {exc}") from exc
