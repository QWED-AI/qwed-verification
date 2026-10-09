"""
Safe Evaluator for Z3 Constraints.
Replaces unsafe eval() with a restricted execution environment.
"""
import ast
from typing import Any, Dict
from z3 import *

# Cost bounds for statically-known integer exponentiation. Python computes
# ``int ** int`` in full before Z3 ever sees the value, so an expression like
# ``x == 9**9**9`` expands a multi-hundred-million-digit integer on the request
# thread (DoS). Mirror the magnitudes used by safe_parser.
_MAX_EXPONENT_MAGNITUDE = 10_000
_MAX_EXPANSION_DIGITS = 100_000


def _const_int(node: ast.AST):
    """Statically fold an integer-only subtree to its int value, or None if the
    subtree is not a pure integer constant expression.

    Folds nested integer powers (``9**9`` inside ``9**9**9``) so the outer
    exponent's true magnitude is known, but raises ValueError the moment a power
    would exceed the expansion bounds — never materializing the huge integer.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        inner = _const_int(node.operand)
        if inner is None:
            return None
        return -inner if isinstance(node.op, ast.USub) else inner
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
        base = _const_int(node.left)
        exponent = _const_int(node.right)
        if base is None or exponent is None:
            return None
        if abs(exponent) > _MAX_EXPONENT_MAGNITUDE:
            raise ValueError(
                "Unsafe expression: exponent exceeds the maximum magnitude "
                f"of {_MAX_EXPONENT_MAGNITUDE}"
            )
        if base != 0 and len(str(abs(base))) * abs(exponent) > _MAX_EXPANSION_DIGITS:
            raise ValueError(
                "Unsafe expression: demands unbounded exact-integer expansion"
            )
        return base ** exponent
    return None


class SafeEvaluator:
    """
    Safely evaluates Z3 constraint strings by restricting globals/locals.
    """
    
    def __init__(self):
        # Whitelist of allowed Z3 functions and types
        self.allowed_globals = {
            '__builtins__': {},  # BLOCK ALL BUILTINS (no open, import, etc.)
            'And': And,
            'Or': Or,
            'Not': Not,
            'Implies': Implies,
            'If': If,
            'ForAll': ForAll,
            'Exists': Exists,
            'Sum': Sum,
            'Product': Product,
            'BitVec': BitVec,
            'Array': Array,
            'Select': Select,
            'Store': Store,
            'True': True,
            'False': False,
            'Int': Int,
            'Bool': Bool,
            'Real': Real,
        }

        # NOTE: Python boolean operators (and/or/not) and chained comparisons
        # are deliberately NOT in this list. On Z3 objects they do not build a
        # Z3 formula — Python evaluates them with bool()/structural ==, which
        # silently changes the constraint and can prove false theorems
        # (GHSA-mfh5-3c8f-975p). Callers must use the Z3 builders And/Or/Not.
        self._allowed_node_types = (
            ast.Expression,
            ast.Call,
            ast.Name,
            ast.Load,
            ast.Constant,
            ast.List,
            ast.Tuple,
            ast.UnaryOp,
            ast.BinOp,
            ast.Compare,
            ast.UAdd,
            ast.USub,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.Mod,
            ast.Pow,
            ast.Eq,
            ast.NotEq,
            ast.Lt,
            ast.LtE,
            ast.Gt,
            ast.GtE,
        )

    def _validate_ast(self, tree: ast.AST, context: Dict[str, Any]) -> None:
        """Allow only a small AST subset for Z3 constraint evaluation."""
        allowed_names = set(context) | {name for name in self.allowed_globals if name != "__builtins__"}

        for node in ast.walk(tree):
            if not isinstance(node, self._allowed_node_types):
                raise ValueError(f"Unsafe expression node detected: {type(node).__name__}")

            # Chained comparisons (e.g. ``0 < x < 5``) desugar to a Python
            # ``and`` over Z3 relations, which Z3 cannot cast to bool. Require a
            # single comparator so the constraint is an unambiguous Z3 relation;
            # callers must split chains into And(0 < x, x < 5).
            if isinstance(node, ast.Compare) and len(node.ops) != 1:
                raise ValueError("Unsafe expression: chained comparison; use And(...) instead")

            if isinstance(node, ast.Name) and node.id not in allowed_names:
                raise ValueError(f"Unsafe expression name detected: {node.id}")

            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name):
                    raise ValueError("Unsafe call target detected")
                if node.func.id not in self.allowed_globals or node.func.id == "__builtins__":
                    raise ValueError(f"Unsafe function call detected: {node.func.id}")

            # Bound statically-known integer powers before Python expands them.
            # _const_int folds nested constant powers and raises if any power
            # would exceed the expansion bounds.
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
                _const_int(node)
        
    def safe_eval(self, expression: str, context: Dict[str, Any]) -> Any:
        """
        Evaluate an expression string with a restricted context.
        
        Args:
            expression: The constraint string (e.g., "x > 5")
            context: Dictionary of variables (e.g., {'x': Int('x')})
            
        Returns:
            Z3 Expression
            
        Raises:
            ValueError: If unsafe code is detected or evaluation fails.
        """
        stripped = expression.strip()

        # 1. Reject obvious dunder access early
        if "__" in stripped:
             raise ValueError(f"Unsafe expression detected (double underscore): {expression}")

        # 2. Parse and validate AST before evaluation
        try:
            tree = ast.parse(stripped, mode="eval")
        except SyntaxError as exc:
            raise ValueError(f"Invalid expression syntax: {exc}") from exc
        self._validate_ast(tree, context)

        # 3. Merge context
        eval_locals = context.copy()
        restricted_globals = {k: v for k, v in self.allowed_globals.items() if k != "__builtins__"}
        restricted_globals["__builtins__"] = {}
        
        try:
            # 4. Execute the validated AST in a restricted namespace
            code = compile(tree, "<safe_z3_expr>", "eval")
            return eval(code, restricted_globals, eval_locals)  # noqa: S307  # nosec - AST-validated
        except Exception as e:
            raise ValueError(f"Safe evaluation failed for '{expression}': {str(e)}")
