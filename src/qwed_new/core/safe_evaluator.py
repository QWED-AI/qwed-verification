"""
Safe Evaluator for Z3 Constraints.
Replaces unsafe eval() with a restricted execution environment.
"""
import ast
from typing import Any, Dict
from z3 import *

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

        self._allowed_node_types = (
            ast.Expression,
            ast.Call,
            ast.Name,
            ast.Load,
            ast.Constant,
            ast.List,
            ast.Tuple,
            ast.BoolOp,
            ast.UnaryOp,
            ast.BinOp,
            ast.Compare,
            ast.And,
            ast.Or,
            ast.Not,
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

            if isinstance(node, ast.Name) and node.id not in allowed_names:
                raise ValueError(f"Unsafe expression name detected: {node.id}")

            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name):
                    raise ValueError("Unsafe call target detected")
                if node.func.id not in self.allowed_globals or node.func.id == "__builtins__":
                    raise ValueError(f"Unsafe function call detected: {node.func.id}")
        
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
