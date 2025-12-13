"""
Safe Evaluator for Z3 Constraints.
Replaces unsafe eval() with a restricted execution environment.
"""
import ast
from typing import Any, Dict, Optional
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
            'True': True,
            'False': False,
            'Int': Int,
            'Bool': Bool,
            'Real': Real,
        }
        
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
        # 1. AST Check (Optional but recommended): Ensure no dangerous nodes
        # For now, we rely on restricted globals + __builtins__={} which is strong.
        # But we can also scan for double underscores to prevent attribute access attacks.
        if "__" in expression:
             raise ValueError(f"Unsafe expression detected (double underscore): {expression}")

        # 2. Merge context
        # We pass variables as locals
        eval_locals = context.copy()
        
        try:
            # 3. Execute with restricted scope
            return eval(expression, self.allowed_globals, eval_locals)
        except Exception as e:
            raise ValueError(f"Safe evaluation failed for '{expression}': {str(e)}")
