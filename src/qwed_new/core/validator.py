"""
Semantic Validation Layer: Pre-validates LLM outputs before symbolic verification.

This layer catches garbage outputs (like "banana * unicorn") BEFORE they reach SymPy.
It's the second line of defense after structured extraction.

Validation Checks:
1. Syntax: Can SymPy parse the expression?
2. Symbols: Only mathematical symbols allowed (no random variables)
3. Evaluable: Can we calculate a numerical result?
"""

from sympy import sympify, Symbol
from sympy.parsing.sympy_parser import parse_expr
from typing import Dict, List


class SemanticValidator:
    """
    Validates that an expression is mathematically sound before verification.
    
    This prevents the verification engine from crashing on invalid inputs.
    """
    
    # Allowed mathematical symbols and functions
    ALLOWED_SYMBOLS = {
        'pi', 'e',  # Constants
        'sin', 'cos', 'tan', 'cot', 'sec', 'csc',  # Trig functions
        'asin', 'acos', 'atan',  # Inverse trig
        'sinh', 'cosh', 'tanh',  # Hyperbolic
        'log', 'ln', 'exp',  # Logarithmic/exponential
        'sqrt', 'cbrt',  # Roots
        'abs', 'factorial',  # Other functions
    }
    
    def validate(self, expression: str) -> Dict[str, any]:
        """
        Validate an expression against all checks.
        
        Args:
            expression: The mathematical expression to validate
        
        Returns:
            Dict with:
                - is_valid: bool (True if all checks pass)
                - checks_passed: List of check names that passed
                - checks_failed: List of check names that failed
                - error: Optional error message
        
        Example:
            validator = SemanticValidator()
            result = validator.validate("2 + 2")
            # Returns: {
            #     "is_valid": True,
            #     "checks_passed": ["syntax", "symbols", "evaluable"],
            #     "checks_failed": []
            # }
        """
        checks_passed = []
        checks_failed = []
        error = None
        
        # Check 1: Syntax validation
        try:
            expr = parse_expr(expression)
            checks_passed.append("syntax")
        except Exception as e:
            checks_failed.append("syntax")
            error = f"Syntax error: {str(e)}"
            return {
                "is_valid": False,
                "checks_passed": checks_passed,
                "checks_failed": checks_failed,
                "error": error
            }
        
        # Check 2: Symbol validation (no undefined variables)
        try:
            # Get all free symbols (variables) in the expression
            free_symbols = {str(s) for s in expr.free_symbols}
            
            # Check if any symbols are not in our allowed list
            invalid_symbols = free_symbols - self.ALLOWED_SYMBOLS
            
            if invalid_symbols:
                checks_failed.append("symbols")
                error = f"Invalid symbols found: {invalid_symbols}. Only mathematical constants and functions are allowed."
                return {
                    "is_valid": False,
                    "checks_passed": checks_passed,
                    "checks_failed": checks_failed,
                    "error": error
                }
            
            checks_passed.append("symbols")
        except Exception as e:
            checks_failed.append("symbols")
            error = f"Symbol validation error: {str(e)}"
            return {
                "is_valid": False,
                "checks_passed": checks_passed,
                "checks_failed": checks_failed,
                "error": error
            }
        
        # Check 3: Evaluability (can we get a numerical result?)
        try:
            # Try to evaluate the expression to a float
            result = float(expr.evalf())
            
            # Check for NaN or Infinity
            if not (-1e308 < result < 1e308):  # Rough bounds for valid floats
                checks_failed.append("evaluable")
                error = "Expression evaluates to infinity or invalid number"
                return {
                    "is_valid": False,
                    "checks_passed": checks_passed,
                    "checks_failed": checks_failed,
                    "error": error
                }
            
            checks_passed.append("evaluable")
        except Exception as e:
            checks_failed.append("evaluable")
            error = f"Cannot evaluate expression: {str(e)}"
            return {
                "is_valid": False,
                "checks_passed": checks_passed,
                "checks_failed": checks_failed,
                "error": error
            }
        
        # All checks passed!
        return {
            "is_valid": True,
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "error": None
        }
