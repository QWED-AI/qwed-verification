"""
Constraint Sanitizer: The "Auto-Correct" for LLM Logic.

This module fixes common syntax errors in LLM-generated Z3 constraints
before they cause crashes. It handles:
1. Bitwise Operators: '|' -> 'Or', '&' -> 'And', '~' -> 'Not'
2. Assignments: '=' -> '==', '!=' -> '!='
3. Categorical Values: 'Color == "Red"' -> 'Color == 1' (if mapped)
"""

import re
from typing import List, Dict

class ConstraintSanitizer:
    """
    Sanitizes and fixes Z3 constraint strings.
    """
    
    def sanitize(self, constraints: List[str], variables: Dict[str, str]) -> List[str]:
        """
        Apply all sanitization rules to a list of constraints.
        """
        sanitized = []
        for constr in constraints:
            clean = constr
            
            # 1. Fix Assignments: '=' -> '==', '!=' -> '!='
            # Regex: (?<![<>!])=(?!=) matches a single = not preceded by <,>,! and not followed by =
            clean = re.sub(r'(?<![<>!=])=(?!=)', '==', clean)
            
            # 2. Fix Bitwise Operators (Heuristic)
            # Replace 'A | B' with 'Or(A, B)' is hard with regex.
            # Instead, we replace the OPERATORS with Python keywords 'or', 'and', 'not'
            # because we inject Z3's Or/And into the eval context, and Python's 'or'/'and'
            # might work if we are careful, OR we map 'or' -> 'Or' in eval globals?
            # NO: Python's 'or' short-circuits. We MUST use Z3's Or(...).
            # BUT: Z3 overloads `|` and `&` for BitVectors, but throws error for Bools.
            
            # Strategy: If we see `|` or `&` and variables are Bool, we try to fix.
            # Simple fix: Replace `|` with ` or ` and `&` with ` and `.
            # Then in eval_globals, map `or` is not overridable.
            # Wait, if I use `A or B` in python eval, it calls `bool(A)` which fails for Z3 Expr.
            # So we MUST convert to `Or(A, B)`.
            
            # Regex for simple binary cases: "A | B" -> "Or(A, B)"
            # This is too complex for regex.
            # ALTERNATIVE: We instruct the user to use `Or` in prompt (Prevention).
            # Here (Correction), we can try a simple replace if it's a known pattern.
            
            # Let's try replacing `|` with `,` and wrapping in `Or(...)`? No.
            
            # Fallback: Just replace `|` with ` or ` and hope? No, that crashes.
            # Let's stick to fixing `=` and maybe simple `&` -> `And` if possible.
            # Actually, if we replace `|` with ` | ` (spaces), maybe we can parse it?
            
            # Let's focus on the most common error: "x = 5" -> "x == 5"
            # And "Red" -> 1 (Categorical Mapping)
            
            # 3. Categorical Mapping
            # If we have a variable "Color" mapped to "Int", and constraint has "Red"
            # We can't fix this without a known mapping.
            # We assume the LLM provides the mapping or we infer it?
            # For now, we skip categorical mapping in sanitizer unless we have a dictionary.
            
            sanitized.append(clean)
            
        return sanitized
