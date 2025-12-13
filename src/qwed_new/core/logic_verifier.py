"""
Logic Verification Engine: The "Reasoning" Core.

This module uses the Z3 Theorem Prover (by Microsoft Research) to verify
logical constraints and solve satisfaction problems.

It takes structured constraints (from the LLM) and proves if they are possible.
"""


from z3 import *
from typing import Dict, List, Optional
from qwed_new.core.schemas import LogicResult
from qwed_new.core.sanitizer import ConstraintSanitizer
from qwed_new.core.safe_evaluator import SafeEvaluator

class LogicVerifier:
    """
    Verifies logic and constraint satisfaction problems using Z3.
    """
    def __init__(self):
        self.sanitizer = ConstraintSanitizer()
        self.safe_evaluator = SafeEvaluator()
    
    def verify_logic(self, variables: Dict[str, str], constraints: List[str]) -> LogicResult:
        """
        Check if a set of constraints is satisfiable.
        """
        try:
            # 1. Sanitize Constraints
            constraints = self.sanitizer.sanitize(constraints, variables)
            
            # 2. Create Z3 Solver with Timeout
            solver = Solver()
            solver.set("timeout", 5000) # 5 seconds timeout
            
            # 3. Define Variables dynamically
            z3_vars = {}
            
            # Fallback: If variables are missing, infer them from constraints (assume Int)
            if not variables:
                import re
                # Simple regex to find variable-like names (alpha chars)
                # This is a heuristic for the fallback case
                for constr in constraints:
                    found_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', constr)
                    for v in found_vars:
                        if v not in ['True', 'False', 'and', 'or', 'not', 'And', 'Or', 'Not', 'Implies', 'If']: # Skip keywords
                            # Heuristic: P, Q, R or is_... are likely Bool
                            if v in ['P', 'Q', 'R'] or v.startswith('is_'):
                                variables[v] = 'Bool'
                            else:
                                variables[v] = 'Int' # Default to Int
            
            for name, type_str in variables.items():
                if type_str.lower() == 'int':
                    z3_vars[name] = Int(name)
                elif type_str.lower() == 'bool':
                    z3_vars[name] = Bool(name)
                elif type_str.lower() == 'real':
                    z3_vars[name] = Real(name)
                else:
                    return LogicResult(status="ERROR", error=f"Unsupported type: {type_str}")
            
            # 4. Add Constraints safely
            for constr in constraints:
                try:
                    # Use SafeEvaluator instead of raw eval()
                    z3_constraint = self.safe_evaluator.safe_eval(constr, z3_vars)
                    solver.add(z3_constraint)
                except Exception as e:
                    return LogicResult(status="ERROR", error=f"Invalid constraint '{constr}': {str(e)}")
            
            # 5. Check Satisfiability
            result = solver.check()
            
            if result == sat:
                model = solver.model()
                # Convert model to simple dict
                solution = {d.name(): str(model[d]) for d in model.decls()}
                return LogicResult(status="SAT", model=solution)
            elif result == unsat:
                return LogicResult(status="UNSAT")
            else:
                return LogicResult(status="UNKNOWN", error="Solver returned unknown (possibly timeout)")
                
        except Exception as e:
            return LogicResult(status="ERROR", error=str(e))
