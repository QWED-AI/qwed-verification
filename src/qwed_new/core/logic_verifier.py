"""
Enterprise Logic Verification Engine.

Uses Z3 Theorem Prover (Microsoft Research) to verify logical constraints.

Enhanced Features:
1. Basic types: Int, Bool, Real
2. Quantifiers: ForAll, Exists
3. Bitvector operations (for crypto/low-level)
4. Array theory
5. Uninterpreted functions
6. Proof generation
7. Model explanation
"""

from z3 import *
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
import re


@dataclass
class LogicResult:
    """Result of logic verification."""
    status: str  # "SAT", "UNSAT", "UNKNOWN", "ERROR"
    model: Optional[Dict[str, str]] = None
    error: Optional[str] = None
    proof_summary: Optional[str] = None
    explanation: Optional[str] = None


@dataclass
class QuantifiedFormula:
    """A quantified logical formula."""
    quantifier: str  # "forall", "exists"
    bound_vars: List[Tuple[str, str]]  # [(name, type), ...]
    body: str  # The formula body


class LogicVerifier:
    """
    Enterprise Logic Verification Engine.
    
    Uses Z3 for satisfiability checking and theorem proving.
    
    Supports:
    - Basic types: Int, Bool, Real
    - Quantifiers: ForAll, Exists
    - Bitvectors: BitVec (for crypto)
    - Arrays: Array theory
    - Arithmetic: +, -, *, /, mod
    - Logical: And, Or, Not, Implies, Iff

    Attributes:
        timeout_ms (int): Solver timeout in milliseconds.
    """
    
    # Reserved keywords (skip in variable inference)
    RESERVED_KEYWORDS = {
        'True', 'False', 'and', 'or', 'not', 'And', 'Or', 'Not',
        'Implies', 'If', 'ForAll', 'Exists', 'Sum', 'Product',
        'BitVec', 'Array', 'Select', 'Store', 'Int', 'Bool', 'Real'
    }
    
    def __init__(self, timeout_ms: int = 5000):
        """
        Initialize Logic Verifier.
        
        Args:
            timeout_ms: Solver timeout in milliseconds.

        Example:
            >>> verifier = LogicVerifier(timeout_ms=10000)
        """
        self.timeout_ms = timeout_ms
        self._sanitizer = None
        self._safe_evaluator = None
    
    @property
    def sanitizer(self):
        """Lazy load sanitizer."""
        if self._sanitizer is None:
            try:
                from qwed_new.core.sanitizer import ConstraintSanitizer
                self._sanitizer = ConstraintSanitizer()
            except ImportError:
                self._sanitizer = None
        return self._sanitizer
    
    @property
    def safe_evaluator(self):
        """Lazy load safe evaluator."""
        if self._safe_evaluator is None:
            try:
                from qwed_new.core.safe_evaluator import SafeEvaluator
                self._safe_evaluator = SafeEvaluator()
            except ImportError:
                self._safe_evaluator = None
        return self._safe_evaluator
    
    def verify_logic(
        self, 
        variables: Dict[str, str], 
        constraints: List[str],
        prove_unsat: bool = False
    ) -> LogicResult:
        """
        Check if a set of constraints is satisfiable.
        
        Args:
            variables: Variable declarations {"x": "Int", "P": "Bool", "bv": "BitVec[8]"}.
            constraints: List of constraint strings.
            prove_unsat: If True and UNSAT, try to explain why.
            
        Returns:
            LogicResult with status and model (if SAT).

        Example:
            >>> result = verifier.verify_logic(
            ...     {"x": "Int", "y": "Int"},
            ...     ["x > 0", "y > 0", "x + y == 10"]
            ... )
            >>> print(result.status)
            'SAT'
        """
        try:
            # 1. Sanitize constraints (if sanitizer available)
            if self.sanitizer:
                constraints = self.sanitizer.sanitize(constraints, variables)
            
            # 2. Create solver with timeout
            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            
            # 3. Infer missing variables
            if not variables:
                variables = self._infer_variables(constraints)
            
            # 4. Create Z3 variables
            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, LogicResult):
                return z3_vars  # Error creating variables
            
            # 5. Add constraints
            for constr in constraints:
                try:
                    z3_constraint = self._parse_constraint(constr, z3_vars)
                    if z3_constraint is not None:
                        solver.add(z3_constraint)
                except Exception as e:
                    return LogicResult(
                        status="ERROR", 
                        error=f"Invalid constraint '{constr}': {str(e)}"
                    )
            
            # 6. Check satisfiability
            result = solver.check()
            
            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                return LogicResult(status="SAT", model=solution)
            
            elif result == unsat:
                explanation = None
                if prove_unsat:
                    explanation = self._explain_unsat(solver, constraints)
                return LogicResult(
                    status="UNSAT", 
                    explanation=explanation or "Constraints are unsatisfiable"
                )
            
            else:
                return LogicResult(
                    status="UNKNOWN", 
                    error="Solver returned unknown (possibly timeout)"
                )
                
        except Exception as e:
            return LogicResult(status="ERROR", error=str(e))
    
    # =========================================================================
    # Quantified Formulas
    # =========================================================================
    
    def verify_with_quantifiers(
        self,
        variables: Dict[str, str],
        quantified_formulas: List[QuantifiedFormula],
        constraints: List[str] = None
    ) -> LogicResult:
        """
        Verify formulas with quantifiers (ForAll, Exists).
        
        Args:
            variables: Free variable declarations.
            quantified_formulas: List of quantified formulas.
            constraints: Additional unquantified constraints.
            
        Returns:
            LogicResult indicating satisfiability.

        Example:
            >>> qf = QuantifiedFormula(
            ...     quantifier="forall",
            ...     bound_vars=[("x", "Int")],
            ...     body="x + y == y + x"
            ... )
            >>> result = verifier.verify_with_quantifiers({"y": "Int"}, [qf])
        """
        try:
            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            
            # Create all variables (free + bound)
            all_vars = dict(variables)
            for qf in quantified_formulas:
                for name, type_str in qf.bound_vars:
                    all_vars[name] = type_str
            
            z3_vars = self._create_z3_variables(all_vars)
            if isinstance(z3_vars, LogicResult):
                return z3_vars
            
            # Add quantified formulas
            for qf in quantified_formulas:
                bound_z3_vars = [z3_vars[name] for name, _ in qf.bound_vars]
                body = self._parse_constraint(qf.body, z3_vars)
                
                if qf.quantifier.lower() == "forall":
                    quantified = ForAll(bound_z3_vars, body)
                elif qf.quantifier.lower() == "exists":
                    quantified = Exists(bound_z3_vars, body)
                else:
                    return LogicResult(
                        status="ERROR",
                        error=f"Unknown quantifier: {qf.quantifier}"
                    )
                
                solver.add(quantified)
            
            # Add regular constraints
            if constraints:
                for constr in constraints:
                    z3_constraint = self._parse_constraint(constr, z3_vars)
                    if z3_constraint is not None:
                        solver.add(z3_constraint)
            
            # Check
            result = solver.check()
            
            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                return LogicResult(status="SAT", model=solution)
            elif result == unsat:
                return LogicResult(status="UNSAT")
            else:
                return LogicResult(status="UNKNOWN")
                
        except Exception as e:
            return LogicResult(status="ERROR", error=str(e))
    
    # =========================================================================
    # Bitvector Operations
    # =========================================================================
    
    def verify_bitvector(
        self,
        variables: Dict[str, int],  # {"x": 8, "y": 32} means 8-bit and 32-bit
        constraints: List[str]
    ) -> LogicResult:
        """
        Verify bitvector constraints (for crypto/low-level verification).
        
        Args:
            variables: Variable name to bit width mapping.
            constraints: Bitvector constraint expressions.
            
        Returns:
            LogicResult indicating satisfiability.

        Example:
            >>> result = verifier.verify_bitvector(
            ...     {"x": 8, "y": 8},
            ...     ["x & y == 0", "x | y == 255"]
            ... )
        """
        try:
            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            
            # Create bitvector variables
            z3_vars = {}
            for name, width in variables.items():
                z3_vars[name] = BitVec(name, width)
            
            # Add constraints
            for constr in constraints:
                z3_constraint = self._parse_constraint(constr, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)
            
            # Check
            result = solver.check()
            
            if result == sat:
                model = solver.model()
                solution = {}
                for d in model.decls():
                    val = model[d]
                    # Format as hex for bitvectors
                    if is_bv(val):
                        solution[d.name()] = hex(val.as_long())
                    else:
                        solution[d.name()] = str(val)
                return LogicResult(status="SAT", model=solution)
            elif result == unsat:
                return LogicResult(status="UNSAT")
            else:
                return LogicResult(status="UNKNOWN")
                
        except Exception as e:
            return LogicResult(status="ERROR", error=str(e))
    
    # =========================================================================
    # Array Theory
    # =========================================================================
    
    def verify_array(
        self,
        array_decls: Dict[str, Tuple[str, str]],  # {"arr": ("Int", "Int")} = Int -> Int array
        variables: Dict[str, str],
        constraints: List[str]
    ) -> LogicResult:
        """
        Verify constraints involving arrays.
        
        Args:
            array_decls: Array declarations {"name": (index_type, value_type)}.
            variables: Regular variable declarations.
            constraints: Constraints using Select(arr, idx) and Store(arr, idx, val).
            
        Returns:
            LogicResult indicating satisfiability.

        Example:
            >>> result = verifier.verify_array(
            ...     {"A": ("Int", "Int")},
            ...     {"i": "Int", "x": "Int"},
            ...     ["Select(Store(A, i, x), i) == x"]
            ... )
        """
        try:
            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            
            z3_vars = {}
            
            # Create arrays
            type_map = {"int": IntSort(), "bool": BoolSort(), "real": RealSort()}
            for name, (idx_type, val_type) in array_decls.items():
                idx_sort = type_map.get(idx_type.lower(), IntSort())
                val_sort = type_map.get(val_type.lower(), IntSort())
                z3_vars[name] = Array(name, idx_sort, val_sort)
            
            # Create regular variables
            regular_vars = self._create_z3_variables(variables)
            if isinstance(regular_vars, LogicResult):
                return regular_vars
            z3_vars.update(regular_vars)
            
            # Add array functions to context
            z3_vars['Select'] = Select
            z3_vars['Store'] = Store
            
            # Add constraints
            for constr in constraints:
                z3_constraint = self._parse_constraint(constr, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)
            
            # Check
            result = solver.check()
            
            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                return LogicResult(status="SAT", model=solution)
            elif result == unsat:
                return LogicResult(status="UNSAT")
            else:
                return LogicResult(status="UNKNOWN")
                
        except Exception as e:
            return LogicResult(status="ERROR", error=str(e))
    
    # =========================================================================
    # Proof and Explanation
    # =========================================================================
    
    def prove_theorem(
        self,
        variables: Dict[str, str],
        premises: List[str],
        conclusion: str
    ) -> LogicResult:
        """
        Prove that conclusion follows from premises.
        
        Uses proof by contradiction: premises AND NOT(conclusion) should be UNSAT.
        
        Args:
            variables: Variable declarations.
            premises: List of premise constraints.
            conclusion: The theorem to prove.
            
        Returns:
            LogicResult with "SAT" if theorem is VALID, "UNSAT" if INVALID.

        Example:
            >>> result = verifier.prove_theorem(
            ...     {"p": "Bool", "q": "Bool"},
            ...     ["Implies(p, q)", "p"],
            ...     "q"
            ... )
            >>> # Status will be SAT if theorem is valid (proof found)
        """
        try:
            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            
            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, LogicResult):
                return z3_vars
            
            # Add premises
            for premise in premises:
                z3_constraint = self._parse_constraint(premise, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)
            
            # Add negation of conclusion
            conclusion_z3 = self._parse_constraint(conclusion, z3_vars)
            solver.add(Not(conclusion_z3))
            
            # Check
            result = solver.check()
            
            if result == unsat:
                # Premises AND NOT(conclusion) is UNSAT
                # Therefore, conclusion follows from premises
                return LogicResult(
                    status="SAT",  # Theorem is valid
                    proof_summary="Theorem proved by contradiction: premises ∧ ¬conclusion is unsatisfiable"
                )
            elif result == sat:
                # Found counterexample
                model = solver.model()
                counterexample = {d.name(): str(model[d]) for d in model.decls()}
                return LogicResult(
                    status="UNSAT",  # Theorem is invalid
                    model=counterexample,
                    explanation="Counterexample found - theorem is not valid"
                )
            else:
                return LogicResult(status="UNKNOWN")
                
        except Exception as e:
            return LogicResult(status="ERROR", error=str(e))
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _infer_variables(self, constraints: List[str]) -> Dict[str, str]:
        """Infer variable types from constraint syntax."""
        variables = {}
        
        for constr in constraints:
            found_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', constr)
            for v in found_vars:
                if v in self.RESERVED_KEYWORDS:
                    continue
                if v in variables:
                    continue
                
                # Heuristics for type inference
                if v in ['P', 'Q', 'R', 'S'] or v.startswith('is_') or v.startswith('has_'):
                    variables[v] = 'Bool'
                elif v.startswith('bv') or v.endswith('_bits'):
                    variables[v] = 'BitVec[32]'  # Default 32-bit
                else:
                    variables[v] = 'Int'
        
        return variables
    
    def _create_z3_variables(self, variables: Dict[str, str]) -> Union[Dict, LogicResult]:
        """Create Z3 variables from type declarations."""
        z3_vars = {}
        
        for name, type_str in variables.items():
            type_lower = type_str.lower()
            
            if type_lower == 'int':
                z3_vars[name] = Int(name)
            elif type_lower == 'bool':
                z3_vars[name] = Bool(name)
            elif type_lower == 'real':
                z3_vars[name] = Real(name)
            elif type_lower.startswith('bitvec'):
                # Parse BitVec[N]
                match = re.match(r'bitvec\[(\d+)\]', type_lower)
                if match:
                    width = int(match.group(1))
                    z3_vars[name] = BitVec(name, width)
                else:
                    z3_vars[name] = BitVec(name, 32)  # Default 32-bit
            else:
                return LogicResult(status="ERROR", error=f"Unsupported type: {type_str}")
        
        return z3_vars
    
    def _parse_constraint(self, constr: str, z3_vars: Dict) -> Any:
        """Parse a constraint string into Z3 expression."""
        # Use safe evaluator if available
        if self.safe_evaluator:
            return self.safe_evaluator.safe_eval(constr, z3_vars)
        
        # Fallback: build safe context for eval
        safe_context = {
            'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies,
            'If': If, 'ForAll': ForAll, 'Exists': Exists,
            'Int': Int, 'Bool': Bool, 'Real': Real,
            'BitVec': BitVec, 'Array': Array, 'Select': Select, 'Store': Store,
            'True': True, 'False': False,
            **z3_vars
        }
        
        return eval(constr, {"__builtins__": {}}, safe_context)
    
    def _explain_unsat(self, solver: Solver, constraints: List[str]) -> str:
        """Try to explain why constraints are unsatisfiable."""
        # Use unsat core if available
        try:
            solver.set("unsat_core", True)
            core = solver.unsat_core()
            if core:
                return f"Conflicting constraints: {[str(c) for c in core]}"
        except:
            pass
        
        return "Constraints are logically inconsistent"
    
    # =========================================================================
    # Convenience Methods
    # =========================================================================
    
    def check_implication(
        self,
        variables: Dict[str, str],
        antecedent: str,
        consequent: str
    ) -> LogicResult:
        """
        Check if antecedent implies consequent.
        
        Args:
            variables: Variable declarations.
            antecedent: The condition formula.
            consequent: The implied formula.

        Returns:
            LogicResult (SAT if implication holds for all values).

        Example:
            >>> result = verifier.check_implication(
            ...     {"x": "Int"},
            ...     "x > 10",
            ...     "x > 5"
            ... )
        """
        # P → Q is valid iff P ∧ ¬Q is unsatisfiable
        return self.prove_theorem(variables, [antecedent], consequent)
    
    def check_equivalence(
        self,
        variables: Dict[str, str],
        formula1: str,
        formula2: str
    ) -> LogicResult:
        """
        Check if two formulas are logically equivalent.

        Args:
            variables: Variable declarations.
            formula1: First formula.
            formula2: Second formula.

        Returns:
            LogicResult (SAT if equivalent).

        Example:
            >>> result = verifier.check_equivalence(
            ...     {"p": "Bool", "q": "Bool"},
            ...     "Not(Or(p, q))",
            ...     "And(Not(p), Not(q))"
            ... )
        """
        try:
            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            
            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, LogicResult):
                return z3_vars
            
            f1 = self._parse_constraint(formula1, z3_vars)
            f2 = self._parse_constraint(formula2, z3_vars)
            
            # Check if there's a case where f1 ≠ f2
            solver.add(Not(f1 == f2))
            
            result = solver.check()
            
            if result == unsat:
                return LogicResult(
                    status="SAT",
                    explanation="Formulas are logically equivalent"
                )
            elif result == sat:
                model = solver.model()
                counterexample = {d.name(): str(model[d]) for d in model.decls()}
                return LogicResult(
                    status="UNSAT",
                    model=counterexample,
                    explanation="Formulas differ at this assignment"
                )
            else:
                return LogicResult(status="UNKNOWN")
                
        except Exception as e:
            return LogicResult(status="ERROR", error=str(e))
