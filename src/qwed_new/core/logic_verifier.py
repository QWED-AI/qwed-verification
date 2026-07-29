# Copyright (c) 2024-2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

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
from dataclasses import dataclass
import re
import logging

from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus, compute_proof_ref

logger = logging.getLogger(__name__)


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

    # ------------------------------------------------------------------
    # Helpers: symbol_table, proof_ref, developer_fields
    # ------------------------------------------------------------------

    @staticmethod
    def _build_symbol_table(variables: Dict[str, str]) -> List[Dict[str, str]]:
        """Build a symbol table listing every declared variable and its type."""
        return [{"name": name, "type": type_str} for name, type_str in sorted(variables.items())]

    @staticmethod
    def _build_proof_ref(solver: Solver) -> Optional[str]:
        """Compute proof_ref from Z3 solver assertion stack."""
        assertions = [str(a) for a in solver.assertions()]
        if not assertions:
            return None
        return compute_proof_ref(str(assertions))

    def _base_developer_fields(self, variables: Dict[str, str]) -> Dict[str, Any]:
        return {
            "symbol_table": self._build_symbol_table(variables),
        }

    # =========================================================================
    # Main Verification
    # =========================================================================

    def verify_logic(
        self,
        variables: Dict[str, str],
        constraints: List[str],
        prove_unsat: bool = False
    ) -> DiagnosticResult:
        """
        Check if a set of constraints is satisfiable.

        Args:
            variables: Variable declarations {"x": "Int", "P": "Bool", "bv": "BitVec[8]"}.
            constraints: List of constraint strings.
            prove_unsat: If True and UNSAT, try to explain why.

        Returns:
            DiagnosticResult — VERIFIED with model if SAT, UNVERIFIABLE if UNSAT, BLOCKED on error.

        Example:
            >>> result = verifier.verify_logic(
            ...     {"x": "Int", "y": "Int"},
            ...     ["x > 0", "y > 0", "x + y == 10"]
            ... )
            >>> result.is_verified
            True
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            if self.sanitizer:
                constraints = self.sanitizer.sanitize(constraints, variables)

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            for constr in constraints:
                try:
                    z3_constraint = self._parse_constraint(constr, z3_vars)
                    if z3_constraint is not None:
                        solver.add(z3_constraint)
                except Exception as e:
                    return DiagnosticResult.blocked(
                        "Logic verification blocked: invalid constraint",
                        {
                            "constraint_id": "logic_verifier.invalid_constraint",
                            "error_type": type(e).__name__,
                            "constraint": constr,
                        },
                    )

            result = solver.check()

            fields = self._base_developer_fields(variables)
            fields["constraints"] = constraints

            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = solution
                fields["deterministic_verdict"] = "SAT"
                proof_ref = self._build_proof_ref(solver)
                return DiagnosticResult.verified(
                    "Logic constraints are satisfiable — model found",
                    fields,
                    {"model": solution, "constraints": constraints},
                    proof_data=proof_ref,
                )

            elif result == unsat:
                fields["deterministic_verdict"] = "UNSAT"
                explanation = None
                if prove_unsat:
                    explanation = self._explain_unsat(solver, constraints)
                fields["explanation"] = explanation or "Constraints are unsatisfiable"
                return DiagnosticResult.unverifiable(
                    "Logic constraints are unsatisfiable — no model exists",
                    fields,
                )

            else:
                fields["deterministic_verdict"] = "UNKNOWN"
                return DiagnosticResult.unverifiable(
                    "Logic verification did not converge — possible timeout",
                    fields,
                )

        except Exception as exc:
            logger.exception("Logic verification pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Quantified Formulas
    # =========================================================================

    def verify_with_quantifiers(
        self,
        variables: Dict[str, str],
        quantified_formulas: List[QuantifiedFormula],
        constraints: List[str] = None
    ) -> DiagnosticResult:
        """
        Verify formulas with quantifiers (ForAll, Exists).

        Returns:
            DiagnosticResult — VERIFIED if SAT, UNVERIFIABLE if UNSAT/UNKNOWN, BLOCKED on error.
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            all_vars = dict(variables)
            for qf in quantified_formulas:
                for name, type_str in qf.bound_vars:
                    all_vars[name] = type_str

            z3_vars = self._create_z3_variables(all_vars)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            for qf in quantified_formulas:
                bound_z3_vars = [z3_vars[name] for name, _ in qf.bound_vars]
                body = self._parse_constraint(qf.body, z3_vars)

                if qf.quantifier.lower() == "forall":
                    quantified = ForAll(bound_z3_vars, body)
                elif qf.quantifier.lower() == "exists":
                    quantified = Exists(bound_z3_vars, body)
                else:
                    return DiagnosticResult.blocked(
                        "Logic verification blocked: unknown quantifier",
                        {"constraint_id": "logic_verifier.unknown_quantifier", "quantifier": qf.quantifier},
                    )

                solver.add(quantified)

            if constraints:
                for constr in constraints:
                    z3_constraint = self._parse_constraint(constr, z3_vars)
                    if z3_constraint is not None:
                        solver.add(z3_constraint)

            result = solver.check()

            fields = self._base_developer_fields(variables)
            fields["deterministic_verdict"] = str(result)

            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = solution
                proof_ref = self._build_proof_ref(solver)
                return DiagnosticResult.verified(
                    "Quantified constraints are satisfiable — model found",
                    fields,
                    {"model": solution},
                    proof_data=proof_ref,
                )
            elif result == unsat:
                return DiagnosticResult.unverifiable(
                    "Quantified constraints are unsatisfiable — no model exists",
                    fields,
                )
            else:
                return DiagnosticResult.unverifiable(
                    "Quantified constraint verification did not converge",
                    fields,
                )

        except Exception as exc:
            logger.exception("Quantified verification pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Bitvector Operations
    # =========================================================================

    def verify_bitvector(
        self,
        variables: Dict[str, int],
        constraints: List[str]
    ) -> DiagnosticResult:
        """
        Verify bitvector constraints (for crypto/low-level verification).

        Returns:
            DiagnosticResult — VERIFIED if SAT, UNVERIFIABLE if UNSAT/UNKNOWN, BLOCKED on error.
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = {}
            for name, width in variables.items():
                z3_vars[name] = BitVec(name, width)

            for constr in constraints:
                z3_constraint = self._parse_constraint(constr, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)

            result = solver.check()

            fields = self._base_developer_fields(
                {name: f"BitVec[{w}]" for name, w in variables.items()}
            )
            fields["deterministic_verdict"] = str(result)

            if result == sat:
                model = solver.model()
                solution = {}
                for d in model.decls():
                    val = model[d]
                    solution[d.name()] = hex(val.as_long()) if is_bv(val) else str(val)
                fields["model"] = solution
                proof_ref = self._build_proof_ref(solver)
                return DiagnosticResult.verified(
                    "Bitvector constraints are satisfiable — model found",
                    fields,
                    {"model": solution},
                    proof_data=proof_ref,
                )
            elif result == unsat:
                return DiagnosticResult.unverifiable(
                    "Bitvector constraints are unsatisfiable",
                    fields,
                )
            else:
                return DiagnosticResult.unverifiable(
                    "Bitvector constraint verification did not converge",
                    fields,
                )

        except Exception as exc:
            logger.exception("Bitvector verification pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Array Theory
    # =========================================================================

    def verify_array(
        self,
        array_decls: Dict[str, Tuple[str, str]],
        variables: Dict[str, str],
        constraints: List[str]
    ) -> DiagnosticResult:
        """
        Verify constraints involving arrays.

        Returns:
            DiagnosticResult — VERIFIED if SAT, UNVERIFIABLE if UNSAT/UNKNOWN, BLOCKED on error.
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = {}
            type_map = {"int": IntSort(), "bool": BoolSort(), "real": RealSort()}
            for name, (idx_type, val_type) in array_decls.items():
                idx_sort = type_map.get(idx_type.lower(), IntSort())
                val_sort = type_map.get(val_type.lower(), IntSort())
                z3_vars[name] = Array(name, idx_sort, val_sort)

            regular_vars = self._create_z3_variables(variables)
            if isinstance(regular_vars, DiagnosticResult):
                return regular_vars
            z3_vars.update(regular_vars)

            z3_vars['Select'] = Select
            z3_vars['Store'] = Store

            for constr in constraints:
                z3_constraint = self._parse_constraint(constr, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)

            result = solver.check()

            fields = self._base_developer_fields(variables)
            fields["deterministic_verdict"] = str(result)

            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = solution
                proof_ref = self._build_proof_ref(solver)
                return DiagnosticResult.verified(
                    "Array constraints are satisfiable — model found",
                    fields,
                    {"model": solution},
                    proof_data=proof_ref,
                )
            elif result == unsat:
                return DiagnosticResult.unverifiable(
                    "Array constraints are unsatisfiable",
                    fields,
                )
            else:
                return DiagnosticResult.unverifiable(
                    "Array constraint verification did not converge",
                    fields,
                )

        except Exception as exc:
            logger.exception("Array verification pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Proof and Explanation
    # =========================================================================

    def prove_theorem(
        self,
        variables: Dict[str, str],
        premises: List[str],
        conclusion: str
    ) -> DiagnosticResult:
        """
        Prove that conclusion follows from premises.

        Uses proof by contradiction: premises AND NOT(conclusion) should be UNSAT.

        Returns:
            DiagnosticResult — VERIFIED (theorem proved) if contradiction found,
            BLOCKED (counterexample) if conclusion does not follow,
            UNVERIFIABLE if unknown.
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            for premise in premises:
                z3_constraint = self._parse_constraint(premise, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)

            conclusion_z3 = self._parse_constraint(conclusion, z3_vars)
            solver.add(Not(conclusion_z3))

            result = solver.check()

            fields = self._base_developer_fields(variables)
            fields["premises"] = premises
            fields["conclusion"] = conclusion

            if result == unsat:
                fields["deterministic_verdict"] = "contradiction_confirmed"
                proof_ref = self._build_proof_ref(solver)
                return DiagnosticResult.verified(
                    "Theorem proved by contradiction",
                    fields,
                    {"premises": premises, "conclusion": conclusion},
                    proof_data=proof_ref,
                )
            elif result == sat:
                model = solver.model()
                counterexample = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = counterexample
                fields["deterministic_verdict"] = "counterexample_found"
                return DiagnosticResult.blocked(
                    "Theorem disproved — counterexample found",
                    fields,
                )
            else:
                fields["deterministic_verdict"] = "UNKNOWN"
                return DiagnosticResult.unverifiable(
                    "Theorem proof did not converge",
                    fields,
                )

        except Exception as exc:
            logger.exception("Theorem proving pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _create_z3_variables(self, variables: Dict[str, str]) -> Union[Dict, DiagnosticResult]:
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
                match = re.match(r'bitvec\[(\d+)\]', type_lower)
                if match:
                    width = int(match.group(1))
                    z3_vars[name] = BitVec(name, width)
                else:
                    return DiagnosticResult.blocked(
                        "Logic verification blocked: malformed BitVec type declaration",
                        {
                            "constraint_id": "dsl_compiler.type_validation",
                            "variable": name,
                            "declared_type": type_str,
                            "error": f"Expected BitVec[N] where N is a positive integer, got '{type_str}'",
                        },
                    )
            else:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: unsupported type declaration",
                    {
                        "constraint_id": "dsl_compiler.type_validation",
                        "variable": name,
                        "declared_type": type_str,
                    },
                )

        return z3_vars

    def _parse_constraint(self, constr: str, z3_vars: Dict) -> Any:
        """Parse a constraint string into Z3 expression."""
        if self.safe_evaluator:
            return self.safe_evaluator.safe_eval(constr, z3_vars)

        raise RuntimeError("SafeEvaluator is required for constraint parsing")

    def _explain_unsat(self, solver: Solver, constraints: List[str]) -> str:
        """Try to explain why constraints are unsatisfiable."""
        try:
            solver.set("unsat_core", True)
            core = solver.unsat_core()
            if core:
                return f"Conflicting constraints: {[str(c) for c in core]}"
        except Exception:
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
    ) -> DiagnosticResult:
        """
        Check if antecedent implies consequent.

        Returns:
            DiagnosticResult — VERIFIED if implication holds, BLOCKED if counterexample found.
        """
        return self.prove_theorem(variables, [antecedent], consequent)

    def check_equivalence(
        self,
        variables: Dict[str, str],
        formula1: str,
        formula2: str
    ) -> DiagnosticResult:
        """
        Check if two formulas are logically equivalent.

        Returns:
            DiagnosticResult — VERIFIED if equivalent, BLOCKED if differ, UNVERIFIABLE if unknown.
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            f1 = self._parse_constraint(formula1, z3_vars)
            f2 = self._parse_constraint(formula2, z3_vars)

            solver.add(Not(f1 == f2))

            result = solver.check()

            fields = self._base_developer_fields(variables)

            if result == unsat:
                fields["deterministic_verdict"] = "equivalent"
                proof_ref = self._build_proof_ref(solver)
                return DiagnosticResult.verified(
                    "Formulas are logically equivalent",
                    fields,
                    {"formula1": formula1, "formula2": formula2},
                    proof_data=proof_ref,
                )
            elif result == sat:
                model = solver.model()
                counterexample = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = counterexample
                fields["deterministic_verdict"] = "not_equivalent"
                return DiagnosticResult.blocked(
                    "Formulas are not equivalent — counterexample found",
                    fields,
                )
            else:
                fields["deterministic_verdict"] = "UNKNOWN"
                return DiagnosticResult.unverifiable(
                    "Equivalence check did not converge",
                    fields,
                )

        except Exception as exc:
            logger.exception("Equivalence check pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Advanced: Optimization & Vacuity
    # =========================================================================

    def verify_optimization(
        self,
        variables: Dict[str, str],
        constraints: List[str],
        objective: str,
        maximize: bool = True
    ) -> DiagnosticResult:
        """
        Optimize an objective function subject to constraints.

        Returns:
            DiagnosticResult — VERIFIED with optimal model if SAT, UNVERIFIABLE if UNSAT/UNKNOWN.
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            opt = Optimize()
            opt.set("timeout", self.timeout_ms)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            for constr in constraints:
                z3_constraint = self._parse_constraint(constr, z3_vars)
                if z3_constraint is not None:
                    opt.add(z3_constraint)

            obj_expr = self._parse_constraint(objective, z3_vars)
            if maximize:
                opt.maximize(obj_expr)
            else:
                opt.minimize(obj_expr)

            result = opt.check()

            fields = self._base_developer_fields(variables)
            fields["objective"] = objective
            fields["maximize"] = maximize

            if result == sat:
                model = opt.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = solution
                fields["deterministic_verdict"] = "OPTIMAL"
                proof_ref = self._build_proof_ref(opt)
                return DiagnosticResult.verified(
                    "Optimal solution found",
                    fields,
                    {"model": solution, "objective": objective},
                    proof_data=proof_ref,
                )
            elif result == unsat:
                fields["deterministic_verdict"] = "UNSAT"
                return DiagnosticResult.unverifiable(
                    "Constraints cannot be satisfied — no feasible solution",
                    fields,
                )
            else:
                fields["deterministic_verdict"] = "UNKNOWN"
                return DiagnosticResult.unverifiable(
                    "Optimization did not converge",
                    fields,
                )

        except Exception as exc:
            logger.exception("Optimization pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )

    def check_vacuity(
        self,
        variables: Dict[str, str],
        antecedent: str,
        consequent: str
    ) -> DiagnosticResult:
        """
        Check for vacuous truth (e.g., "If False then Anything").

        Returns:
            DiagnosticResult — UNVERIFIABLE if vacuous, VERIFIED if non-vacuous.
        """
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable declarations are required",
                    {"constraint_id": "logic_verifier.explicit_declarations_required"},
                )

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            ant_expr = self._parse_constraint(antecedent, z3_vars)
            solver.add(ant_expr)

            result = solver.check()

            fields = self._base_developer_fields(variables)
            fields["antecedent"] = antecedent
            fields["deterministic_verdict"] = str(result)

            if result == unsat:
                return DiagnosticResult.unverifiable(
                    "Rule is vacuously true — antecedent can never be satisfied",
                    fields,
                )

            proof_ref = self._build_proof_ref(solver)
            return DiagnosticResult.verified(
                "Rule is non-vacuous — antecedent is satisfiable",
                fields,
                {"antecedent": antecedent},
                proof_data=proof_ref,
            )

        except Exception as exc:
            logger.exception("Vacuity check pipeline failed")
            return DiagnosticResult.blocked(
                "Logic verification blocked: pipeline error",
                {"constraint_id": "logic_verifier.execution_error", "error_type": type(exc).__name__},
            )
