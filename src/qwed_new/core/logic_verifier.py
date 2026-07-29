# Copyright (c) 2024-2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""
Enterprise Logic Verification Engine.

Uses Z3 Theorem Prover (Microsoft Research) to verify logical constraints.
"""

from z3 import *
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import re
import logging

from qwed_new.core.diagnostics import DiagnosticResult

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Constants (avoid SonarQube duplication warnings)
# ------------------------------------------------------------------
_EXPLICIT_DECLARATIONS_REQUIRED_MSG = (
    "Logic verification blocked: explicit variable declarations are required"
)
_PIPELINE_ERROR_MSG = "Logic verification blocked: pipeline error"

_CONSTRAINT_ID_EXPLICIT_DECLARATIONS = "logic_verifier.explicit_declarations_required"
_CONSTRAINT_ID_EXECUTION_ERROR = "logic_verifier.execution_error"
_CONSTRAINT_ID_INVALID_CONSTRAINT = "logic_verifier.invalid_constraint"
_CONSTRAINT_ID_TYPE_VALIDATION = "dsl_compiler.type_validation"


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
    """

    def __init__(self, timeout_ms: int = 5000):
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
    # Helpers: sanitizer, symbol_table, proof_ref, developer_fields
    # ------------------------------------------------------------------

    def _ensure_sanitizer(self) -> Optional[DiagnosticResult]:
        """Fail-closed: return BLOCKED if sanitizer unavailable."""
        if self.sanitizer is None:
            return DiagnosticResult.blocked(
                "Logic verification blocked: constraint sanitizer unavailable",
                {"constraint_id": "logic_verifier.sanitizer_unavailable"},
            )
        return None

    def _sanitize(self, constraints: List[str], variables: Dict[str, str]) -> List[str]:
        """Apply sanitizer (caller must have checked _ensure_sanitizer)."""
        return self.sanitizer.sanitize(constraints, variables)

    @staticmethod
    def _build_symbol_table(variables: Dict[str, str]) -> List[Dict[str, str]]:
        return [{"name": name, "type": type_str} for name, type_str in sorted(variables.items())]

    @staticmethod
    def _build_bitvector_model(solver: Solver) -> Dict[str, str]:
        model = solver.model()
        result = {}
        for d in model.decls():
            val = model[d]
            result[d.name()] = hex(val.as_long()) if is_bv(val) else str(val)
        return result

    @staticmethod
    def _build_proof_data(solver: Solver, extra: Optional[List[str]] = None) -> str:
        """Return raw assertion string for proof_ref hashing (no double-hash)."""
        assertions = [str(a) for a in solver.assertions()]
        if extra:
            assertions.extend(extra)
        return str(assertions)

    def _base_developer_fields(self, variables: Dict[str, str]) -> Dict[str, Any]:
        return {"symbol_table": self._build_symbol_table(variables)}

    def _add_z3_constraint(
        self, solver: Solver, constr: str, z3_vars: Dict, prove_unsat: bool, i: int
    ) -> None:
        z3_constraint = self._parse_constraint(constr, z3_vars)
        if z3_constraint is not None:
            if prove_unsat:
                solver.assert_and_track(z3_constraint, f"c{i}")
            else:
                solver.add(z3_constraint)

    def _handle_opt_sat(
        self, opt: Optimize, handle, fields: Dict, objective: str, maximize: bool
    ) -> DiagnosticResult:
        obj_value = handle.value()
        obj_str = str(obj_value)
        if obj_str in ("oo", "-oo"):
            fields["deterministic_verdict"] = "UNBOUNDED"
            return DiagnosticResult.unverifiable(
                "Objective is unbounded — no finite optimum exists",
                fields,
            )
        model = opt.model()
        solution = {d.name(): str(model[d]) for d in model.decls()}
        fields["model"] = solution
        fields["deterministic_verdict"] = "OPTIMAL"
        fields["objective_value"] = obj_str
        direction = "maximize" if maximize else "minimize"
        proof_data = self._build_proof_data(opt, extra=[f"{direction}: {objective}"])
        return DiagnosticResult.verified(
            "Optimal solution found",
            fields,
            {"model": solution, "objective": objective, "objective_value": obj_str},
            proof_data=proof_data,
        )

    def _build_array_z3_vars(
        self, array_decls: Dict[str, Tuple[str, str]]
    ) -> Tuple[Dict, Dict] | DiagnosticResult:
        z3_vars = {}
        type_map = {"int": IntSort(), "bool": BoolSort(), "real": RealSort()}
        all_symbols = {}
        for name, (idx_type, val_type) in array_decls.items():
            idx_sort = type_map.get(idx_type.lower())
            val_sort = type_map.get(val_type.lower())
            if idx_sort is None or val_sort is None:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: unsupported array sort declaration",
                    {
                        "constraint_id": _CONSTRAINT_ID_TYPE_VALIDATION,
                        "variable": name,
                        "declared_type": f"Array[{idx_type}, {val_type}]",
                    },
                )
            z3_vars[name] = Array(name, idx_sort, val_sort)
            all_symbols[name] = f"Array[{idx_type}, {val_type}]"
        return z3_vars, all_symbols

    # =========================================================================
    # Main Verification
    # =========================================================================

    def verify_logic(
        self,
        variables: Dict[str, str],
        constraints: List[str],
        prove_unsat: bool = False
    ) -> DiagnosticResult:
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    _EXPLICIT_DECLARATIONS_REQUIRED_MSG,
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            blocked = self._ensure_sanitizer()
            if blocked:
                return blocked
            blocked = self._ensure_safe_evaluator()
            if blocked:
                return blocked
            constraints = self._sanitize(constraints, variables)

            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            if prove_unsat:
                solver.set("unsat_core", True)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            for i, constr in enumerate(constraints):
                try:
                    self._add_z3_constraint(solver, constr, z3_vars, prove_unsat, i)
                except Exception as e:
                    return DiagnosticResult.blocked(
                        "Logic verification blocked: invalid constraint",
                        {
                            "constraint_id": _CONSTRAINT_ID_INVALID_CONSTRAINT,
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
                proof_data = self._build_proof_data(solver)
                return DiagnosticResult.verified(
                    "Logic constraints are satisfiable — model found",
                    fields,
                    {"model": solution, "constraints": constraints},
                    proof_data=proof_data,
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
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Quantified Formulas
    # =========================================================================

    def verify_with_quantifiers(
        self,
        variables: Dict[str, str],
        quantified_formulas: List[QuantifiedFormula],
        constraints: Optional[List[str]] = None
    ) -> DiagnosticResult:
        try:
            if not variables and not quantified_formulas:
                return DiagnosticResult.blocked(
                    _EXPLICIT_DECLARATIONS_REQUIRED_MSG,
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            seen_bound = {}  # cross-qf bound var conflict detection

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            for qf in quantified_formulas:
                scope_vars = dict(variables)
                for name, type_str in qf.bound_vars:
                    existing = scope_vars.get(name)
                    if existing is not None and existing.lower() != type_str.lower():
                        return DiagnosticResult.blocked(
                            "Logic verification blocked: bound variable conflicts with declaration",
                            {
                                "constraint_id": "logic_verifier.bound_variable_conflict",
                                "variable": name,
                                "declared_type": existing,
                                "bound_type": type_str,
                            },
                        )
                    prev_bound = seen_bound.get(name)
                    if prev_bound is not None and prev_bound.lower() != type_str.lower():
                        return DiagnosticResult.blocked(
                            "Logic verification blocked: bound variable conflicts across quantified formulas",
                            {
                                "constraint_id": "logic_verifier.bound_variable_conflict",
                                "variable": name,
                                "declared_type": prev_bound,
                                "bound_type": type_str,
                            },
                        )
                    scope_vars[name] = type_str
                    seen_bound[name] = type_str

                scope_z3 = self._create_z3_variables(scope_vars)
                if isinstance(scope_z3, DiagnosticResult):
                    return scope_z3

                blocked = self._ensure_sanitizer()
                if blocked:
                    return blocked
                blocked = self._ensure_safe_evaluator()
                if blocked:
                    return blocked
                sanitized_body = self._sanitize([qf.body], scope_vars)[0]
                body = self._parse_constraint(sanitized_body, scope_z3)
                if body is None:
                    continue

                bound_z3_vars = [scope_z3[name] for name, _ in qf.bound_vars]

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
                blocked = self._ensure_sanitizer()
                if blocked:
                    return blocked
                blocked = self._ensure_safe_evaluator()
                if blocked:
                    return blocked
                constraints = self._sanitize(constraints, variables)

                z3_vars = self._create_z3_variables(variables)
                if isinstance(z3_vars, DiagnosticResult):
                    return z3_vars
                for constr in constraints:
                    z3_constraint = self._parse_constraint(constr, z3_vars)
                    if z3_constraint is not None:
                        solver.add(z3_constraint)

            result = solver.check()

            fields = self._base_developer_fields(variables)
            verdict = str(result)
            fields["deterministic_verdict"] = verdict.upper()

            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = solution
                proof_data = self._build_proof_data(solver)
                return DiagnosticResult.verified(
                    "Quantified constraints are satisfiable — model found",
                    fields,
                    {"model": solution},
                    proof_data=proof_data,
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
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Bitvector Operations
    # =========================================================================

    def verify_bitvector(
        self,
        variables: Dict[str, int],
        constraints: List[str]
    ) -> DiagnosticResult:
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    _EXPLICIT_DECLARATIONS_REQUIRED_MSG,
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            z3_vars = {}
            for name, width in variables.items():
                if not isinstance(width, int) or width <= 0:
                    return DiagnosticResult.blocked(
                        "Logic verification blocked: malformed BitVec width declaration",
                        {
                            "constraint_id": _CONSTRAINT_ID_TYPE_VALIDATION,
                            "variable": name,
                            "declared_type": f"BitVec[{width}]",
                        },
                    )
                z3_vars[name] = BitVec(name, width)

            blocked = self._ensure_sanitizer()
            if blocked:
                return blocked
            blocked = self._ensure_safe_evaluator()
            if blocked:
                return blocked
            constraint_strs = {name: f"BitVec[{w}]" for name, w in variables.items()}
            constraints = self._sanitize(constraints, constraint_strs)

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            for constr in constraints:
                z3_constraint = self._parse_constraint(constr, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)

            result = solver.check()

            fields = self._base_developer_fields(
                {name: f"BitVec[{w}]" for name, w in variables.items()}
            )
            fields["deterministic_verdict"] = str(result).upper()

            if result == sat:
                solution = self._build_bitvector_model(solver)
                fields["model"] = solution
                proof_data = self._build_proof_data(solver)
                return DiagnosticResult.verified(
                    "Bitvector constraints are satisfiable — model found",
                    fields,
                    {"model": solution},
                    proof_data=proof_data,
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
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
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
        try:
            if not variables and not array_decls:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: explicit variable or array declarations are required",
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            array_built = self._build_array_z3_vars(array_decls)
            if isinstance(array_built, DiagnosticResult):
                return array_built
            z3_vars, all_symbols = array_built

            regular_vars = self._create_z3_variables(variables)
            if isinstance(regular_vars, DiagnosticResult):
                return regular_vars
            overlap = set(regular_vars) & set(z3_vars)
            if overlap:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: duplicate symbol declaration",
                    {"constraint_id": "logic_verifier.duplicate_symbol", "symbols": sorted(overlap)},
                )
            z3_vars.update(regular_vars)
            all_symbols.update(variables)

            blocked = self._ensure_sanitizer()
            if blocked:
                return blocked
            blocked = self._ensure_safe_evaluator()
            if blocked:
                return blocked
            constraints = self._sanitize(constraints, all_symbols)

            z3_vars['Select'] = Select
            z3_vars['Store'] = Store

            for constr in constraints:
                z3_constraint = self._parse_constraint(constr, z3_vars)
                if z3_constraint is not None:
                    solver.add(z3_constraint)

            result = solver.check()

            fields = self._base_developer_fields(all_symbols)
            fields["deterministic_verdict"] = str(result).upper()

            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                fields["model"] = solution
                proof_data = self._build_proof_data(solver)
                return DiagnosticResult.verified(
                    "Array constraints are satisfiable — model found",
                    fields,
                    {"model": solution},
                    proof_data=proof_data,
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
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
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
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    _EXPLICIT_DECLARATIONS_REQUIRED_MSG,
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            blocked = self._ensure_sanitizer()
            if blocked:
                return blocked
            blocked = self._ensure_safe_evaluator()
            if blocked:
                return blocked
            premises = self._sanitize(premises, variables)
            conclusion = self._sanitize([conclusion], variables)[0]

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
            if conclusion_z3 is None:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: invalid conclusion",
                    {"constraint_id": _CONSTRAINT_ID_INVALID_CONSTRAINT, "constraint": conclusion},
                )
            solver.add(Not(conclusion_z3))

            result = solver.check()

            fields = self._base_developer_fields(variables)
            fields["premises"] = premises
            fields["conclusion"] = conclusion

            if result == unsat:
                fields["deterministic_verdict"] = "contradiction_confirmed"
                proof_data = self._build_proof_data(solver)
                return DiagnosticResult.verified(
                    "Theorem proved by contradiction",
                    fields,
                    {"premises": premises, "conclusion": conclusion},
                    proof_data=proof_data,
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
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
            )

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _create_z3_variables(self, variables: Dict[str, str]) -> dict | DiagnosticResult:
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
                match = re.fullmatch(r'bitvec\[(\d+)\]', type_lower)
                width = int(match.group(1)) if match else 0
                if width > 0:
                    z3_vars[name] = BitVec(name, width)
                else:
                    return DiagnosticResult.blocked(
                        "Logic verification blocked: malformed BitVec type declaration",
                        {
                            "constraint_id": _CONSTRAINT_ID_TYPE_VALIDATION,
                            "variable": name,
                            "declared_type": type_str,
                            "error": f"Expected BitVec[N] where N is a positive integer, got '{type_str}'",
                        },
                    )
            else:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: unsupported type declaration",
                    {
                        "constraint_id": _CONSTRAINT_ID_TYPE_VALIDATION,
                        "variable": name,
                        "declared_type": type_str,
                    },
                )

        return z3_vars

    def _ensure_safe_evaluator(self) -> Optional[DiagnosticResult]:
        if self.safe_evaluator is None:
            return DiagnosticResult.blocked(
                "Logic verification blocked: constraint safe evaluator unavailable",
                {"constraint_id": "logic_verifier.safe_evaluator_unavailable"},
            )
        return None

    def _parse_constraint(self, constr: str, z3_vars: Dict) -> Any:
        """Parse a constraint string into Z3 expression."""
        if self.safe_evaluator:
            return self.safe_evaluator.safe_eval(constr, z3_vars)
        raise RuntimeError("SafeEvaluator is required for constraint parsing")

    def _explain_unsat(self, solver: Solver, constraints: List[str]) -> str:
        """Try to explain why constraints are unsatisfiable."""
        try:
            core = solver.unsat_core()
            if core:
                return f"Conflicting constraints: {[str(c) for c in core]}"
        except Exception:
            logger.debug("Unsat core extraction unavailable", exc_info=True)

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
        return self.prove_theorem(variables, [antecedent], consequent)

    def check_equivalence(
        self,
        variables: Dict[str, str],
        formula1: str,
        formula2: str
    ) -> DiagnosticResult:
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    _EXPLICIT_DECLARATIONS_REQUIRED_MSG,
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            blocked = self._ensure_sanitizer()
            if blocked:
                return blocked
            blocked = self._ensure_safe_evaluator()
            if blocked:
                return blocked
            sanitized = self._sanitize([formula1, formula2], variables)
            formula1, formula2 = sanitized[0], sanitized[1]

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            f1 = self._parse_constraint(formula1, z3_vars)
            f2 = self._parse_constraint(formula2, z3_vars)
            if f1 is None:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: invalid formula",
                    {"constraint_id": _CONSTRAINT_ID_INVALID_CONSTRAINT, "constraint": formula1},
                )
            if f2 is None:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: invalid formula",
                    {"constraint_id": _CONSTRAINT_ID_INVALID_CONSTRAINT, "constraint": formula2},
                )

            solver.add(Not(f1 == f2))

            result = solver.check()

            fields = self._base_developer_fields(variables)

            if result == unsat:
                fields["deterministic_verdict"] = "equivalent"
                proof_data = self._build_proof_data(solver)
                return DiagnosticResult.verified(
                    "Formulas are logically equivalent",
                    fields,
                    {"formula1": formula1, "formula2": formula2},
                    proof_data=proof_data,
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
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
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
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    _EXPLICIT_DECLARATIONS_REQUIRED_MSG,
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            blocked = self._ensure_sanitizer()
            if blocked:
                return blocked
            blocked = self._ensure_safe_evaluator()
            if blocked:
                return blocked
            constraints = self._sanitize(constraints, variables)
            objective = self._sanitize([objective], variables)[0]

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
            if obj_expr is None:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: invalid objective",
                    {"constraint_id": _CONSTRAINT_ID_INVALID_CONSTRAINT, "constraint": objective},
                )
            if maximize:
                handle = opt.maximize(obj_expr)
            else:
                handle = opt.minimize(obj_expr)

            result = opt.check()

            fields = self._base_developer_fields(variables)
            fields["objective"] = objective
            fields["maximize"] = maximize

            if result == sat:
                return self._handle_opt_sat(opt, handle, fields, objective, maximize)
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
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
            )

    def check_vacuity(
        self,
        variables: Dict[str, str],
        antecedent: str,
        consequent: Optional[str] = None
    ) -> DiagnosticResult:
        try:
            if not variables:
                return DiagnosticResult.blocked(
                    _EXPLICIT_DECLARATIONS_REQUIRED_MSG,
                    {"constraint_id": _CONSTRAINT_ID_EXPLICIT_DECLARATIONS},
                )

            blocked = self._ensure_sanitizer()
            if blocked:
                return blocked
            blocked = self._ensure_safe_evaluator()
            if blocked:
                return blocked
            antecedent = self._sanitize([antecedent], variables)[0]

            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            z3_vars = self._create_z3_variables(variables)
            if isinstance(z3_vars, DiagnosticResult):
                return z3_vars

            ant_expr = self._parse_constraint(antecedent, z3_vars)
            if ant_expr is None:
                return DiagnosticResult.blocked(
                    "Logic verification blocked: invalid antecedent",
                    {"constraint_id": _CONSTRAINT_ID_INVALID_CONSTRAINT, "constraint": antecedent},
                )
            solver.add(ant_expr)

            result = solver.check()

            fields = self._base_developer_fields(variables)
            fields["antecedent"] = antecedent
            if consequent:
                fields["consequent"] = consequent

            if result == unsat:
                fields["deterministic_verdict"] = "VACUOUS"
                return DiagnosticResult.unverifiable(
                    "Rule is vacuously true — antecedent can never be satisfied",
                    fields,
                )
            elif result == sat:
                fields["deterministic_verdict"] = "NON_VACUOUS"
                proof_data = self._build_proof_data(solver)
                return DiagnosticResult.verified(
                    "Rule is non-vacuous — antecedent is satisfiable",
                    fields,
                    {"antecedent": antecedent},
                    proof_data=proof_data,
                )
            else:
                fields["deterministic_verdict"] = "UNKNOWN"
                return DiagnosticResult.unverifiable(
                    "Vacuity check did not converge",
                    fields,
                )

        except Exception as exc:
            logger.exception("Vacuity check pipeline failed")
            return DiagnosticResult.blocked(
                _PIPELINE_ERROR_MSG,
                {"constraint_id": _CONSTRAINT_ID_EXECUTION_ERROR, "error_type": type(exc).__name__},
            )
