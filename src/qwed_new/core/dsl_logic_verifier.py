"""
Logic Verification Engine with DSL Support.

This module provides a new logic verifier that uses the QWED-DSL
for secure, validated constraint parsing.
"""

import ast
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from z3 import Solver, sat, unsat

from qwed_new.core.dsl import parse_and_validate, compile_to_z3
from qwed_new.core.translator import TranslationLayer


@dataclass
class DSLVerificationResult:
    """Result of DSL-based logic verification."""
    status: str  # "SAT", "UNSAT", "ERROR", "BLOCKED"
    model: Optional[Dict[str, str]] = None
    dsl_code: Optional[str] = None
    parsed_ast: Optional[Any] = None
    error: Optional[str] = None
    rejection_reason: Optional[str] = None  # Human-readable explanation for UNSAT
    provider_used: Optional[str] = None


class DSLLogicVerifier:
    """
    Logic Verifier using QWED-DSL.
    
    This replaces unsafe eval() with a secure, whitelist-based parser.
    
    Flow:
    1. Parse DSL code → AST
    2. Validate against whitelist
    3. Compile to Z3
    4. Solve and return result
    """
    
    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms
    
    def verify_from_dsl(
        self, 
        dsl_code: str,
        variables: Optional[List[Dict[str, str]]] = None
    ) -> DSLVerificationResult:
        """
        Verify logic from QWED-DSL code.
        
        Args:
            dsl_code: The QWED-DSL S-expression string
            variables: Optional list of variable declarations [{"name": "x", "type": "Int"}, ...]
            
        Returns:
            DSLVerificationResult with status and model
        """
        # 1. Parse and Validate
        parse_result = parse_and_validate(dsl_code)
        
        if parse_result['status'] == 'BLOCKED':
            return DSLVerificationResult(
                status="BLOCKED",
                error=parse_result.get('error'),
                dsl_code=dsl_code
            )
        
        if parse_result['status'] == 'PARSE_ERROR':
            return DSLVerificationResult(
                status="ERROR",
                error=f"Parse error: {parse_result.get('error')}",
                dsl_code=dsl_code
            )
        
        if parse_result['status'] != 'SUCCESS':
            return DSLVerificationResult(
                status="ERROR",
                error=parse_result.get('error', 'Unknown error'),
                dsl_code=dsl_code
            )
        
        # 2. Convert variables list to dict format for compiler
        var_declarations = {}
        if variables:
            for var in variables:
                if isinstance(var, dict) and 'name' in var:
                    var_declarations[var['name']] = {'type': var.get('type', 'Int')}
        
        # 3. Compile to Z3
        ast = parse_result['ast']
        compile_result = compile_to_z3(ast, var_declarations)
        
        if not compile_result.success:
            return DSLVerificationResult(
                status="ERROR",
                error=compile_result.error,
                dsl_code=dsl_code,
                parsed_ast=ast
            )
        
        # 4. Solve with Z3
        try:
            solver = Solver()
            solver.set("timeout", self.timeout_ms)
            
            # Add the compiled constraint
            if compile_result.compiled is not None:
                solver.add(compile_result.compiled)
            
            # Check satisfiability
            result = solver.check()
            
            if result == sat:
                model = solver.model()
                solution = {d.name(): str(model[d]) for d in model.decls()}
                return DSLVerificationResult(
                    status="SAT",
                    model=solution,
                    dsl_code=dsl_code,
                    parsed_ast=ast
                )
            elif result == unsat:
                # Generate human-readable rejection reason
                rejection_reason = self._explain_unsat(dsl_code, ast)
                return DSLVerificationResult(
                    status="UNSAT",
                    dsl_code=dsl_code,
                    parsed_ast=ast,
                    rejection_reason=rejection_reason
                )
            else:
                return DSLVerificationResult(
                    status="UNKNOWN",
                    error="Solver returned unknown (possibly timeout)",
                    dsl_code=dsl_code,
                    parsed_ast=ast
                )
        
        except Exception as e:
            return DSLVerificationResult(
                status="ERROR",
                error=f"Z3 solver error: {str(e)}",
                dsl_code=dsl_code,
                parsed_ast=ast
            )
    
    def _explain_unsat(self, dsl_code: str, ast: Any) -> str:
        """
        Generate a human-readable explanation for why constraints are unsatisfiable.
        
        This analyzes the AST to identify conflicting constraints and generates
        a user-friendly message.
        
        Args:
            dsl_code: Original DSL code
            ast: Parsed AST
            
        Returns:
            Human-readable explanation string
        """
        # Extract constraint descriptions from AST
        constraints = self._extract_constraints_from_ast(ast)
        
        if len(constraints) == 0:
            return "The constraints are contradictory and cannot be satisfied."
        
        if len(constraints) == 1:
            return f"Rule violated: {constraints[0]}"
        
        # Try to identify specific conflicts
        conflict_msg = self._identify_conflicts(constraints)
        if conflict_msg:
            return conflict_msg
        
        # Default: List all constraints
        constraint_list = "\n  - ".join(constraints)
        return (
            f"No valid solution exists. The following constraints are in conflict:\n"
            f"  - {constraint_list}"
        )
    
    def _extract_constraints_from_ast(self, ast: Any) -> List[str]:
        """Extract human-readable constraint descriptions from AST."""
        constraints = []
        
        if ast is None:
            return constraints
        
        # Handle tuple format: (OPERATOR, operand1, operand2, ...)
        if isinstance(ast, tuple) and len(ast) >= 1:
            op = ast[0]
            
            # Comparison operators
            if op in ("GT", "LT", "GE", "LE", "GTE", "LTE", "EQ", "NE", "NEQ"):
                op_symbols = {
                    "GT": ">",
                    "LT": "<",
                    "GE": ">=",
                    "LE": "<=",
                    "GTE": ">=",
                    "LTE": "<=",
                    "EQ": "==",
                    "NE": "!=",
                    "NEQ": "!=",
                }
                if len(ast) >= 3:
                    left = self._format_operand(ast[1])
                    right = self._format_operand(ast[2])
                    constraints.append(f"{left} {op_symbols.get(op, op)} {right}")
            
            # Logical operators (recurse)
            elif op in ("AND", "OR", "NOT", "IMPLIES"):
                for operand in ast[1:]:
                    constraints.extend(self._extract_constraints_from_ast(operand))
            
            # Arithmetic (just describe)
            elif op in ("PLUS", "MINUS", "MUL", "MULT", "DIV"):
                constraints.append("Arithmetic expression constraint")
        
        return constraints
    
    def _format_operand(self, operand: Any) -> str:
        """Format an operand for display."""
        if isinstance(operand, tuple):
            # Nested expression
            op = operand[0]
            if op in ("PLUS", "MINUS", "MUL", "MULT", "DIV"):
                op_symbols = {"PLUS": "+", "MINUS": "-", "MUL": "*", "MULT": "*", "DIV": "/"}
                if len(operand) >= 3:
                    left = self._format_operand(operand[1])
                    right = self._format_operand(operand[2])
                    return f"({left} {op_symbols.get(op, op)} {right})"
            return str(operand)
        return str(operand)
    
    def _identify_conflicts(self, constraints: List[str]) -> Optional[str]:
        """Try to identify specific conflicts between constraints."""
        # Look for obvious contradictions like x > 5 AND x < 3
        for i, c1 in enumerate(constraints):
            for c2 in constraints[i+1:]:
                # Check if same variable has conflicting bounds
                if self._are_conflicting(c1, c2):
                    return (
                        f"Contradiction detected:\n"
                        f"  Rule 1: {c1}\n"
                        f"  Rule 2: {c2}\n"
                        f"These constraints cannot both be true."
                    )
        return None
    
    def _are_conflicting(self, c1: str, c2: str) -> bool:
        """Check if two constraints are obviously conflicting."""
        # Simple heuristic: same variable with > and < that overlap
        # E.g., "x > 5" and "x < 3"
        import re
        
        # Pattern: variable > number
        gt_pattern = r"(\w+)\s*>\s*([\d.]+)"
        lt_pattern = r"(\w+)\s*<\s*([\d.]+)"
        
        gt1 = re.search(gt_pattern, c1)
        lt1 = re.search(lt_pattern, c1)
        gt2 = re.search(gt_pattern, c2)
        lt2 = re.search(lt_pattern, c2)
        
        # Check x > a AND x < b where a >= b
        if gt1 and lt2:
            if gt1.group(1) == lt2.group(1):  # Same variable
                lower = float(gt1.group(2))
                upper = float(lt2.group(2))
                if lower >= upper:
                    return True
        
        if lt1 and gt2:
            if lt1.group(1) == gt2.group(1):  # Same variable
                upper = float(lt1.group(2))
                lower = float(gt2.group(2))
                if lower >= upper:
                    return True
        
        return False

    def _provider_label(self, provider: Any) -> str:
        """Normalize provider enum/string to a plain string label."""
        if provider is None:
            return "unknown"
        value = str(getattr(provider, "value", provider)).strip().lower()
        return value or "unknown"

    def _bool_literal(self, value: bool) -> str:
        """Convert Python booleans to DSL bool literals."""
        return "True" if value else "False"

    def _ast_to_dsl(self, node: ast.AST) -> str:
        """Convert Python AST node to QWED DSL."""
        if isinstance(node, ast.BoolOp):
            op = "AND" if isinstance(node.op, ast.And) else "OR"
            parts = [self._ast_to_dsl(v) for v in node.values]
            if len(parts) == 1:
                return parts[0]
            return f"({op} {' '.join(parts)})"

        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return f"(NOT {self._ast_to_dsl(node.operand)})"
            if isinstance(node.op, ast.USub):
                if isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, int):
                    return str(-node.operand.value)
                if isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, float):
                    raise ValueError(
                        "Floating-point literals are not allowed in verification logic; use exact integer input."
                    )
                return f"(MINUS 0 {self._ast_to_dsl(node.operand)})"
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")

        if isinstance(node, ast.BinOp):
            op_map = {
                ast.Add: "PLUS",
                ast.Sub: "MINUS",
                ast.Mult: "MUL",
                ast.Div: "DIV",
                ast.Mod: "MOD",
                ast.Pow: "POW",
            }
            op = op_map.get(type(node.op))
            if not op:
                raise ValueError(f"Unsupported arithmetic operator: {type(node.op).__name__}")
            return f"({op} {self._ast_to_dsl(node.left)} {self._ast_to_dsl(node.right)})"

        if isinstance(node, ast.Compare):
            cmp_map = {
                ast.Eq: "EQ",
                ast.NotEq: "NE",
                ast.Gt: "GT",
                ast.Lt: "LT",
                ast.GtE: "GE",
                ast.LtE: "LE",
            }
            if len(node.ops) != len(node.comparators):
                raise ValueError("Invalid comparison expression")
            comparisons = []
            left = node.left
            for op_node, right in zip(node.ops, node.comparators, strict=False):
                op = cmp_map.get(type(op_node))
                if not op:
                    raise ValueError(f"Unsupported comparison operator: {type(op_node).__name__}")
                comparisons.append(f"({op} {self._ast_to_dsl(left)} {self._ast_to_dsl(right)})")
                left = right
            if len(comparisons) == 1:
                return comparisons[0]
            return f"(AND {' '.join(comparisons)})"

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            func = node.func.id
            if func in {"And", "Or"}:
                op = "AND" if func == "And" else "OR"
                args = [self._ast_to_dsl(arg) for arg in node.args]
                if len(args) == 1:
                    return args[0]
                return f"({op} {' '.join(args)})"
            if func == "Not":
                if len(node.args) != 1:
                    raise ValueError("Not(...) requires one argument")
                return f"(NOT {self._ast_to_dsl(node.args[0])})"

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, bool):
                return self._bool_literal(value)
            if isinstance(value, int):
                return str(value)
            if isinstance(value, float):
                raise ValueError(
                    "Floating-point literals are not allowed in verification logic; use exact integer input."
                )
            if isinstance(value, str):
                token = re.sub(r"\W+", "_", value).strip("_")
                return token or "value"
            return str(value)

        raise ValueError(f"Unsupported constraint node: {type(node).__name__}")

    def _constraint_to_dsl(self, constraint: str, var_types: Optional[Dict[str, str]] = None) -> str:
        """Convert one Python-like logical constraint to DSL."""
        text = str(constraint or "").strip()
        if not text:
            raise ValueError("Empty constraint")

        var_types = var_types or {}

        def _required_literal(var_name: str, required: bool) -> str:
            var_type = str(var_types.get(var_name, "")).lower()
            if var_type == "bool":
                return self._bool_literal(required)
            return "1" if required else "0"

        def _replace_not_required(match: re.Match) -> str:
            var_name = match.group(1)
            return f"{var_name} == {_required_literal(var_name, required=False)}"

        def _replace_required(match: re.Match) -> str:
            var_name = match.group(1)
            return f"{var_name} == {_required_literal(var_name, required=True)}"

        # Normalize common natural-language boolean phrases.
        text = re.sub(
            r"\b([A-Za-z_]\w*)\s+is\s+not\s+required\b",
            _replace_not_required,
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r"\b([A-Za-z_]\w*)\s+is\s+required\b",
            _replace_required,
            text,
            flags=re.IGNORECASE,
        )

        # Normalize uppercase keywords from LLM outputs.
        text = re.sub(r"\bAND\b", "and", text, flags=re.IGNORECASE)
        text = re.sub(r"\bOR\b", "or", text, flags=re.IGNORECASE)
        text = re.sub(r"\bNOT\b", "not", text, flags=re.IGNORECASE)

        # Replace accidental assignment-style "=" with comparison "==".
        text = re.sub(r"(?<![<>=!])=(?!=)", "==", text)

        parsed = ast.parse(text, mode="eval")
        return self._ast_to_dsl(parsed.body)

    def _logic_task_to_dsl(self, logic_task: Any) -> tuple[str, List[Dict[str, str]]]:
        """Convert LogicVerificationTask to DSL code and variable declarations."""
        goal = str(getattr(logic_task, "goal", "SATISFIABILITY")).strip().upper()
        if goal != "SATISFIABILITY":
            raise ValueError(f"Unsupported logic goal: {goal}")

        constraints = [str(c).strip() for c in getattr(logic_task, "constraints", []) if str(c).strip()]
        if not constraints:
            return "", []

        variables_dict = getattr(logic_task, "variables", {}) or {}
        dsl_parts = [self._constraint_to_dsl(c, variables_dict) for c in constraints]
        dsl_code = dsl_parts[0] if len(dsl_parts) == 1 else f"(AND {' '.join(dsl_parts)})"
        variables = [{"name": str(name), "type": str(vtype)} for name, vtype in variables_dict.items()]
        return dsl_code, variables
    
    def verify_from_natural_language(
        self,
        query: str,
        provider: str = "azure_openai"
    ) -> DSLVerificationResult:
        """
        Full pipeline: Natural Language → DSL → Z3.
        
        Args:
            query: Natural language logic query
            provider: Which LLM provider to use
            
        Returns:
            DSLVerificationResult
        """
        provider_label = self._provider_label(provider)
        resolved_provider = provider_label
        translator = TranslationLayer()

        # 1. Translate to structured logic constraints
        try:
            logic_result = translator.translate_logic(query, provider=provider_label)
            resolved_provider = self._provider_label(
                getattr(translator, "last_resolved_provider", None) or provider_label
            )
            dsl_code, variables = self._logic_task_to_dsl(logic_result)
            if not dsl_code:
                return DSLVerificationResult(
                    status="ERROR",
                    error="No constraints generated from natural language query",
                    provider_used=resolved_provider,
                )
        except ValueError as e:
            return DSLVerificationResult(
                status="ERROR",
                error=str(e) if str(e).startswith("Unsupported logic goal:") else "LLM translation failed",
                provider_used=resolved_provider,
            )
        except Exception:
            return DSLVerificationResult(
                status="ERROR",
                error="LLM translation failed",
                provider_used=resolved_provider,
            )

        # 2. Verify from DSL
        verification_result = self.verify_from_dsl(dsl_code, variables)
        verification_result.provider_used = resolved_provider
        if not verification_result.dsl_code:
            verification_result.dsl_code = dsl_code
        return verification_result


# Singleton for convenience
_dsl_verifier = None

def get_dsl_verifier() -> DSLLogicVerifier:
    """Get the singleton DSL verifier instance."""
    global _dsl_verifier
    if _dsl_verifier is None:
        _dsl_verifier = DSLLogicVerifier()
    return _dsl_verifier


def verify_logic_dsl(dsl_code: str, variables: Optional[List[Dict]] = None) -> DSLVerificationResult:
    """Convenience function to verify logic from DSL code."""
    return get_dsl_verifier().verify_from_dsl(dsl_code, variables)


# --- DEMO ---
if __name__ == "__main__":
    verifier = DSLLogicVerifier()
    
    print("=" * 60)
    print("QWED DSL Logic Verifier Demo")
    print("=" * 60)
    
    # Test 1: Valid constraint - SAT
    print("\nTest 1: x > 5 AND y < 10 (should be SAT)")
    result = verifier.verify_from_dsl(
        "(AND (GT x 5) (LT y 10))",
        [{"name": "x", "type": "Int"}, {"name": "y", "type": "Int"}]
    )
    print(f"Status: {result.status}")
    print(f"Model: {result.model}")
    
    # Test 2: Unsatisfiable
    print("\nTest 2: x > 10 AND x < 5 (should be UNSAT)")
    result = verifier.verify_from_dsl(
        "(AND (GT x 10) (LT x 5))",
        [{"name": "x", "type": "Int"}]
    )
    print(f"Status: {result.status}")
    
    # Test 3: Security block
    print("\nTest 3: Attempt IMPORT (should be BLOCKED)")
    result = verifier.verify_from_dsl("(IMPORT os)")
    print(f"Status: {result.status}")
    print(f"Error: {result.error}")
    
    # Test 4: Enterprise rule
    print("\nTest 4: If amount > 10000 then requires_approval = True")
    result = verifier.verify_from_dsl(
        "(IMPLIES (GT amount 10000) (EQ requires_approval True))",
        [{"name": "amount", "type": "Int"}, {"name": "requires_approval", "type": "Bool"}]
    )
    print(f"Status: {result.status}")
    print(f"Model: {result.model}")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
