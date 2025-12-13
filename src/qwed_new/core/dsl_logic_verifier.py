"""
Logic Verification Engine with DSL Support.

This module provides a new logic verifier that uses the QWED-DSL
for secure, validated constraint parsing.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from z3 import Solver, sat, unsat

from qwed_new.core.dsl import parse_and_validate, compile_to_z3
from qwed_new.core.schemas import LogicResult


@dataclass
class DSLVerificationResult:
    """Result of DSL-based logic verification."""
    status: str  # "SAT", "UNSAT", "ERROR", "BLOCKED"
    model: Optional[Dict[str, str]] = None
    dsl_code: Optional[str] = None
    parsed_ast: Optional[Any] = None
    error: Optional[str] = None


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
                return DSLVerificationResult(
                    status="UNSAT",
                    dsl_code=dsl_code,
                    parsed_ast=ast
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
        # 1. Translate to DSL
        try:
            if provider == "azure_openai":
                from qwed_new.providers.azure_openai import AzureOpenAIProvider
                llm = AzureOpenAIProvider()
                dsl_result = llm.translate_logic_dsl(query)
            else:
                # Fallback to Azure
                from qwed_new.providers.azure_openai import AzureOpenAIProvider
                llm = AzureOpenAIProvider()
                dsl_result = llm.translate_logic_dsl(query)
            
            dsl_code = dsl_result.get('dsl_code', '')
            variables = dsl_result.get('variables', [])
            
        except Exception as e:
            return DSLVerificationResult(
                status="ERROR",
                error=f"LLM translation failed: {str(e)}"
            )
        
        # 2. Verify from DSL
        return self.verify_from_dsl(dsl_code, variables)


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
