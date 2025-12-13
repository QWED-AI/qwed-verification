"""
Unit Tests for QWED DSL Parser and Compiler.

Run with: pytest tests/test_dsl.py -v
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from qwed_new.core.dsl.parser import QWEDLogicDSL, parse_and_validate


class TestDSLParser:
    """Test the DSL parser."""
    
    def setup_method(self):
        """Setup for each test."""
        self.parser = QWEDLogicDSL()
    
    # === VALID EXPRESSIONS ===
    
    def test_simple_comparison(self):
        """Test simple comparison: (GT x 5)"""
        result = self.parser.run("(GT x 5)")
        assert result['status'] == 'SUCCESS'
        assert result['ast'] == ['GT', 'x', 5]
    
    def test_nested_and_or(self):
        """Test nested AND/OR: (AND (GT x 5) (LT y 10))"""
        result = self.parser.run("(AND (GT x 5) (LT y 10))")
        assert result['status'] == 'SUCCESS'
        assert result['ast'][0] == 'AND'
        assert len(result['ast']) == 3
    
    def test_implies(self):
        """Test IMPLIES (enterprise rule pattern)."""
        result = self.parser.run("(IMPLIES (GT amount 10000) (EQ requires_approval True))")
        assert result['status'] == 'SUCCESS'
        assert result['ast'][0] == 'IMPLIES'
    
    def test_arithmetic(self):
        """Test arithmetic: (MULT 0.15 200)"""
        result = self.parser.run("(MULT 0.15 200)")
        assert result['status'] == 'SUCCESS'
        assert result['ast'] == ['MULT', 0.15, 200]
    
    def test_complex_nested(self):
        """Test deeply nested expression."""
        result = self.parser.run("(AND (OR (GT x 5) (LT y 10)) (NOT (EQ z 0)))")
        assert result['status'] == 'SUCCESS'
    
    def test_variable_declaration(self):
        """Test VAR declaration."""
        result = self.parser.run("(VAR x Int)")
        assert result['status'] == 'SUCCESS'
        assert 'x' in result['variables']
        assert result['variables']['x']['type'] == 'Int'
    
    def test_boolean_literals(self):
        """Test boolean literals True/False."""
        result = self.parser.run("(EQ is_valid True)")
        assert result['status'] == 'SUCCESS'
        assert result['ast'] == ['EQ', 'is_valid', True]
    
    def test_float_numbers(self):
        """Test floating point numbers."""
        result = self.parser.run("(LT probability 0.95)")
        assert result['status'] == 'SUCCESS'
        assert result['ast'][2] == 0.95
    
    # === SECURITY BLOCKS ===
    
    def test_block_import(self):
        """Security: Block IMPORT operator."""
        result = self.parser.run("(IMPORT os)")
        assert result['status'] == 'BLOCKED'
        assert 'SECURITY BLOCK' in result['error']
        assert 'IMPORT' in result['error']
    
    def test_block_exec(self):
        """Security: Block EXEC operator."""
        result = self.parser.run("(EXEC 'os.system(\"rm -rf /\")')")
        assert result['status'] == 'BLOCKED'
        assert 'SECURITY BLOCK' in result['error']
    
    def test_block_eval(self):
        """Security: Block EVAL operator."""
        result = self.parser.run("(EVAL code)")
        assert result['status'] == 'BLOCKED'
    
    def test_block_unknown_operator(self):
        """Security: Block unknown operator (LLM hallucination)."""
        result = self.parser.run("(CHECK_IF_HAPPY user)")
        assert result['status'] == 'BLOCKED'
        assert 'CHECK_IF_HAPPY' in result['error']
    
    def test_block_dunder(self):
        """Security: Block __import__ style attacks."""
        result = self.parser.run("(__IMPORT__ os)")
        assert result['status'] == 'BLOCKED'
    
    def test_block_system(self):
        """Security: Block SYSTEM call."""
        result = self.parser.run("(SYSTEM 'rm -rf /')")
        assert result['status'] == 'BLOCKED'
    
    # === ARITY VALIDATION ===
    
    def test_not_requires_one_arg(self):
        """Arity: NOT requires exactly 1 argument."""
        result = self.parser.run("(NOT a b c)")
        assert result['status'] == 'BLOCKED'
        assert 'at most 1' in result['error']
    
    def test_implies_requires_two_args(self):
        """Arity: IMPLIES requires exactly 2 arguments."""
        result = self.parser.run("(IMPLIES a)")
        assert result['status'] == 'BLOCKED'
        assert 'at least 2' in result['error']
    
    def test_and_requires_at_least_two(self):
        """Arity: AND requires at least 2 arguments."""
        result = self.parser.run("(AND x)")
        assert result['status'] == 'BLOCKED'
    
    # === SYNTAX ERRORS ===
    
    def test_empty_expression(self):
        """Syntax: Empty string."""
        result = self.parser.run("")
        assert result['status'] == 'PARSE_ERROR'
    
    def test_unbalanced_parens(self):
        """Syntax: Unbalanced parentheses."""
        result = self.parser.run("(AND (GT x 5)")
        assert result['status'] == 'PARSE_ERROR'
    
    def test_unexpected_close_paren(self):
        """Syntax: Unexpected closing paren."""
        result = self.parser.run(")")
        assert result['status'] == 'PARSE_ERROR'
    
    # === EDGE CASES ===
    
    def test_empty_list(self):
        """Edge case: Empty list ()."""
        result = self.parser.run("()")
        assert result['status'] == 'SUCCESS'
        assert result['ast'] == []
    
    def test_single_atom(self):
        """Edge case: Just a variable name."""
        result = self.parser.run("x")
        assert result['status'] == 'SUCCESS'
        assert result['ast'] == 'x'
    
    def test_whitespace_handling(self):
        """Edge case: Extra whitespace."""
        result = self.parser.run("  (  AND  (GT x  5)  (LT y  10)  )  ")
        assert result['status'] == 'SUCCESS'


class TestDSLCompiler:
    """Test the DSL compiler."""
    
    def setup_method(self):
        """Setup for each test."""
        self.parser = QWEDLogicDSL()
    
    def test_z3_simple_constraint(self):
        """Compile simple constraint to Z3."""
        from qwed_new.core.dsl.compiler import compile_to_z3
        
        result = self.parser.run("(AND (GT x 5) (LT y 10))")
        assert result['status'] == 'SUCCESS'
        
        z3_result = compile_to_z3(result['ast'])
        assert z3_result.success
        assert z3_result.compiled is not None
        # Verify it's a Z3 expression (has decl method)
        assert hasattr(z3_result.compiled, 'decl')
    
    def test_sympy_arithmetic(self):
        """Compile arithmetic to SymPy."""
        from qwed_new.core.dsl.compiler import compile_to_sympy
        import sympy
        
        result = self.parser.run("(MULT 0.15 200)")
        assert result['status'] == 'SUCCESS'
        
        sympy_result = compile_to_sympy(result['ast'])
        assert sympy_result.success
        
        # Evaluate the expression
        evaluated = sympy.simplify(sympy_result.compiled)
        assert float(evaluated) == 30.0
    
    def test_z3_implies(self):
        """Compile IMPLIES to Z3."""
        from qwed_new.core.dsl.compiler import compile_to_z3
        
        result = self.parser.run("(IMPLIES (GT x 10) (EQ y 1))")
        assert result['status'] == 'SUCCESS'
        
        z3_result = compile_to_z3(result['ast'])
        assert z3_result.success


class TestSecurityIntegration:
    """Integration tests for security scenarios from real logs."""
    
    def setup_method(self):
        self.parser = QWEDLogicDSL()
    
    def test_error_log_import_attack(self):
        """
        From error_test_log.json:
        SECURITY VIOLATION: Dangerous function: __import__
        """
        # The LLM tried to sneak in an import
        result = self.parser.run("(AND (GT x 5) (IMPORT os))")
        assert result['status'] == 'BLOCKED'
    
    def test_extreme_adversarial_hallucination(self):
        """
        From extreme_adversarial_report.json:
        name 'logic_function_schema' is not defined
        """
        # The LLM invented a function
        result = self.parser.run("(logic_function_schema variables)")
        assert result['status'] == 'BLOCKED'
    
    def test_prompt_injection_sql(self):
        """
        Prompt injection attempting SQL.
        """
        result = self.parser.run("(SQL 'DROP TABLE users')")
        assert result['status'] == 'BLOCKED'


# Run tests directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
