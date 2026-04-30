"""
Tests for SymbolicVerifier - CrossHair Integration.

These tests verify the symbolic execution engine works correctly.
"""

import pytest
import sys
import os
from unittest.mock import patch

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from qwed_new.core.symbolic_verifier import SymbolicVerifier, create_symbolic_verifier


class TestSymbolicVerifierBasic:
    """Basic tests for SymbolicVerifier."""
    
    def test_verifier_initialization(self):
        """Test that verifier initializes correctly."""
        verifier = SymbolicVerifier()
        assert verifier.timeout_seconds == 30
        assert verifier.max_iterations == 100
    
    def test_verifier_custom_config(self):
        """Test custom configuration."""
        verifier = SymbolicVerifier(timeout_seconds=60, max_iterations=200)
        assert verifier.timeout_seconds == 60
        assert verifier.max_iterations == 200
    
    def test_factory_function(self):
        """Test factory function works."""
        verifier = create_symbolic_verifier(timeout_seconds=10)
        assert verifier.timeout_seconds == 10


class TestSafetyPropertyChecks:
    """Test safety property verification."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier()
    
    def test_detect_division_by_zero_literal(self):
        """Test detection of literal division by zero."""
        code = """
def divide(x):
    return x / 0
"""
        result = self.verifier.verify_safety_properties(code)
        assert not result["is_safe"]
        assert any("division_by_zero" in str(i) for i in result["issues"])
    
    def test_detect_potential_division_by_variable(self):
        """Test detection of potential division by zero with variable."""
        code = """
def divide(x: int, y: int) -> float:
    return x / y
"""
        result = self.verifier.verify_safety_properties(code)
        # Should flag as potential issue
        assert len(result["issues"]) > 0
        assert any("potential_division_by_zero" in str(i["type"]) for i in result["issues"])
    
    def test_safe_code(self):
        """Test that safe code passes."""
        code = """
def add(x: int, y: int) -> int:
    return x + y
"""
        result = self.verifier.verify_safety_properties(code)
        # No division, should be clean
        assert result["errors"] == 0
    
    def test_syntax_error_handling(self):
        """Test handling of syntax errors."""
        code = """
def broken(
    return x + 
"""
        result = self.verifier.verify_safety_properties(code)
        assert not result["is_safe"]
        assert result["status"] == "syntax_error"


class TestFunctionExtraction:
    """Test function extraction from code."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier()
    
    def test_extract_typed_function(self):
        """Test extraction of typed functions."""
        code = """
def add(x: int, y: int) -> int:
    return x + y
"""
        import ast
        tree = ast.parse(code)
        functions = self.verifier._extract_functions(tree)
        
        assert len(functions) == 1
        assert functions[0]["name"] == "add"
        assert functions[0]["has_types"] == True
    
    def test_extract_untyped_function(self):
        """Test extraction of untyped functions."""
        code = """
def add(x, y):
    return x + y
"""
        import ast
        tree = ast.parse(code)
        functions = self.verifier._extract_functions(tree)
        
        assert len(functions) == 1
        assert functions[0]["name"] == "add"
        assert functions[0]["has_types"] == False
    
    def test_multiple_functions(self):
        """Test extraction of multiple functions."""
        code = """
def add(x: int, y: int) -> int:
    return x + y

def multiply(x: int, y: int) -> int:
    return x * y

def divide(x, y):
    return x / y
"""
        import ast
        tree = ast.parse(code)
        functions = self.verifier._extract_functions(tree)
        
        assert len(functions) == 3


# Check if CrossHair is available at module level
_crosshair_available = SymbolicVerifier()._crosshair_available


class TestCodeVerification:
    """Test code verification with CrossHair."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier(timeout_seconds=5)
    
    def test_verify_no_functions(self):
        """Code with no functions must fail closed, not pass as verified."""
        code = """
x = 1 + 2
print(x)
"""
        with patch.object(self.verifier, "_crosshair_available", True):
            result = self.verifier.verify_code(code)
        assert result["is_verified"] is False
        assert result["status"] == "no_verifiable_functions"
        assert result["functions_discovered"] == 0
        assert result["functions_checked"] == 0
        assert result["functions_verified"] == 0
        assert result["functions_unverifiable"] == 0
        assert result["issues"][0]["type"] == "unverifiable"

    @pytest.mark.skipif(not _crosshair_available, reason="CrossHair not installed")
    def test_verify_syntax_error(self):
        """Test verification handles syntax errors."""
        code = """
def broken(
"""
        result = self.verifier.verify_code(code)
        assert result["status"] == "syntax_error"
    
    @pytest.mark.skipif(not _crosshair_available, reason="CrossHair not installed")
    def test_verify_simple_function(self):
        """Test verification of simple typed function."""
        code = """
def add(x: int, y: int) -> int:
    return x + y
"""
        result = self.verifier.verify_code(code)
        # Simple addition should verify
        assert result["functions_checked"] > 0

    def test_verify_untyped_function_fails_closed(self):
        """Untyped functions must not be reported as verified."""
        code = """
def add(a, b):
    return a + b
"""
        with patch.object(self.verifier, "_crosshair_available", True):
            result = self.verifier.verify_code(code)

        assert result["is_verified"] is False
        assert result["status"] == "no_verifiable_functions"
        assert result["functions_discovered"] == 1
        assert result["functions_checked"] == 0
        assert result["functions_skipped"] == 1
        assert result["functions_unverifiable"] == 1
        assert result["functions_verified"] == 0
        assert any(issue["function"] == "add" for issue in result["issues"])

    def test_verify_mixed_typed_and_untyped_functions_remains_unverifiable(self):
        """A skipped function must prevent an overall verified result."""
        code = """
def typed_add(a: int, b: int) -> int:
    return a + b

def untyped_add(a, b):
    return a + b
"""
        with patch.object(self.verifier, "_crosshair_available", True):
            with patch.object(
                self.verifier,
                "_verify_function",
                side_effect=[
                    {
                        "verified": True,
                        "function": "typed_add",
                        "skipped": False,
                        "unverifiable": False,
                        "issues": []
                    },
                    {
                        "verified": False,
                        "function": "untyped_add",
                        "skipped": True,
                        "unverifiable": True,
                        "issues": [{
                            "type": "unverifiable",
                            "function": "untyped_add",
                            "description": "Function skipped: no type annotations for symbolic verification"
                        }]
                    }
                ]
            ):
                result = self.verifier.verify_code(code)

        assert result["is_verified"] is False
        assert result["status"] == "unverifiable"
        assert result["functions_discovered"] == 2
        assert result["functions_checked"] == 1
        assert result["functions_verified"] == 1
        assert result["functions_skipped"] == 1
        assert result["functions_unverifiable"] == 1

    def test_skipped_function_result_is_not_marked_verified(self):
        """Function-level skip results must not claim successful verification."""
        func_info = {"name": "add", "has_types": False}
        result = self.verifier._verify_function("def add(a, b):\n    return a + b\n", func_info)

        assert result["verified"] is False
        assert result["skipped"] is True
        assert result["unverifiable"] is True
        assert result["issues"][0]["type"] == "unverifiable"


class TestContractVerification:
    """Test function contract verification."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier()
    
    def test_add_preconditions(self):
        """Test adding preconditions to code."""
        code = """
def divide(x: int, y: int) -> float:
    return x / y
"""
        decorated = self.verifier._add_contracts(
            code,
            "divide",
            preconditions=["y != 0"],
            postconditions=[]
        )
        
        assert "assert y != 0" in decorated


# =============================================================================
# Phase 2: Bounded Model Checking Tests
# =============================================================================

class TestComplexityAnalysis:
    """Test complexity analysis for bounded model checking."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier()
    
    def test_find_simple_for_loop(self):
        """Test detection of simple for loop."""
        code = """
def iterate(items):
    for item in items:
        print(item)
"""
        result = self.verifier.analyze_complexity(code)
        assert result["status"] == "analyzed"
        assert result["total_loops"] == 1
        assert result["loops"][0]["type"] == "for"
    
    def test_find_while_loop(self):
        """Test detection of while loop."""
        code = """
def countdown(n):
    while n > 0:
        n -= 1
"""
        result = self.verifier.analyze_complexity(code)
        assert result["total_loops"] == 1
        assert result["loops"][0]["type"] == "while"
    
    def test_nested_loops_depth(self):
        """Test detection of nested loop depth."""
        code = """
def matrix_ops(matrix):
    for row in matrix:
        for col in row:
            for item in col:
                print(item)
"""
        result = self.verifier.analyze_complexity(code)
        assert result["max_loop_depth"] == 3
        assert result["total_loops"] == 3
    
    def test_detect_direct_recursion(self):
        """Test detection of direct recursion."""
        code = """
def factorial(n: int) -> int:
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"""
        result = self.verifier.analyze_complexity(code)
        assert result["total_recursive_functions"] >= 1
        assert any(r["type"] == "direct" for r in result["recursions"])
    
    def test_complexity_score(self):
        """Test complexity score calculation."""
        simple_code = """
def add(x, y):
    return x + y
"""
        complex_code = """
def complex_func(items):
    for i in items:
        for j in items:
            while True:
                if i == j:
                    break
"""
        simple_result = self.verifier.analyze_complexity(simple_code)
        complex_result = self.verifier.analyze_complexity(complex_code)
        
        assert simple_result["complexity_score"] < complex_result["complexity_score"]
    
    def test_recommendation_for_complex_code(self):
        """Test that complex code gets appropriate recommendations."""
        code = """
def deeply_nested(items):
    for a in items:
        for b in items:
            for c in items:
                for d in items:
                    print(a, b, c, d)
"""
        result = self.verifier.analyze_complexity(code)
        assert result["recommendation"]["risk_level"] in ["medium", "high"]


class TestBoundedVerification:
    """Test bounded model checking verification."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier()
    
    def test_verify_bounded_returns_bounds_info(self):
        """Test that verify_bounded includes bounds information."""
        code = """
def simple(x: int) -> int:
    return x + 1
"""
        result = self.verifier.verify_bounded(code, loop_bound=5, recursion_depth=3)
        assert "bounded" in result
        assert result["bounded"] == True
        assert "bounds_applied" in result
        assert result["bounds_applied"]["loop_bound"] == 5
        assert result["bounds_applied"]["recursion_depth"] == 3
    
    def test_verify_bounded_syntax_error(self):
        """Test bounded verification handles syntax errors."""
        code = """
def broken(
"""
        result = self.verifier.verify_bounded(code)
        assert result["status"] == "syntax_error"
    
    def test_add_bounds_transforms_code(self):
        """Test that _add_bounds_to_code transforms functions."""
        code = """
def recursive_func(n: int) -> int:
    return recursive_func(n - 1)
"""
        bounded = self.verifier._add_bounds_to_code(code, loop_bound=10, recursion_depth=5)
        assert "_qwed_depth" in bounded


class TestVerificationBudget:
    """Test verification budget calculation."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier()
    
    def test_simple_code_feasible(self):
        """Test that simple code is marked as feasible."""
        code = """
def add(x, y):
    return x + y
"""
        result = self.verifier.get_verification_budget(code)
        assert result["feasible"] == True
    
    def test_complex_code_path_explosion(self):
        """Test that complex code triggers path explosion warning."""
        code = """
def explosion(items):
    for a in items:
        for b in items:
            for c in items:
                for d in items:
                    for e in items:
                        print(a, b, c, d, e)
"""
        result = self.verifier.get_verification_budget(code, max_paths=100)
        assert result["feasible"] == False
        assert "path explosion" in result["message"].lower() or result["estimated_paths"] > 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
