"""
Tests for SymbolicVerifier - CrossHair Integration.

These tests verify the symbolic execution engine works correctly.
"""

import pytest
import sys
import os

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


class TestCodeVerification:
    """Test code verification with CrossHair."""
    
    def setup_method(self):
        self.verifier = SymbolicVerifier(timeout_seconds=5)
    
    def test_verify_no_functions(self):
        """Test verification of code with no functions."""
        code = """
x = 1 + 2
print(x)
"""
        result = self.verifier.verify_code(code)
        assert result["status"] == "no_functions_to_check"
    
    def test_verify_syntax_error(self):
        """Test verification handles syntax errors."""
        code = """
def broken(
"""
        result = self.verifier.verify_code(code)
        assert result["status"] == "syntax_error"
    
    @pytest.mark.skipif(
        not SymbolicVerifier()._crosshair_available,
        reason="CrossHair not installed"
    )
    def test_verify_simple_function(self):
        """Test verification of simple typed function."""
        code = """
def add(x: int, y: int) -> int:
    return x + y
"""
        result = self.verifier.verify_code(code)
        # Simple addition should verify
        assert result["functions_checked"] > 0


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
