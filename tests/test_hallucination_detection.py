"""
Hallucination Detection Tests

Tests QWED's primary capability: detecting when LLMs generate incorrect outputs
across multiple domains (math, code, facts, logic, statistics).
"""

import pytest
from qwed_sdk import QWEDClient


@pytest.fixture
def client():
    """Initialize QWED client with mock provider for testing"""
    return QWEDClient(provider="mock")


# ============================================================================
# Math Hallucination Tests
# ============================================================================

def test_math_hallucination_simple(client):
    """Verify QWED catches simple arithmetic hallucinations"""
    result = client.verify_math_claim("2+2=5")
    assert result["verified"] == False, "Should detect incorrect arithmetic"
    assert "4" in result["explanation"], "Should provide correct answer"


def test_derivative_hallucination(client):
    """Verify QWED catches incorrect derivative calculations"""
    result = client.verify_math_claim("The derivative of x² is 3x")
    assert result["verified"] == False, "Should detect incorrect derivative"
    assert "2*x" in result["explanation"] or "2x" in result["explanation"], \
        "Should provide correct derivative"


def test_integral_hallucination(client):
    """Verify QWED catches incorrect integral calculations"""
    result = client.verify_math_claim("The integral of sin(x) is sin(x)")
    assert result["verified"] == False, "Should detect incorrect integral"


# ============================================================================
# Code Hallucination Tests
# ============================================================================

def test_code_syntax_hallucination(client):
    """Verify QWED catches syntax errors in generated code"""
    code = "print('hello"  # Missing closing quote
    result = client.verify_code(code, language="python")
    assert result["verified"] == False, "Should detect syntax error"
    assert "syntax" in result["explanation"].lower(), \
        "Should explain syntax error"


def test_sql_injection_hallucination(client):
    """Verify QWED catches SQL injection vulnerabilities"""
    # Dangerous SQL with string concatenation
    sql = "SELECT * FROM users WHERE id = '{}'"
    result = client.verify_sql(sql)
    assert result["verified"] == False, "Should detect SQL injection risk"
    assert "injection" in result["explanation"].lower() or \
           "unsafe" in result["explanation"].lower(), \
        "Should explain security risk"


# ============================================================================
# Fact Hallucination Tests
# ============================================================================

def test_fact_mismatch_hallucination(client):
    """Verify QWED catches factual mismatches against source documents"""
    claim = "The Earth is flat"
    source = "The Earth is an oblate spheroid, slightly flattened at the poles"
    result = client.verify_fact(claim=claim, source=source)
    assert result["verified"] == False, \
        "Should detect factual mismatch"


# ============================================================================
# Logic Hallucination Tests
# ============================================================================

def test_logic_fallacy_hallucination(client):
    """Verify QWED catches logical fallacies"""
    # Invalid logic: affirming the consequent
    premise1 = "All humans are mortal"
    premise2 = "Socrates is mortal"
    conclusion = "Therefore, Socrates is human"  # Invalid!
    
    result = client.verify_logic(
        premises=[premise1, premise2],
        conclusion=conclusion
    )
    assert result["verified"] == False, \
        "Should detect invalid logical inference"


# ============================================================================
# Statistics Hallucination Tests
# ============================================================================

def test_stats_calculation_hallucination(client):
    """Verify QWED catches incorrect statistical calculations"""
    data = [1, 2, 3, 4, 5]
    claim = "The mean of this dataset is 4"  # Actual mean is 3
    result = client.verify_stats(data=data, claim=claim)
    assert result["verified"] == False, \
        "Should detect incorrect mean calculation"
    assert "3" in str(result["value"]), \
        "Should provide correct mean value"


# ============================================================================
# Complex Hallucination Tests
# ============================================================================

@pytest.mark.parametrize("expression,wrong_answer", [
    ("derivative of x**3", "2*x**2"),  # Should be 3*x**2
    ("integral of 2*x", "2*x**2"),     # Should be x**2
    ("solve x**2 - 4 = 0", "x = 3"),   # Should be x = ±2
])
def test_parametrized_math_hallucinations(client, expression, wrong_answer):
    """Test multiple math hallucinations with parametrization"""
    result = client.verify_math_claim(f"{expression} equals {wrong_answer}")
    assert result["verified"] == False, \
        f"Should detect incorrect answer for {expression}"


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
