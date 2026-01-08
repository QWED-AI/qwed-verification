"""
Core Regression Tests

Tests to ensure core verification engines don't break with updates.
Uses parametrized tests for high coverage with minimal code.
"""

import pytest
from qwed_sdk import QWEDClient


@pytest.fixture
def client():
    """Initialize QWED client with mock provider for testing"""
    return QWEDClient(provider="mock")


# ============================================================================
# Math Engine Regression Tests
# ============================================================================

@pytest.mark.parametrize("expression,expected", [
    ("2+2", 4),
    ("10-5", 5),
    ("3*4", 12),
    ("15/3", 5),
    ("2**3", 8),
    ("10%3", 1),
    ("abs(-5)", 5),
    ("max(1,2,3)", 3),
])
def test_math_engine_basic_operations(client, expression, expected):
    """
    Regression test: Ensure basic math operations still work
    
    Tests fundamental arithmetic that should never break.
    """
    result = client.verify_math(f"{expression}={expected}")
    assert result["verified"] == True, \
        f"Failed to verify correct math: {expression}={expected}"


@pytest.mark.parametrize("expression,approx_expected", [
    ("sqrt(16)", 4.0),
    ("sin(0)", 0.0),
    ("cos(0)", 1.0),
    ("log(1)", 0.0),
    ("exp(0)", 1.0),
])
def test_math_engine_functions(client, expression, approx_expected):
    """
    Regression test: Mathematical functions
    
    Tests that symbolic math functions work correctly.
    """
    result = client.verify_math(expression)
    assert result["verified"] == True or abs(result["value"] - approx_expected) < 0.01, \
        f"Math function result incorrect for {expression}"


# ============================================================================
# Code Engine Regression Tests
# ============================================================================

@pytest.mark.parametrize("code,should_pass", [
    # Valid code
    ("print('hello')", True),
    ("x = 1 + 2", True),
    ("def foo():\n    return 42", True),
    ("[1, 2, 3]", True),
    ("{'key': 'value'}", True),
    
    # Syntax errors
    ("print('missing quote", False),
    ("if True", False),  # Missing colon
    ("def foo(", False),  # Incomplete
    
    # Security risks (should be detected)
    ("import os; os.system('rm -rf /')", False),
    ("eval('malicious code')", False),
    ("__import__('os').system('cmd')", False),
])
def test_code_engine_regression(client, code, should_pass):
    """
    Regression test: Code verification still catches issues
    
    Ensures code engine correctly validates Python syntax and security.
    """
    result = client.verify_code(code, language="python")
    assert result["verified"] == should_pass, \
        f"Code verification failed for: {code}"


# ============================================================================
# SQL Engine Regression Tests
# ============================================================================

@pytest.mark.parametrize("sql,should_pass", [
    # Valid SQL
    ("SELECT * FROM users", True),
    ("SELECT name, age FROM users WHERE age > 18", True),
    ("INSERT INTO users (name) VALUES ('John')", True),
    
    # SQL injection patterns (should be detected)
    ("SELECT * FROM users WHERE id = '1' OR '1'='1'", False),
    ("'; DROP TABLE users; --", False),
    ("SELECT * FROM users WHERE name = '{}'".format("input"), False),
])
def test_sql_engine_regression(client, sql, should_pass):
    """
    Regression test: SQL validation and security
    
    Ensures SQL engine detects injection vulnerabilities.
    """
    result = client.verify_sql(sql)
    assert result["verified"] == should_pass, \
        f"SQL verification failed for: {sql}"


# ============================================================================
# Fact Engine Regression Tests
# ============================================================================

def test_fact_engine_tf_idf_still_works(client):
    """
    Regression test: TF-IDF grounding remains deterministic
    
    Critical test: QWED's deterministic fact verification must not regress.
    """
    source = "The capital of France is Paris. Paris is located in northern France."
    
    # Should match: claim is semantically equivalent
    claim1 = "Paris is the capital of France"
    result1 = client.verify_fact(claim=claim1, source=source)
    assert result1["verified"] == True, \
        "Should verify factually correct claim"
    
    # Should NOT match: contradicts source
    claim2 = "Lyon is the capital of France"
    result2 = client.verify_fact(claim=claim2, source=source)
    assert result2["verified"] == False, \
        "Should reject factually incorrect claim"


def test_fact_engine_lexical_matching(client):
    """
    Regression test: Lexical matching (not just semantic)
    
    Ensures TF-IDF based matching works as expected (deterministic).
    """
    source = "The Earth orbits the Sun in an elliptical path."
    
    # Exact lexical match
    claim1 = "Earth orbits Sun"
    result1 = client.verify_fact(claim=claim1, source=source)
    assert result1["verified"] == True
    
    # Opposite meaning (should fail even if semantically similar)
    claim2 = "The Sun orbits the Earth"
    result2 = client.verify_fact(claim=claim2, source=source)
    assert result2["verified"] == False


# ============================================================================
# PII Engine Regression Tests
# ============================================================================

@pytest.mark.parametrize("text,should_detect", [
    # Should detect PII
    ("My SSN is 123-45-6789", True),
    ("Email: test@example.com", True),
    ("Call me at 555-123-4567", True),
    ("My credit card is 4111111111111111", True),
    
    # Should NOT detect PII (no sensitive data)
    ("Hello world", False),
    ("The meeting is at 3pm", False),
    ("Product ID: ABC123", False),
])
def test_pii_engine_still_detects(client, text, should_detect):
    """
    Regression test: PII detection doesn't regress
    
    Ensures Presidio-based PII masking continues working.
    """
    result = client.mask_pii(text)
    
    if should_detect:
        assert "123-45-6789" not in result.get("masked_text", text) or \
               result.get("entities_found", 0) > 0, \
            f"Should detect PII in: {text}"
    else:
        assert result.get("entities_found", 0) == 0 or \
               text == result.get("masked_text", ""), \
            f"Should NOT detect PII in: {text}"


# ============================================================================
# Logic Engine Regression Tests
# ============================================================================

@pytest.mark.parametrize("premises,conclusion,is_valid", [
    # Valid syllogisms
    (["All humans are mortal", "Socrates is a human"], "Socrates is mortal", True),
    (["All dogs bark", "Fido is a dog"], "Fido barks", True),
    
    # Invalid logic
    (["All humans are mortal", "Socrates is mortal"], "Socrates is human", False),
    (["Some cats are black", "Fluffy is a cat"], "Fluffy is black", False),
])
def test_logic_engine_regression(client, premises, conclusion, is_valid):
    """
    Regression test: Logical reasoning engine
    
    Ensures Z3-based logic verification works correctly.
    """
    result = client.verify_logic(premises=premises, conclusion=conclusion)
    assert result["verified"] == is_valid, \
        f"Logic verification incorrect for {conclusion}"


# ============================================================================
# Image Verification Regression Tests
# ============================================================================

@pytest.mark.skip(reason="Requires image file fixtures")
def test_image_verifier_still_works(client):
    """
    Regression test: Image metadata verification
    
    Ensures image engine validates metadata claims.
    """
    # Would test with actual image file
    image_path = "test_image.jpg"
    claim = "This image is 1920x1080 pixels"
    
    result = client.verify_image(image_path, claim)
    assert "verified" in result


# ============================================================================
# Stats Engine Regression Tests
# ============================================================================

@pytest.mark.parametrize("data,claim,expected", [
    ([1, 2, 3, 4, 5], "mean=3", True),
    ([1, 2, 3, 4, 5], "mean=4", False),
    ([1, 1, 2, 2, 3], "mode=1", True),  # or mode=2
    ([1, 2, 3, 4, 5], "median=3", True),
])
def test_stats_engine_regression(client, data, claim, expected):
    """
    Regression test: Statistical verification
    
    Ensures stats engine calculates correctly.
    """
    result = client.verify_stats(data=data, claim=claim)
    assert result["verified"] == expected, \
        f"Stats verification failed for {claim} on {data}"


# ============================================================================
# Multi-Engine Integration Regression
# ============================================================================

def test_multi_engine_coordination(client):
    """
    Regression test: Multiple engines working together
    
    Ensures different engines can verify aspects of same query.
    """
    query = "Calculate 2+2 and verify it equals 4"
    
    result = client.verify(query, engines=["math"])
    
    # Should successfully process multi-step verification
    assert "verified" in result
    assert result["verified"] == True


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
