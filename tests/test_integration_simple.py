"""
Integration Tests - End-to-End Workflows

Tests complete verification pipelines from user query to verified output.
These tests demonstrate real-world usage patterns.
"""

import pytest
from qwed_sdk import QWEDClient


@pytest.fixture
def client():
    """Initialize QWED client with mock provider for testing"""
    return QWEDClient(provider="mock")


# ============================================================================
# Full Pipeline Tests
# ============================================================================

def test_full_pipeline_math_correct(client):
    """
    End-to-end test: User query → LLM generates correct answer → QWED verifies
    
    Workflow:
    1. User asks math question
    2. LLM provides correct answer
    3. QWED verifies and approves
    """
    query = "What is 2+2?"
    llm_output = "2+2 equals 4"
    
    result = client.verify_math_claim(llm_output)
    
    assert result["verified"] == True, "Should verify correct math"
    assert result["value"] == 4, "Should return correct computed value"


def test_full_pipeline_math_hallucination(client):
    """
    End-to-end test: User query → LLM hallucinates → QWED catches error
    
    Workflow:
    1. User asks math question
    2. LLM provides incorrect answer (hallucination)
    3. QWED detects error and provides correct answer
    """
    query = "What is 2+2?"
    llm_output = "2+2 equals 5"  # Hallucination
    
    result = client.verify_math_claim(llm_output)
    
    assert result["verified"] == False, "Should detect hallucination"
    assert result["value"] == 4, "Should provide correct answer"
    assert "explanation" in result, "Should explain the error"


def test_full_pipeline_code_valid(client):
    """
    End-to-end test: User requests code → LLM generates valid code → QWED verifies
    
    Workflow:
    1. User asks for Python code
    2. LLM generates syntactically valid code
    3. QWED verifies syntax and security
    """
    code = """
def add(a, b):
    return a + b

result = add(2, 2)
print(result)
"""
    
    result = client.verify_code(code, language="python")
    
    assert result["verified"] == True, "Should verify valid Python code"
    assert "syntax" in result["explanation"].lower() or \
           "valid" in result["explanation"].lower(), \
        "Should confirm code validity"


def test_full_pipeline_code_invalid(client):
    """
    End-to-end test: User requests code → LLM generates invalid code → QWED catches
    
    Workflow:
    1. User asks for Python code
    2. LLM generates code with syntax error
    3. QWED detects and explains error
    """
    code = """
def add(a, b)  # Missing colon
    return a + b
"""
    
    result = client.verify_code(code, language="python")
    
    assert result["verified"] == False, "Should detect syntax error"
    assert "syntax" in result["explanation"].lower(), \
        "Should explain syntax error"


# ============================================================================
# PII Masking Integration Tests
# ============================================================================

def test_pii_masking_roundtrip(client):
    """
    End-to-end test: PII masking workflow
    
    Workflow:
    1. User input contains PII (SSN)
    2. QWED masks PII before sending to LLM
    3. LLM processes masked text
    4. QWED unmasks in final output
    5. Verification confirms PII was protected
    """
    text_with_pii = "My SSN is 123-45-6789"
    
    result = client.verify_with_pii_masking(text_with_pii, engine="math")
    
    # PII should not appear in LLM input
    assert "123-45-6789" not in result["llm_input"], \
        "PII should be masked before LLM"
    
    # PII should be detected
    assert result["pii_detected"] == True, \
        "Should detect PII in input"
    
    # Should list detected entity types
    assert "entities" in result, \
        "Should report detected PII entities"


# ============================================================================
# Multi-Engine Integration Tests
# ============================================================================

def test_multi_engine_verification(client):
    """
    End-to-end test: Query requires multiple verification engines
    
    Workflow:
    1. User query requires both math AND fact verification
    2. QWED automatically routes to multiple engines
    3. Both verifications must pass for overall approval
    """
    query = "Calculate average GDP: USA=$25T, China=$17T, India=$3T"
    
    # This requires:
    # - Math engine (for average calculation)
    # - Fact engine (for GDP figures verification against source)
    
    result = client.verify(
        query,
        engines=["math", "facts"],
        source_data={"USA": 25, "China": 17, "India": 3}
    )
    
    # Should use both engines
    assert "math" in result["engines_used"], \
        "Should use math engine for averaging"
    assert "facts" in result["engines_used"] or "fact" in result["engines_used"], \
        "Should use fact engine for data verification"


# ============================================================================
# Error Recovery Integration Tests
# ============================================================================

def test_verification_with_fallback(client):
    """
    End-to-end test: Verification fails → Fallback value used
    
    Workflow:
    1. LLM provides unverifiable output
    2. QWED verification fails
    3. System returns predefined fallback value
    4. User is notified of fallback usage
    """
    unverifiable_claim = "The answer is unknowable"
    fallback_value = "Unable to verify"
    
    result = client.verify_math_claim(
        unverifiable_claim,
        fallback=fallback_value
    )
    
    assert result["verified"] == False, \
        "Should fail to verify unknowable claim"
    assert result.get("fallback_used") == True or \
           result.get("value") == fallback_value, \
        "Should use fallback value"


# ============================================================================
# Batch Verification Integration Tests
# ============================================================================

@pytest.mark.parametrize("claim,expected_verified", [
    ("2+2=4", True),
    ("2+2=5", False),
    ("10-5=5", True),
    ("10-5=3", False),
])
def test_batch_verification(client, claim, expected_verified):
    """
    Integration test: Batch processing multiple claims
    
    Tests that QWED can efficiently verify multiple claims
    and return correct results for each.
    """
    result = client.verify_math_claim(claim)
    assert result["verified"] == expected_verified, \
        f"Verification failed for claim: {claim}"


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
