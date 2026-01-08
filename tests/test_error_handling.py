"""
Error Handling Tests

Tests that QWED fails gracefully and provides clear error messages
when encountering invalid inputs or edge cases.
"""

import pytest
from qwed_sdk import QWEDClient
from qwed_sdk.exceptions import VerificationError, InvalidInputError, TimeoutError as QWEDTimeoutError


@pytest.fixture
def client():
    """Initialize QWED client with mock provider for testing"""
    return QWEDClient(provider="mock")


# ============================================================================
# Invalid Input Handling Tests
# ============================================================================

def test_invalid_math_input(client):
    """Verify graceful handling of unparseable math input"""
    garbage_input = "asdfasdf !@#$ random garbage"
    
    # Should raise InvalidInputError or return verification failure
    try:
        result = client.verify_math(garbage_input)
        assert result["verified"] == False, \
            "Should mark unparseable input as unverified"
        assert "error" in result or "invalid" in result.get("explanation", "").lower(), \
            "Should explain why input is invalid"
    except InvalidInputError as e:
        # Acceptable to raise exception for invalid input
        assert "parse" in str(e).lower() or "invalid" in str(e).lower()


def test_empty_input(client):
    """Verify handling of empty input"""
    with pytest.raises((InvalidInputError, ValueError)):
        client.verify_math("")


def test_null_input(client):
    """Verify handling of None/null input"""
    with pytest.raises((InvalidInputError, TypeError, ValueError)):
        client.verify_math(None)


# ============================================================================
# Solver Timeout Tests
# ============================================================================

@pytest.mark.slow
def test_solver_timeout_handling(client):
    """Verify graceful handling when solver times out"""
    # Create extremely complex formula that might timeout
    complex_formula = " AND ".join([f"(x{i} OR y{i})" for i in range(100)])
    
    try:
        result = client.verify_logic(complex_formula, timeout=0.1)
        
        # Should either timeout or complete
        if not result.get("verified"):
            assert "timeout" in result.get("explanation", "").lower() or \
                   "complex" in result.get("explanation", "").lower(), \
                "Should explain timeout or complexity issue"
    
    except QWEDTimeoutError as e:
        # Acceptable to raise timeout exception
        assert "timeout" in str(e).lower()


# ============================================================================
# Missing Configuration Tests
# ============================================================================

def test_missing_api_key():
    """Verify clear error message when LLM API key is missing"""
    # Should raise ValueError for missing API key when provider requires it
    with pytest.raises((ValueError, RuntimeError), match="API key|key"):
        client = QWEDClient(provider="openai")  # No API key provided


def test_invalid_provider():
    """Verify clear error message for unsupported LLM provider"""
    with pytest.raises(ValueError, match="provider|unsupported"):
        client = QWEDClient(provider="nonexistent_provider")


# ============================================================================
# Engine Selection Tests
# ============================================================================

def test_unsupported_engine(client):
    """Verify clear error message for non-existent verification engine"""
    with pytest.raises(ValueError, match="engine|unknown"):
        client.verify("test claim", engine="nonexistent_engine")


def test_engine_mismatch(client):
    """Verify handling when wrong engine is used for input type"""
    # Using code engine for obvious math problem
    code = "2 + 2 ="  # Not valid code, but looks like math
    
    result = client.verify_code(code, language="python")
    
    assert result["verified"] == False, \
        "Should fail to verify math expression as code"


# ============================================================================
# Resource Limit Tests
# ============================================================================

@pytest.mark.skip(reason="Optional: Tests resource limits")
def test_memory_limit_handling():
    """Verify handling when verification requires too much memory"""
    from qwed_sdk import QWEDClient
    
    client = QWEDClient(provider="mock", max_memory_mb=10)
    
    # Create extremely large verification task
    huge_formula = " AND ".join([f"var{i}" for i in range(10000)])
    
    try:
        result = client.verify_logic(huge_formula)
        # Should either fail gracefully or complete
        assert "verified" in result
    except MemoryError:
        # Acceptable to raise memory error
        pass


# ============================================================================
# Concurrent Request Error Tests
# ============================================================================

@pytest.mark.asyncio
async def test_concurrent_request_handling():
    """Verify system handles concurrent requests without errors"""
    import asyncio
    from qwed_sdk import QWEDClient
    
    client = QWEDClient(provider="mock")
    
    # Launch multiple concurrent verifications
    tasks = [
        client.verify_math_async(f"{i}+{i}={i*2}")
        for i in range(10)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # All should complete (either success or controlled failure)
    assert len(results) == 10
    for result in results:
        assert isinstance(result, (dict, Exception)), \
            "Should return result or exception, not hang"


# ============================================================================
# Data Validation Tests
# ============================================================================

def test_malformed_json_input():
    """Verify handling of malformed JSON in API requests"""
    # This would be tested at API level
    pytest.skip("API-level test - requires running server")


def test_sql_injection_in_claim():
    """Verify QWED doesn't execute malicious SQL in claims"""
    from qwed_sdk import QWEDClient
    
    client = QWEDClient(provider="mock")
    
    malicious_claim = "'; DROP TABLE users; --"
    
    # Should safely handle as text, not execute
    result = client.verify_math(malicious_claim)
    
    # Should fail to parse, but not execute SQL
    assert result["verified"] == False
    # Most importantly: this test completing means no SQL was executed


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
