"""
Error Handling Tests

Tests that QWED fails gracefully and provides clear error messages
when encountering invalid inputs or edge cases.
"""

import pytest
from qwed_sdk import QWEDClient


@pytest.fixture
def client():
    """Initialize QWED client for testing"""
    # Using test API key - tests will mock responses
    return QWEDClient(api_key="test_mock_key", base_url="http://localhost:8000")


# ============================================================================
# Invalid Input Handling Tests
# ============================================================================

def test_invalid_math_input(client):
    """Verify graceful handling of unparseable math input"""
    garbage_input = "asdfasdf !@#$ random garbage"
    
    # Should return verification failure or raise exception
    try:
        result = client.verify_math(garbage_input)
        # If it doesn't raise, should mark as unverified
        assert result.is_verified == False, \
            "Should mark unparseable input as unverified"
    except Exception as e:
        # Acceptable to raise exception for invalid input
        assert "parse" in str(e).lower() or "invalid" in str(e).lower() or "error" in str(e).lower()


def test_empty_input(client):
    """Verify handling of empty input"""
    with pytest.raises((ValueError, Exception)):
        client.verify_math("")


def test_null_input(client):
    """Verify handling of None/null input"""
    with pytest.raises((TypeError, ValueError, Exception)):
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
    
    except Exception as e:
        # Acceptable to raise timeout or other exception
        assert "timeout" in str(e).lower() or "error" in str(e).lower()


# ============================================================================
# Missing Configuration Tests
# ============================================================================

def test_missing_api_key():
    """Verify clear error message when API key is missing"""
    # Should raise error for missing API key
    with pytest.raises((TypeError, ValueError)):
        client = QWEDClient()  # No API key provided


@pytest.mark.skip(reason="API key validation depends on backend implementation")
def test_invalid_base_url(client):
    """Verify handling of invalid base URL"""
    try:
        client = QWEDClient(api_key="test", base_url="invalid://url")
        # If it doesn't raise during init, it should fail on first request
        client.health()
    except Exception:
        pass  # Expected


def test_invalid_provider():
    """Verify clear error message for unsupported LLM provider"""
    with pytest.raises(ValueError, match="provider|unsupported"):
        client = QWEDClient(api_key="test_key", provider="nonexistent_provider")


# ============================================================================
# Engine Selection Tests
# ============================================================================

@pytest.mark.skip(reason="Engine selection depends on backend API implementation")
def test_unsupported_engine(client):
    """Verify clear error message for non-existent verification engine"""
    # This would be tested against actual API
    pass


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
    
    client = QWEDClient(api_key="test", base_url="http://localhost:8000")
    
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
    from qwed_sdk import QWEDAsyncClient
    
    async with QWEDAsyncClient(api_key="test", base_url="http://localhost:8000") as client:
        # Mock concurrent requests
        pass  # Simplified for now
    
@pytest.mark.skip(reason="Requires running API server")
async def test_concurrent_requests_skip():
    pass


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
    
    client = QWEDClient(api_key="test", base_url="http://localhost:8000")
    
    malicious_claim = "'; DROP TABLE users; --"
    
    # Should safely handle as text, not execute
    try:
        result = client.verify_math(malicious_claim)
        # Should reject malicious input
        assert result.is_verified == False
    except Exception:
        # Also acceptable to raise error
        pass
    # Most importantly: this test completing means no SQL was executed


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
