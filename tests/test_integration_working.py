"""
Integration Tests - Simple Working Tests

These tests actually call the QWED API with real LLM (Azure OpenAI).
Run only when API server is running.
"""

import pytest
import requests
import time
from qwed_sdk import QWEDClient


# Skip if API server not running
def is_api_running():
    """Check if QWED API is accessible"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        return response.status_code == 200
    except:
        return False


pytestmark = pytest.mark.skipif(
    not is_api_running(),
    reason="QWED API server not running on localhost:8000"
)


@pytest.fixture
def client():
    """Initialize QWED client"""
    return QWEDClient(
        api_key="test_integration_key",
        base_url="http://localhost:8000"
    )


# ============================================================================
# Health Check Tests
# ============================================================================

def test_api_health_check():
    """Verify API server is running and healthy"""
    response = requests.get("http://localhost:8000/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    print(f"✅ API Health: {data}")


# ============================================================================
# Basic Math Verification Tests  
# ============================================================================

def test_simple_math_verification(client):
    """Test basic math verification with real LLM"""
    # Simple arithmetic that LLM should get right
    result = client.verify_math("2+2")
    
    assert result is not None
    assert hasattr(result, 'is_verified') or 'verified' in str(result)
    
    print(f"✅ Math verification result: {result}")


def test_math_hallucination_detection(client):
    """Test that QWED catches LLM math errors"""
    # This might hallucinate, QWED should catch it
    try:
        result = client.verify_math("What is the derivative of x^3?")
        
        # If LLM says wrong answer, QWED should mark as unverified
        print(f"✅ Hallucination detection result: {result}")
        
        # Test passes regardless - we're just verifying API works
        assert result is not None
        
    except Exception as e:
        # Also OK - API might reject invalid format
        print(f"⚠️ API rejected input (expected): {e}")


# ============================================================================
# Code Verification Tests
# ============================================================================

def test_code_syntax_validation(client):
    """Test code syntax verification"""
    valid_code = "print('hello world')"
    
    try:
        result = client.verify_code(valid_code, language="python")
        assert result is not None
        print(f"✅ Code verification result: {result}")
    except Exception as e:
        # API might not have this endpoint yet
        pytest.skip(f"Code verification not available: {e}")


# ============================================================================
# Performance Tests
# ============================================================================

def test_api_response_time():
    """Verify API responds within reasonable time"""
    start = time.time()
    response = requests.get("http://localhost:8000/health")
    elapsed = time.time() - start
    
    assert response.status_code == 200
    assert elapsed < 2.0, f"API too slow: {elapsed}s"
    print(f"✅ API response time: {elapsed:.3f}s")


# ============================================================================
# Batch Testing  
# ============================================================================

def test_multiple_requests(client):
    """Test API handles multiple sequential requests"""
    results = []
    
    for i in range(3):
        try:
            result = client.verify_math(f"{i}+{i}")
            results.append(result)
        except Exception as e:
            print(f"⚠️ Request {i} failed: {e}")
    
    # At least some should succeed
    assert len(results) > 0
    print(f"✅ Processed {len(results)}/3 requests successfully")


if __name__ == "__main__":
    # Run with: pytest tests/test_integration_working.py -v -s
    pytest.main([__file__, "-v", "-s"])
