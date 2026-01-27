"""
Simple unit test for QWEDLocal (no external dependencies).

Tests the basic structure without actually calling LLMs.
"""

import sys
sys.path.insert(0, ".")

from qwed_sdk.qwed_local import QWEDLocal, VerificationResult

def test_initialization():
    """Test QWEDLocal can be initialized."""
    print("Test 1: Initialization")
    
    # This should work (simulating Ollama)
    client = QWEDLocal(
        base_url="http://localhost:11434/v1",
        model="llama3"
    )
    print("  ✅ Ollama-style initialization SUCCESS")
    
    # Check client properties
    assert client.base_url == "http://localhost:11434/v1"
    assert client.model == "llama3"
    assert client.client_type == "openai"
    print("  ✅ Client properties correct")

def test_verification_result():
    """Test VerificationResult dataclass."""
    print("\nTest 2: VerificationResult")
    
    result = VerificationResult(
        verified=True,
        value=4,
        confidence=1.0,
        evidence={"method": "test"}
    )
    
    assert result.verified is True
    assert result.value == 4
    assert result.confidence == 1.0
    assert result.evidence["method"] == "test"
    print("  ✅ VerificationResult works")

def test_provider_validation():
    """Test that invalid providers are rejected."""
    print("\nTest 3: Provider Validation")
    
    with pytest.raises(ValueError):
        # Should fail - no provider or base_url
        QWEDLocal(model="test")
        print("  ❌ Should have raised ValueError")
    
    print("  ✅ Correctly rejected invalid config")

if __name__ == "__main__":
    # If run as script, just call functions (but pytest will handle them otherwise)
    try:
        test_initialization()
        test_verification_result()
        test_provider_validation()
        print("\n✅ All tests PASSED!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
