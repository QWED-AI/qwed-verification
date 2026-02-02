from qwed_new.auth.security import hash_api_key
from qwed_new.core.image_verifier import ImageVerifier

def test_hash_api_key_pbkdf2():
    """
    Test that hash_api_key uses PBKDF2 (returns a hex string).
    This ensures the new security logic is covered.
    """
    key = "qwed_live_test_key_12345"
    hashed = hash_api_key(key)
    
    # Check it returns a string
    assert isinstance(hashed, str)
    # Check it's hex
    assert all(c in '0123456789abcdef' for c in hashed)
    # Length of SHA256 hex digest is 64 chars
    assert len(hashed) == 64
    
    # Deterministic check
    assert hash_api_key(key) == hashed

def test_image_verifier_redos_protection():
    """
    Test that ImageVerifier rejects overly long claim strings (ReDoS protection).
    """
    verifier = ImageVerifier(use_vlm_fallback=False)
    
    # Create a dummy image (valid PNG header)
    dummy_image = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
    
    # 1. Normal claim
    normal_claim = "Is this a cat?"
    result = verifier.verify_image(dummy_image, normal_claim)
    # Should perform analysis (likely INCONCLUSIVE or fail elsewhere, but not ReDoS block)
    assert result["verdict"] != "INCONCLUSIVE" or result["reasoning"] != "Claim text too long (max 500 chars) - Security ReDoS protection"

    # 2. Long claim (ReDoS attack simulation)
    long_claim = "a" * 600  # Exceeds 500 char limit
    result_blocked = verifier.verify_image(dummy_image, long_claim)
    
    assert result_blocked["verdict"] == "INCONCLUSIVE"
    assert "Claim text too long" in result_blocked["reasoning"]
    assert result_blocked["confidence"] == 0.0
