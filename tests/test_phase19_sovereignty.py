from qwed_sdk.guards.sovereignty_guard import SovereigntyGuard

def test_sovereignty_guard_allows_safe_data_to_external():
    guard = SovereigntyGuard()
    result = guard.verify_routing(prompt="What is the capital of France?", target_provider="openai")
    
    assert result["verified"] is True
    assert result["risk"] is None
    assert "message" in result

def test_sovereignty_guard_blocks_sensitive_data_to_external():
    guard = SovereigntyGuard()
    prompt = "Here is the CONFIDENTIAL contract for our new client."
    result = guard.verify_routing(prompt=prompt, target_provider="openai")
    
    assert result["verified"] is False
    assert result["risk"] == "DATA_SOVEREIGNTY_VIOLATION"
    assert "message" in result

def test_sovereignty_guard_blocks_ssn_to_external():
    guard = SovereigntyGuard()
    prompt = "My SSN is 123-45-6789. Please process my application."
    result = guard.verify_routing(prompt=prompt, target_provider="anthropic")
    
    assert result["verified"] is False
    assert result["risk"] == "DATA_SOVEREIGNTY_VIOLATION"
    assert "message" in result

def test_sovereignty_guard_allows_sensitive_data_to_local():
    guard = SovereigntyGuard()
    prompt = "Here is the CONFIDENTIAL contract. SSN: 123-45-6789."
    # Ollama is in the default local_providers list
    result = guard.verify_routing(prompt=prompt, target_provider="ollama")
    
    assert result["verified"] is True
    assert result["risk"] is None
    assert "message" in result

def test_sovereignty_guard_blocks_space_separated_ssn_to_external():
    guard = SovereigntyGuard()
    prompt = "My SSN is 123 45 6789. Please process my application."
    result = guard.verify_routing(prompt=prompt, target_provider="anthropic")
    
    assert result["verified"] is False
    assert result["risk"] == "DATA_SOVEREIGNTY_VIOLATION"
    assert "message" in result

def test_sovereignty_guard_blocks_contiguous_ssn_to_external():
    guard = SovereigntyGuard()
    prompt = "SSN: 123456789"
    result = guard.verify_routing(prompt=prompt, target_provider="openai")
    
    assert result["verified"] is False
    assert result["risk"] == "DATA_SOVEREIGNTY_VIOLATION"
    assert "message" in result

def test_sovereignty_guard_allows_vllm_local():
    guard = SovereigntyGuard()
    prompt = "Here is the CONFIDENTIAL contract. SSN: 123-45-6789."
    result = guard.verify_routing(prompt=prompt, target_provider="vllm_local")
    
    assert result["verified"] is True
    assert result["risk"] is None
    assert "message" in result

def test_sovereignty_guard_case_insensitive_provider():
    guard = SovereigntyGuard()
    prompt = "Here is the CONFIDENTIAL contract. SSN: 123-45-6789."
    result = guard.verify_routing(prompt=prompt, target_provider="OLLAMA")
    
    assert result["verified"] is True
    assert result["risk"] is None
    assert "message" in result

def test_sovereignty_guard_custom_local_provider():
    guard = SovereigntyGuard(required_local_providers=["my_local_llm"])
    prompt = "Here is the CONFIDENTIAL contract. SSN: 123-45-6789."
    
    # Allowed local provider
    result_local = guard.verify_routing(prompt=prompt, target_provider="my_local_llm")
    assert result_local["verified"] is True
    assert "message" in result_local
    
    # Default 'ollama' is now external since required_local_providers overrode it
    result_external = guard.verify_routing(prompt=prompt, target_provider="ollama")
    assert result_external["verified"] is False
    assert result_external["risk"] == "DATA_SOVEREIGNTY_VIOLATION"
    assert "message" in result_external

import pytest

def test_sovereignty_guard_raises_on_empty_prompt():
    guard = SovereigntyGuard()
    with pytest.raises(ValueError, match="prompt must be a non-empty string"):
        guard.verify_routing(prompt="", target_provider="ollama")
        
    with pytest.raises(ValueError, match="prompt must be a non-empty string"):
        guard.verify_routing(prompt=None, target_provider="ollama")

def test_sovereignty_guard_raises_on_empty_provider():
    guard = SovereigntyGuard()
    with pytest.raises(ValueError, match="target_provider must be a non-empty string"):
        guard.verify_routing(prompt="Valid prompt", target_provider="")
        
    with pytest.raises(ValueError, match="target_provider must be a non-empty string"):
        guard.verify_routing(prompt="Valid prompt", target_provider=None)
