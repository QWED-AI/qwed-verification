from qwed_sdk.guards.sovereignty_guard import SovereigntyGuard

def test_sovereignty_guard_allows_safe_data_to_external():
    guard = SovereigntyGuard()
    result = guard.verify_routing(prompt="What is the capital of France?", target_provider="openai")
    
    assert result["verified"] is True

def test_sovereignty_guard_blocks_sensitive_data_to_external():
    guard = SovereigntyGuard()
    prompt = "Here is the CONFIDENTIAL contract for our new client."
    result = guard.verify_routing(prompt=prompt, target_provider="openai")
    
    assert result["verified"] is False
    assert result["risk"] == "DATA_SOVEREIGNTY_VIOLATION"

def test_sovereignty_guard_blocks_ssn_to_external():
    guard = SovereigntyGuard()
    prompt = "My SSN is 123-45-6789. Please process my application."
    result = guard.verify_routing(prompt=prompt, target_provider="anthropic")
    
    assert result["verified"] is False
    assert result["risk"] == "DATA_SOVEREIGNTY_VIOLATION"

def test_sovereignty_guard_allows_sensitive_data_to_local():
    guard = SovereigntyGuard()
    prompt = "Here is the CONFIDENTIAL contract. SSN: 123-45-6789."
    # Ollama is in the default local_providers list
    result = guard.verify_routing(prompt=prompt, target_provider="ollama")
    
    assert result["verified"] is True
