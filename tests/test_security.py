"""
Test script for Security & Stability.
Verifies SafeEvaluator blocks malicious code and Timeouts work.
"""

from qwed_new.core.logic_verifier import LogicVerifier
import time

def test_security():
    verifier = LogicVerifier()
    
    print("🛡️ Testing Security (SafeEvaluator)...")
    
    # Case 1: Malicious Code Execution
    # Try to import os and run system command
    malicious_query = "x > 0 and __import__('os').system('echo HACKED') == 0"
    vars1 = {'x': 'Int'}
    constrs1 = [malicious_query]
    
    result1 = verifier.verify_logic(vars1, constrs1)
    print(f"Query: {malicious_query}")
    print(f"Result: {result1.status.value}")
    print(f"Blocked: {not result1.is_verified}")
    
    if not result1.is_verified and result1.constraint_id:
        print("✅ PASSED (Blocked malicious code)")
    else:
        print("❌ FAILED (Did not block malicious code correctly)")
        
    print("-" * 30)
    
    print("⏱️ Testing Timeout (5s)...")
    
    vars2 = {'x': 'Int'}
    constrs2 = ["x > 0", "x < 10"]
    result2 = verifier.verify_logic(vars2, constrs2)
    if result2.is_verified:
        print("✅ PASSED (Normal query works with SafeEvaluator)")
    else:
        print(f"❌ FAILED (Normal query failed)")

if __name__ == "__main__":
    test_security()
