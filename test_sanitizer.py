"""
Test script for Constraint Sanitizer.
Deliberately sends broken syntax to see if the middleware fixes it.
"""

from qwed_new.core.logic_verifier import LogicVerifier

def test_sanitizer():
    verifier = LogicVerifier()
    
    # Case 1: Assignment '=' instead of '=='
    print("🧪 Case 1: Testing '=' fix (x = 5)")
    vars1 = {'x': 'Int'}
    constrs1 = ["x = 5", "x > 0"]
    result1 = verifier.verify_logic(vars1, constrs1)
    print(f"Result: {result1.status}")
    if result1.status == "SAT":
        print("✅ PASSED (Sanitizer fixed '=')")
    else:
        print(f"❌ FAILED: {result1.error}")
    print("-" * 30)

    # Case 2: Bitwise '|' (Not implemented yet, but checking behavior)
    # We decided NOT to implement regex fix for '|' yet as it's complex.
    # But let's see what happens.
    
if __name__ == "__main__":
    test_sanitizer()
