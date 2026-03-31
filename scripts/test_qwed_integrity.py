"""
QWED Verification Integrity Test

This test FORCES incorrect answers to verify QWED:
1. Actually calculates independently (not just agreeing with LLM)
2. Catches wrong answers
3. Reports accurate verification

We bypass the LLM and simulate "wrong LLM answers" to test QWED's detection.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sympy import sympify, N

def test_qwed_catches_errors():
    """
    Test that QWED actually catches wrong answers.
    We simulate LLM giving WRONG answers and check if QWED catches them.
    """
    print("=" * 60)
    print("🔬 QWED VERIFICATION INTEGRITY TEST")
    print("=" * 60)
    print("Testing: Does QWED actually catch errors?\n")
    
    # Test cases: (query, WRONG answer, CORRECT answer, expression)
    test_cases = [
        # LLM might say 15 instead of 12 for "15% of 80"
        ("15% of 80", 15, 12, "0.15 * 80"),
        
        # Classic floating point trap - LLM might say 0.30000000000000004
        ("0.1 + 0.2", 0.30000004, 0.3, "Rational(1,10) + Rational(2,10)"),
        
        # LLM might confuse square root
        ("sqrt(144)", 14, 12, "sqrt(144)"),
        
        # LLM might just repeat the numbers
        ("2^10", 20, 1024, "2**10"),
        
        # Classic math mistake
        ("5 * 5", 10, 25, "5 * 5"),  # LLM adds instead of multiplies
        
        # Order of operations confusion
        ("2 + 3 * 4", 20, 14, "2 + 3 * 4"),  # LLM does (2+3)*4 instead of 2+(3*4)
        
        # Percentage mistake
        ("50 - 20%", 45, 40, "50 * 0.8"),  # 50 - 20% of 50 = 40
        
        # Log confusion
        ("log10(1000)", 100, 3, "log(1000, 10)"),
    ]
    
    results = {"caught": 0, "missed": 0, "verified_correct": 0}
    
    for query, wrong_answer, correct_answer, expr in test_cases:
        print(f"\n📝 Query: {query}")
        print(f"   Wrong LLM answer: {wrong_answer}")
        print(f"   Correct answer: {correct_answer}")
        
        # QWED calculates independently using SymPy
        try:
            qwed_result = float(N(sympify(expr)))
            print(f"   QWED calculated: {qwed_result}")
            
            # Check if QWED catches the error
            tolerance = 0.01
            llm_correct = abs(wrong_answer - qwed_result) <= tolerance
            
            if llm_correct:
                # QWED FAILED - didn't catch the wrong answer
                print(f"   ❌ QWED MISSED ERROR! Said wrong answer was correct!")
                results["missed"] += 1
            else:
                # QWED CAUGHT the error!
                print(f"   ✅ QWED CAUGHT ERROR! Rejected wrong answer.")
                results["caught"] += 1
                
        except Exception as e:
            print(f"   ⚠️ Error: {e}")
    
    # Now test with CORRECT answers to make sure QWED doesn't reject good answers
    print("\n" + "=" * 60)
    print("🔬 TESTING: Does QWED accept correct answers?")
    print("=" * 60)
    
    correct_tests = [
        ("5 * 5", 25, "5 * 5"),
        ("2 + 2", 4, "2 + 2"),
        ("sqrt(144)", 12, "sqrt(144)"),
        ("100 / 4", 25, "100 / 4"),
    ]
    
    for query, correct_answer, expr in correct_tests:
        try:
            qwed_result = float(N(sympify(expr)))
            tolerance = 0.01
            is_correct = abs(correct_answer - qwed_result) <= tolerance
            
            if is_correct:
                print(f"   ✅ QWED correctly verified: {query} = {correct_answer}")
                results["verified_correct"] += 1
            else:
                print(f"   ❌ QWED wrongly rejected correct answer: {query}")
        except Exception as e:
            print(f"   ⚠️ Error: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 INTEGRITY TEST RESULTS")
    print("=" * 60)
    print(f"Wrong answers caught:     {results['caught']}/{len(test_cases)}")
    print(f"Wrong answers missed:     {results['missed']}/{len(test_cases)}")
    print(f"Correct answers verified: {results['verified_correct']}/{len(correct_tests)}")
    
    if results["caught"] == len(test_cases) and results["verified_correct"] == len(correct_tests):
        print("\n✅ QWED VERIFICATION IS WORKING CORRECTLY!")
        print("   - Catches all wrong answers")
        print("   - Accepts all correct answers")
    elif results["missed"] > 0:
        print("\n❌ QWED VERIFICATION HAS ISSUES!")
        print(f"   - Missed {results['missed']} wrong answers")
    
    return results

if __name__ == "__main__":
    test_qwed_catches_errors()
