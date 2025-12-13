"""
Local Adversarial Logic Verification Runner.

Runs the adversarial logic tests directly against the local DSL pipeline
(DSLLogicVerifier), bypassing the API and remote VM.

This validates that the new DSL implementation can handle the complex
logic puzzles designed to break LLMs.
"""

import sys
import os
import json
from datetime import datetime

# Add src and root to path to allow importing modules
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, '../../'))
src_dir = os.path.join(root_dir, 'src')

sys.path.insert(0, root_dir)  # For benchmarks import
sys.path.insert(0, src_dir)   # For qwed_new import

from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
try:
    from benchmarks.deep_suite.adversarial_logic_tests import ADVERSARIAL_LOGIC_TESTS
except ImportError:
    # Fallback if running from root
    from deep_suite.adversarial_logic_tests import ADVERSARIAL_LOGIC_TESTS

def run_verification():
    print(f"\n{'='*80}")
    print(f"ADVERSARIAL DSL VERIFICATION (LOCAL)")
    print(f"Testing {len(ADVERSARIAL_LOGIC_TESTS)} complex logic puzzles against QWED-DSL")
    print(f"{'='*80}\n")
    
    verifier = DSLLogicVerifier()
    results = []
    
    for i, test in enumerate(ADVERSARIAL_LOGIC_TESTS):
        print(f"Test {i+1}/{len(ADVERSARIAL_LOGIC_TESTS)}: {test['id']}")
        print(f"Query: {test['query'][:100]}...")
        
        try:
            # Run verification through the DSL pipeline
            # This triggers: LLM -> DSL -> Parser -> Validator -> Compiler -> Z3
            result = verifier.verify_from_natural_language(test['query'])
            
            # Analyze result
            # DSLVerificationResult is a dataclass, so use attribute access
            status = result.status
            dsl_code = result.dsl_code if result.dsl_code else 'N/A'
            error = result.error
            
            print(f"Status: {status}")
            if dsl_code != 'N/A':
                print(f"DSL: {dsl_code}")
            
            # success means the pipeline ran without crashing and produced a result
            # Ideally verification passes (SAT) or correctly identifies contradiction (UNSAT)
            success = status in ['SAT', 'UNSAT', 'SUCCESS']
            
            results.append({
                "id": test['id'],
                "status": status,
                "dsl": dsl_code,
                "success": success,
                "error": error
            })
            
        except Exception as e:
            print(f"CRASH: {str(e)}")
            results.append({
                "id": test['id'],
                "status": "CRASH",
                "success": False,
                "error": str(e)
            })
        print("-" * 40)

    # Summary
    successful = sum(1 for r in results if r['success'])
    print(f"\n{'='*80}")
    print(f"SUMMARY")
    print(f"Total Tests: {len(results)}")
    print(f"Pipeline Success: {successful}/{len(results)} ({successful/len(results)*100:.1f}%)")
    print(f"{'='*80}")
    
    # Check for specific failures
    crashes = [r for r in results if r['status'] == 'CRASH']
    if crashes:
        print(f"\nCRASHES ({len(crashes)}):")
        for c in crashes:
            print(f"- {c['id']}: {c['error']}")
            
if __name__ == "__main__":
    run_verification()
