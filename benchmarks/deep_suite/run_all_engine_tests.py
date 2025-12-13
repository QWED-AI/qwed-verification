"""
Run All Engine Tests - Complete Test Suite
Runs all 61 new engine tests (Fact, Code, SQL, Stats, Reasoning)
"""

import subprocess
import sys

PYTHON_PATH = r"C:\Users\rahul\AppData\Local\Programs\Python\Python311\python.exe"

TESTS = [
    ("Fact Engine", "fact_engine_tests.py"),
    ("Code Engine", "code_engine_tests.py"),
    ("SQL Engine", "sql_engine_tests.py"),
    ("Stats Engine", "stats_engine_tests.py"),
    ("Reasoning Engine", "reasoning_engine_tests.py"),
]

def run_all_tests():
    print("="*80)
    print("RUNNING ALL ENGINE TESTS")
    print("="*80)
    print()
    
    results = {}
    
    for name, script in TESTS:
        print(f"\n{'#'*80}")
        print(f"# Running: {name}")
        print(f"{'#'*80}\n")
        
        try:
            result = subprocess.run(
                [PYTHON_PATH, script],
                capture_output=True,
                text=True,
                timeout=600  # 10 min timeout per test
            )
            
            results[name] = {
                "success": result.returncode == 0,
                "output": result.stdout
            }
            
            print(result.stdout)
            
            if result.returncode != 0:
                print(f"\n❌ {name} FAILED")
                print(result.stderr)
            else:
                print(f"\n✅ {name} COMPLETED")
                
        except Exception as e:
            print(f"\n❌ {name} ERROR: {e}")
            results[name] = {
                "success": False,
                "error": str(e)
            }
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    for name, result in results.items():
        status = "✅ PASS" if result.get("success") else "❌ FAIL"
        print(f"{status} - {name}")
    
    print("\n" + "="*80)
    print("ALL TESTS COMPLETED!")
    print("="*80)

if __name__ == "__main__":
    run_all_tests()
