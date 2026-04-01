"""
Quick Install Verification

Run this after installation to verify all engines work:

    python examples/verify_installation.py

Expected output: All 8 tests should pass.
"""

import sys


def check_import(module_name: str, description: str) -> bool:
    """Check if a module can be imported."""
    try:
        __import__(module_name)
        print(f"✅ {description}")
        return True
    except ImportError as e:
        print(f"❌ {description}: {e}")
        return False


def check_engine(name: str, test_func) -> bool:
    """Check if an engine works."""
    try:
        result = test_func()
        if result:
            print(f"✅ {name} Engine")
            return True
        else:
            print(f"❌ {name} Engine: Test failed")
            return False
    except Exception as e:
        print(f"❌ {name} Engine: {e}")
        return False


def test_math_engine():
    from qwed_new.core.verifier import VerificationEngine
    engine = VerificationEngine()
    result = engine.verify_math("2 + 2", expected_value=4)
    return result.get("is_correct", False)


def test_logic_engine():
    from qwed_new.core.logic_verifier import LogicVerifier
    LogicVerifier()
    # Basic test - just ensure it initializes
    return True


def test_code_engine():
    from qwed_new.core.code_verifier import CodeSecurityVerifier
    verifier = CodeSecurityVerifier()
    verifier.analyze_code("x = 1")
    return True


def test_sql_engine():
    from qwed_new.core.sql_verifier import SQLVerifier
    SQLVerifier()
    # Basic test
    return True


def test_stats_engine():
    from qwed_new.core.verifier import VerificationEngine
    engine = VerificationEngine()
    result = engine.verify_statistics([1, 2, 3], "mean", 2.0)
    return result.get("is_correct", False)


def test_ablation_tracker():
    from qwed_new.core.ablation_tracker import AblationTracker
    tracker = AblationTracker()
    tracker.record("math", {"is_correct": True})
    stats = tracker.get_stats()
    return stats["engines"]["math"]["verified"] == 1


def main():
    print("\n" + "="*50)
    print("   QWED Installation Verification")
    print("="*50 + "\n")
    
    all_passed = True
    
    # Check dependencies
    print("📦 Checking Dependencies...")
    deps = [
        ("sympy", "SymPy (Math Engine)"),
        ("z3", "Z3 Solver (Logic Engine)"),
        ("sqlglot", "SQLGlot (SQL Engine)"),
    ]
    
    for module, desc in deps:
        if not check_import(module, desc):
            all_passed = False
    
    print("\n🔧 Checking Engines...")
    
    engines = [
        ("Math", test_math_engine),
        ("Code", test_code_engine),
        ("SQL", test_sql_engine),
        ("Stats", test_stats_engine),
        ("Ablation Tracker", test_ablation_tracker),
    ]
    
    for name, test_func in engines:
        if not check_engine(name, test_func):
            all_passed = False
    
    print("\n" + "="*50)
    if all_passed:
        print("   ✅ All checks passed! QWED is ready.")
    else:
        print("   ❌ Some checks failed. Please fix issues above.")
    print("="*50 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
