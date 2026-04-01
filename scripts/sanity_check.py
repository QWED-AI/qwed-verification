import sys
import os

# Ensure we can import from src/
sys.path.append(os.path.join(os.getcwd(), "src"))

try:
    print("--- 1. Testing Money Engine (Financial Precision) ---")
    from qwed_new.core.money import Money, UnitMismatchError
    
    # Test 1: Valid Addition
    m1 = Money("100.00", "INR")
    m2 = Money("50.50", "INR")
    result = m1 + m2
    assert str(result.amount) == "150.50", f"Math Error: Got {result.amount}"
    print("✅ Valid Money Addition Passed")

    # Test 2: Unit Mismatch (The Beast Feature)
    try:
        m3 = Money("10", "USD")
        m1 + m3
        print("❌ FAILED: Unit Mismatch did not raise error!")
        sys.exit(1)
    except UnitMismatchError:
        print("✅ Unit Mismatch Caught Successfully")

    print("\n--- 2. Testing Logic Engine (Z3 Counter-Models) ---")
    from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
    
    verifier = DSLLogicVerifier()
    # Create a contradiction: x > 5 AND x < 3
    bad_logic = "(AND (GT x 5) (LT x 3))"
    res = verifier.verify_from_dsl(bad_logic)
    
    if res.status == "UNSAT" and res.rejection_reason:
        print(f"✅ Counter-Model Working! Reason: {res.rejection_reason.strip()[:50]}...")
    else:
        print(f"❌ FAILED: Logic check did not return UNSAT or Reason. Status: {res.status}")
        sys.exit(1)

    print("\n--- 3. Database Check (Postgres Config) ---")
    # Just checking if we can import the DB config without crashing
    # Fixed path: qwed_new.core.database (not qwed_new.db.database)
    from qwed_new.core.database import get_session
    print("✅ Database modules imported successfully (Runtime check needs Docker up)")

    print("\n🎉 ALL SYSTEMS GO! READY TO PUSH. 🚀")

except ImportError as e:
    print(f"❌ Import Error: {e}. Check your paths!")
    sys.exit(1)
except Exception as e:
    print(f"❌ UNEXPECTED ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
