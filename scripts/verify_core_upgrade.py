import sys
import os

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

try:
    from qwed_new.core.logic_verifier import LogicVerifier
    verifier = LogicVerifier()
    print("✅ LogicVerifier instantiated successfully.")
    
    # Check if new methods exist
    if hasattr(verifier, 'verify_optimization') and hasattr(verifier, 'check_vacuity'):
         print("✅ New methods found: verify_optimization, check_vacuity")
    else:
         print("❌ Verification Failed: Methods missing.")
         sys.exit(1)

except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Run: pip install z3-solver")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
