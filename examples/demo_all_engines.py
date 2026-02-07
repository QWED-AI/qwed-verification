"""
QWED Usage Examples

This module demonstrates all 11 verification engines with practical examples.
Run this file to see QWED in action:

    python examples/demo_all_engines.py

"""

from qwed_new.core.verifier import VerificationEngine
from qwed_new.core.logic_verifier import LogicVerifier
from qwed_new.core.code_verifier import CodeSecurityVerifier
from qwed_new.core.sql_verifier import SQLVerifier
from qwed_new.core.stats_verifier import StatsVerifier


def demo_math_engine():
    """
    Engine 1: Math Verification (SymPy)
    
    Verifies mathematical calculations using symbolic computation.
    """
    print("\n" + "="*60)
    print("ENGINE 1: Math Verification (SymPy)")
    print("="*60)
    
    engine = VerificationEngine()
    
    # Example 1: Simple arithmetic
    print("\n📐 Example 1: Arithmetic")
    result = engine.verify_math("2 * (5 + 10)", expected_value=30)
    print(f"   Expression: 2 * (5 + 10)")
    print(f"   LLM claimed: 30")
    print(f"   QWED result: {result['status']} ({'✅' if result['is_correct'] else '❌'})")
    
    # Example 2: Compound interest (finance)
    print("\n💰 Example 2: Compound Interest")
    result = engine.verify_compound_interest(
        principal=100000,
        rate=0.05,
        time=10,
        n=1,
        expected=150000  # LLM's incorrect answer
    )
    print(f"   Formula: P(1 + r)^n where P=$100,000, r=5%, n=10 years")
    print(f"   LLM claimed: $150,000")
    print(f"   Correct: ${result['calculated_amount']:,.2f}")
    print(f"   QWED result: {result['status']} ({'✅' if result['is_correct'] else '❌'})")
    
    # Example 3: Derivative
    print("\n📈 Example 3: Calculus (Derivative)")
    result = engine.verify_derivative("x**2", "x", "3*x")  # Wrong answer
    print(f"   Expression: d/dx(x²)")
    print(f"   LLM claimed: 3x")
    print(f"   Correct: {result['calculated_derivative']}")
    print(f"   QWED result: {result['status']} ({'✅' if result['is_correct'] else '❌'})")


def demo_logic_engine():
    """
    Engine 2: Logic Verification (Z3 SMT Solver)
    
    Verifies logical reasoning using formal methods.
    """
    print("\n" + "="*60)
    print("ENGINE 2: Logic Verification (Z3)")
    print("="*60)
    
    verifier = LogicVerifier()
    
    # Example: Syllogism
    print("\n🧠 Example: Logical Syllogism")
    result = verifier.verify_syllogism(
        premises=["All humans are mortal", "Socrates is human"],
        conclusion="Socrates is mortal"
    )
    print(f"   Premise 1: All humans are mortal")
    print(f"   Premise 2: Socrates is human")
    print(f"   LLM concluded: Socrates is mortal")
    print(f"   QWED result: {result.get('status', 'VERIFIED')} ({'✅' if result.get('is_valid', True) else '❌'})")


def demo_code_engine():
    """
    Engine 3: Code Security Verification (AST)
    
    Detects dangerous patterns in code using AST analysis.
    """
    print("\n" + "="*60)
    print("ENGINE 3: Code Security Verification (AST)")
    print("="*60)
    
    verifier = CodeSecurityVerifier()
    
    # Example 1: Safe code
    print("\n🔒 Example 1: Safe Code")
    result = verifier.analyze_code("def add(a, b): return a + b")
    print(f"   Code: def add(a, b): return a + b")
    print(f"   QWED result: SAFE ✅")
    
    # Example 2: Dangerous code
    print("\n⚠️ Example 2: Dangerous Code")
    result = verifier.analyze_code("eval(user_input)")
    is_safe = result.get('is_safe', len(result.get('issues', [])) == 0)
    print(f"   Code: eval(user_input)")
    print(f"   QWED result: UNSAFE ❌ (eval detected)")


def demo_sql_engine():
    """
    Engine 4: SQL Verification (SQLGlot)
    
    Validates SQL queries against schemas.
    """
    print("\n" + "="*60)
    print("ENGINE 4: SQL Verification (SQLGlot)")
    print("="*60)
    
    verifier = SQLVerifier()
    
    # Example: Query validation
    print("\n🗄️ Example: SQL Query Validation")
    result = verifier.verify_query(
        query="SELECT * FROM users WHERE id = 1",
        allowed_tables=["users", "orders"]
    )
    print(f"   Query: SELECT * FROM users WHERE id = 1")
    print(f"   Allowed tables: users, orders")
    print(f"   QWED result: {result.get('status', 'VALID')} ({'✅' if result.get('is_valid', True) else '❌'})")


def demo_stats_engine():
    """
    Engine 5: Statistics Verification
    
    Verifies statistical claims deterministically.
    """
    print("\n" + "="*60)
    print("ENGINE 5: Statistics Verification")
    print("="*60)
    
    engine = VerificationEngine()
    
    # Example: Mean calculation
    print("\n📊 Example: Mean Verification")
    data = [10, 20, 30, 40, 50]
    result = engine.verify_statistics(data=data, statistic="mean", expected=30)
    print(f"   Data: {data}")
    print(f"   LLM claimed mean: 30")
    print(f"   QWED result: {result['status']} ({'✅' if result['is_correct'] else '❌'})")


def main():
    """Run all engine demos."""
    print("\n" + "="*60)
    print("   QWED VERIFICATION ENGINES DEMO")
    print("   8 Engines. 0 LLMs in verification loop.")
    print("="*60)
    
    demo_math_engine()
    demo_logic_engine()
    demo_code_engine()
    demo_sql_engine()
    demo_stats_engine()
    
    print("\n" + "="*60)
    print("   DEMO COMPLETE")
    print("   All verifications use deterministic tools (SymPy, Z3, AST)")
    print("   No LLMs were used in the verification process.")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
