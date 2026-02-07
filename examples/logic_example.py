"""
QWED Logic Verification Example.

Demonstrates:
1. Verifying logic puzzles and constraints using the Logic Engine (Z3).
"""

from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    print("--- Logic Verification ---")
    # A simple constraint problem
    query = "(AND (GT x 5) (LT y 10) (Eq (+ x y) 15))"
    print(f"Query: {query}")

    result = client.verify_logic(query)
    print(f"Status: {result.status}")

    if result.is_verified: # SAT or UNSAT considered verified outcomes in broad sense, but usually SAT means we found a model
        print(f"Model: {result.result}")
    else:
        print("Could not satisfy constraints or error occurred.")

    print()

    print("--- Unsatisfiable Constraint ---")
    unsat_query = "(AND (GT x 10) (LT x 5))"
    print(f"Query: {unsat_query}")
    result = client.verify_logic(unsat_query)
    print(f"Result: {result.result}") # Expecting UNSAT

if __name__ == "__main__":
    main()
