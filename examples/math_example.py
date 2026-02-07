"""
QWED Math Verification Example.

Demonstrates:
1. Verifying mathematical expressions.
2. Verifying natural language math questions.
"""

from qwed_sdk import QWEDClient
import os

def main():
    # Initialize client (defaults to localhost:8000)
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    print("--- 1. Symbolic Math Verification ---")
    expression = "x**2 - y**2 = (x-y)*(x+y)"
    print(f"Verifying identity: {expression}")

    result = client.verify_math(expression)
    print(f"Status: {result.status}")
    print(f"Is Valid: {result.is_verified}")
    print(f"Result: {result.result}")
    print()

    print("--- 2. Natural Language Math ---")
    query = "What is the derivative of x^3 + 2x?"
    print(f"Query: {query}")

    result = client.verify(query)
    print(f"Status: {result.status}")
    print(f"Answer: {result.result}")
    print()

    print("--- 3. Handling Errors ---")
    invalid_expr = "1/0"
    print(f"Verifying: {invalid_expr}")
    result = client.verify_math(invalid_expr)
    print(f"Status: {result.status}")
    print(f"Verified: {result.is_verified}")
    if result.error:
        print(f"Error: {result.error}")

if __name__ == "__main__":
    main()
