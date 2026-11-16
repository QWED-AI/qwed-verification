"""
QWED Logic Verification Example.

Demonstrates:
1. Checking whether a claim follows from the conditions a question states,
   using the Logic Engine (Z3).
"""

from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    print("--- A claim that follows ---")
    # The question states its conditions and the claim to check. The
    # configured model translates both, and Z3 decides the claim for every x.
    query = "x is greater than 5. Is x greater than 3?"
    print(f"Query: {query}")

    result = client.verify_logic(query)
    # VERIFIED: the claim follows from the translated constraints. It is not
    # admitted (is_verified is False): the translation itself is not verified.
    print(f"Status: {result.status}, admitted: {result.is_verified}")

    print()

    print("--- A claim that does not follow ---")
    query = "x is greater than 5. Is x greater than 10?"
    print(f"Query: {query}")
    result = client.verify_logic(query)
    # Proven false (is_valid False), with a counterexample such as x = 6.
    data = result.result or {}
    print(f"Status: {result.status}, valid: {data.get('is_valid')}, counterexample: {data.get('model')}")

if __name__ == "__main__":
    main()
