"""
QWED Fact Verification Example.

Demonstrates:
1. Verifying a claim against a provided text context.
"""

from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    context = """
    QWED v2.0 was released in 2024. It introduces 8 specialized verification engines including
    Math, Logic, Stats, Fact, Code, SQL, Image, and Consensus.
    The platform treats LLMs as untrusted translators and uses symbolic engines as trusted verifiers.
    """

    print("--- 1. Supported Claim ---")
    claim = "QWED v2.0 includes a Statistics verification engine."
    print(f"Context: ... (len={len(context)})")
    print(f"Claim: {claim}")

    result = client.verify_fact(claim, context)
    print(f"Is Verified: {result.is_verified}")
    print(f"Verdict: {result.result.get('verdict')}")
    print()

    print("--- 2. Unsupported Claim ---")
    false_claim = "QWED v2.0 was released in 2020."
    print(f"Claim: {false_claim}")

    result = client.verify_fact(false_claim, context)
    print(f"Is Verified: {result.is_verified}")
    print(f"Verdict: {result.result.get('verdict')}")

if __name__ == "__main__":
    main()
