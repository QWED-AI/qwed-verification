"""
QWED Consensus Verification Example.

Demonstrates:
1. Using multiple engines to verify a query with higher confidence.
2. Specifying verification mode and minimum confidence.
"""

from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    print("--- Consensus Verification ---")
    query = "Is the square root of 16 equal to 4?"

    # Mode can be 'single', 'high' (2 engines), or 'maximum' (3+ engines)
    mode = "high"
    min_confidence = 0.90

    print(f"Query: {query}")
    print(f"Mode: {mode}")

    result = client.verify_consensus(
        query,
        mode=mode,
        min_confidence=min_confidence
    )

    print(f"Status: {result.status}")
    print(f"Is Verified: {result.is_verified}")

    if result.result:
        print(f"Confidence: {result.result.get('confidence')}%")
        print(f"Engines Used: {result.result.get('engines_used')}")
        print(f"Agreement: {result.result.get('agreement_status')}")

if __name__ == "__main__":
    main()
