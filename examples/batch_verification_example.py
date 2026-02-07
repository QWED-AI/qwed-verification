"""
QWED Batch Verification Example.

Demonstrates:
1. Sending multiple verification requests in a single batch.
2. Checking batch status and results.
"""

from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    items = [
        {"query": "2+2=4", "type": "math"},
        {"query": "3*3=10", "type": "math"},
        {"query": "(AND (GT x 5))", "type": "logic"}
    ]

    print(f"Submitting batch of {len(items)} items...")

    batch_result = client.verify_batch(items)

    print(f"Job ID: {batch_result.job_id}")
    print(f"Status: {batch_result.status}")
    print(f"Success Rate: {batch_result.success_rate}%")

    print("\nResults:")
    for item in batch_result.items:
        print(f"[{item.type}] {item.query} -> {item.status}")
        if item.result:
             print(f"   Details: {item.result}")

if __name__ == "__main__":
    main()
