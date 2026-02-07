"""
QWED Stats Verification Example.

Demonstrates:
1. Uploading a CSV file and verifying statistical claims about it.
"""

import os
from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    # Create a dummy CSV file for the example
    csv_path = "sales_data.csv"
    with open(csv_path, "w") as f:
        f.write("month,sales,profit\n")
        f.write("Jan,100,20\n")
        f.write("Feb,120,25\n")
        f.write("Mar,150,30\n")
        f.write("Apr,130,28\n")

    try:
        print("--- Stats Verification ---")
        query = "What is the average sales amount?"
        print(f"File: {csv_path}")
        print(f"Query: {query}")

        result = client.verify_stats(query, csv_path)

        print(f"Status: {result.status}")
        if result.status == "SUCCESS":
            print(f"Result: {result.result.get('result')}")
            print(f"Generated Code: {result.result.get('code')}")
        else:
            print(f"Error: {result.error}")

    finally:
        # Cleanup
        if os.path.exists(csv_path):
            os.remove(csv_path)

if __name__ == "__main__":
    main()
