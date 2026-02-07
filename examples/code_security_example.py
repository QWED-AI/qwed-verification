"""
QWED Code Security Example.

Demonstrates:
1. Scanning code for security vulnerabilities.
2. Detecting dangerous functions like eval(), os.system().
"""

from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    print("--- 1. Safe Code ---")
    safe_code = """
def add(a, b):
    return a + b
    """
    print(f"Code:\n{safe_code}")
    result = client.verify_code(safe_code)
    print(f"Is Safe: {result.is_verified}")
    print()

    print("--- 2. Dangerous Code ---")
    dangerous_code = """
import os
def delete_everything():
    os.system("rm -rf /")
    """
    print(f"Code:\n{dangerous_code}")
    result = client.verify_code(dangerous_code)
    print(f"Is Safe: {result.is_verified}")

    if not result.is_verified:
        # Depending on API response structure, we might print details
        print(f"Details: {result.result}")

if __name__ == "__main__":
    main()
