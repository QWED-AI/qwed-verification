"""
QWED SQL Safety Example.

Demonstrates:
1. Verifying SQL queries against a schema.
2. Checking for syntax errors or invalid column references.
"""

from qwed_sdk import QWEDClient
import os

def main():
    client = QWEDClient(api_key=os.environ.get("QWED_API_KEY", "qwed_test_key"))

    schema = "CREATE TABLE users (id INT, name TEXT, email TEXT);"

    print("--- 1. Valid SQL ---")
    query = "SELECT name, email FROM users WHERE id > 100"
    print(f"Schema: {schema}")
    print(f"Query: {query}")

    result = client.verify_sql(query, schema_ddl=schema)
    print(f"Is Valid: {result.is_verified}")
    print()

    print("--- 2. Invalid SQL (Unknown Column) ---")
    bad_query = "SELECT age FROM users" # 'age' does not exist
    print(f"Query: {bad_query}")

    result = client.verify_sql(bad_query, schema_ddl=schema)
    print(f"Is Valid: {result.is_verified}")
    if not result.is_verified:
        print(f"Error: {result.result}")

if __name__ == "__main__":
    main()
