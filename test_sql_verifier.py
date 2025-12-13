import requests
import json
import textwrap

BASE_URL = "http://127.0.0.1:8002"

def print_header(title):
    print("\n" + "=" * 60)
    print(f"🧪 {title}")
    print("=" * 60)

def test_sql_verifier():
    print_header("Engine 6: SQL Verifier Test")
    
    # Define a schema (DDL)
    schema = textwrap.dedent("""
    CREATE TABLE users (
        id INT PRIMARY KEY,
        name TEXT,
        email TEXT
    );
    CREATE TABLE orders (
        id INT PRIMARY KEY,
        user_id INT,
        amount DECIMAL,
        date DATE
    );
    """)
    
    # Test Cases
    test_cases = [
        {
            "name": "Valid Query",
            "query": "SELECT name, email FROM users WHERE id > 100",
            "expected_valid": True
        },
        {
            "name": "Invalid Syntax",
            "query": "SELECT * FORM users", # Typo FORM
            "expected_valid": False
        },
        {
            "name": "Missing Table",
            "query": "SELECT * FROM products", # products table doesn't exist
            "expected_valid": False
        },
        {
            "name": "Missing Column",
            "query": "SELECT age FROM users", # age column doesn't exist
            "expected_valid": False
        },
        {
            "name": "Dangerous Query",
            "query": "DROP TABLE users",
            "expected_valid": False
        }
    ]
    
    for case in test_cases:
        print(f"\n🔹 Testing: {case['name']}")
        print(f"Query: {case['query']}")
        
        try:
            response = requests.post(
                f"{BASE_URL}/verify/sql",
                json={
                    "query": case['query'],
                    "schema_ddl": schema,
                    "dialect": "sqlite"
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Valid: {result['is_valid']}")
                if not result['is_valid']:
                    print(f"⚠️ Issues: {result['issues']}")
                
                if result['is_valid'] == case['expected_valid']:
                    print("🎯 PASS")
                else:
                    print(f"❌ FAIL (Expected {case['expected_valid']}, got {result['is_valid']})")
            else:
                print(f"❌ API Error: {response.text}")
                
        except Exception as e:
            print(f"❌ Exception: {e}")

if __name__ == "__main__":
    test_sql_verifier()
