"""
Test script for Logic Verification (Z3).
"""

import requests
import json
import os

# API endpoint
BASE_URL = "http://127.0.0.1:8000"

# Test query: A simple constraint problem
test_query = "Find two integers x and y where x is greater than y and their sum is 10."

print(f"Testing Logic Verification with query: '{test_query}'")
print(f"Active Provider: {os.getenv('ACTIVE_PROVIDER', 'default')}")
print("=" * 60)

try:
    response = requests.post(
        f"{BASE_URL}/verify/logic",
        json={"query": test_query}
    )

    if response.status_code == 200:
        result = response.json()
        print(json.dumps(result, indent=2))
        print("=" * 60)
        
        if result['status'] == 'SAT':
            print("✅ SUCCESS: Problem is Satisfiable!")
            print(f"Solution: {result['model']}")
            
            # Verify manually
            model = result['model']
            x = int(model['x'])
            y = int(model['y'])
            if x > y and x + y == 10:
                print("✅ Manual Check Passed: x > y and x + y == 10")
            else:
                print("❌ Manual Check Failed")
        else:
            print(f"❌ Status: {result['status']}")
            if result.get('error'):
                print(f"Error: {result['error']}")
    else:
        print(f"❌ Error: {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"❌ Connection Error: {e}")
