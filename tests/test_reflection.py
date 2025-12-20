"""
Test script for Reflection (Feedback Loop).
We need to simulate a failure that the Sanitizer misses but Z3 catches.
Example: Using a Python function that doesn't exist in Z3, e.g. `max(x, y)`.
Z3 has `Max` but python `max` might fail if arguments are symbolic.
Or better: `x ** y` (Power) which Z3 supports but maybe syntax is tricky?
Actually, let's try a syntax error that Sanitizer doesn't fix: `x is 5`.
"""

import requests
import json
import os

BASE_URL = "http://127.0.0.1:8000"

def test_reflection():
    # Query that might cause a syntax error if translated naively
    # "x is equal to 5" -> LLM might output "x is 5" (invalid python)
    # or "x equals 5"
    query = "Find x where x equals 5." 
    
    print(f"🧪 Testing Reflection with query: '{query}'")
    print("Expecting initial failure (if LLM is lazy) and then success via Reflection.")
    
    try:
        response = requests.post(
            f"{BASE_URL}/verify/logic",
            json={"query": query}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(json.dumps(result, indent=2))
            
            if result['status'] == 'SAT':
                print("✅ SUCCESS (Either initial or reflection worked)")
            else:
                print(f"❌ FAILED: {result.get('error')}")
        else:
            print(f"❌ API Error: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    test_reflection()
