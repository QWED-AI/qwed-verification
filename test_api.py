"""
Test script for the natural language verification endpoint.

This script tests the full QWED pipeline:
1. Translation (Azure OpenAI)
2. Validation (Semantic checks)
3. Verification (SymPy)
"""

import requests
import json

# API endpoint
BASE_URL = "http://127.0.0.1:8000"

# Test query
test_query = "What is 15% of 200?"

print(f"Testing QWED with query: '{test_query}'")
print("=" * 60)

# Make the request
response = requests.post(
    f"{BASE_URL}/verify/natural_language",
    json={"query": test_query}
)

# Print the result
if response.status_code == 200:
    result = response.json()
    print(json.dumps(result, indent=2))
    print("=" * 60)
    print(f"✅ Status: {result['status']}")
    print(f"✅ Final Answer: {result['final_answer']}")
    print(f"✅ Latency: {result['latency_ms']:.2f}ms")
else:
    print(f"❌ Error: {response.status_code}")
    print(response.text)
