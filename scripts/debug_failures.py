import requests
import json

BASE_URL = "http://127.0.0.1:8002"

def debug_math():
    print("\n🔍 Debugging Math Failure...")
    query = "What is the derivative of x**3 + 2*x**2 + 5 at x = 3?"
    try:
        response = requests.post(f"{BASE_URL}/verify/natural_language", json={"query": query})
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

def debug_logic():
    print("\n🔍 Debugging Logic Failure...")
    query = "Color a map with 3 regions (A, B, C) using Red, Green, Blue such that A touches B, B touches C, and A touches C. No adjacent regions can have the same color."
    try:
        response = requests.post(f"{BASE_URL}/verify/logic", json={"query": query})
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    debug_math()
    debug_logic()
