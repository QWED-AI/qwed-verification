import requests
import time

BASE_URL = "http://127.0.0.1:8002"

def test_database_integration():
    print("💾 Testing Database Integration...")
    
    # 1. Send a Verification Request
    query = "What is 50 + 50?"
    print(f"\n1. Sending Query: '{query}'")
    try:
        response = requests.post(f"{BASE_URL}/verify/natural_language", json={"query": query})
        if response.status_code == 200:
            print("✅ Verification Success")
        else:
            print(f"❌ Verification Failed: {response.text}")
            return
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        return

    # 2. Check History
    print("\n2. Checking History Endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/history")
        if response.status_code == 200:
            history = response.json()
            print(f"✅ History Retrieved: {len(history)} items")
            if len(history) > 0:
                latest = history[0]
                print(f"   Latest Log: {latest['query']} -> Verified: {latest['is_verified']}")
                if latest['query'] == query:
                    print("✅ Log matches query!")
                else:
                    print("❌ Log mismatch!")
            else:
                print("❌ History is empty!")
        else:
            print(f"❌ History Failed: {response.text}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    test_database_integration()
