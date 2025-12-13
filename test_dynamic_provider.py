import requests
import json

BASE_URL = "http://127.0.0.1:8002"

def test_dynamic_switching():
    print("🔄 Testing Dynamic Provider Switching...")
    
    query = "What is 10 + 10?"
    
    # 1. Test Azure (Default)
    print("\n1. Testing Azure OpenAI (Default)...")
    try:
        payload = {"query": query, "provider": "azure_openai"}
        response = requests.post(f"{BASE_URL}/verify/natural_language", json=payload)
        if response.status_code == 200:
            print("✅ Azure Request Success")
            # We can't easily check which provider was used from the response unless we add metadata
            # But if it didn't crash, it's a good sign.
        else:
            print(f"❌ Azure Request Failed: {response.text}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")

    # 2. Test Anthropic
    print("\n2. Testing Anthropic (Claude)...")
    try:
        payload = {"query": query, "provider": "anthropic"}
        response = requests.post(f"{BASE_URL}/verify/natural_language", json=payload)
        if response.status_code == 200:
            print("✅ Anthropic Request Success")
        else:
            print(f"❌ Anthropic Request Failed: {response.text}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    test_dynamic_switching()
