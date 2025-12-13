import requests
import json

BASE_URL = "http://127.0.0.1:8002"

def test_fact_verification():
    print("🕵️ Testing Fact Verifier...")
    
    # 1. Define Context and Claim
    context = """
    QWED Insurance Policy 2024.
    Section 3.1: Water Damage.
    The policy covers sudden and accidental water damage from burst pipes.
    However, it explicitly excludes damage caused by flood, surface water, or gradual seepage.
    Mold remediation is covered up to $5,000 if resulting from a covered water loss.
    """
    
    claim_supported = "The policy covers mold remediation up to $5,000 if it comes from a burst pipe."
    claim_refuted = "The policy covers damage from floods."
    
    # 2. Test Supported Claim
    print(f"\nTesting Supported Claim: '{claim_supported}'")
    data = {
        "claim": claim_supported,
        "context": context,
        "provider": "azure_openai"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/verify/fact", json=data)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Result: {result['verdict']}")
            print(f"Reasoning: {result['reasoning']}")
            print(f"Citations: {result['citations']}")
            
            if result['verdict'] == "SUPPORTED":
                print("🎯 Correct Verdict!")
            else:
                print("⚠️ Unexpected Verdict.")
        else:
            print(f"❌ Request Failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

    # 3. Test Refuted Claim
    print(f"\nTesting Refuted Claim: '{claim_refuted}'")
    data["claim"] = claim_refuted
    
    try:
        response = requests.post(f"{BASE_URL}/verify/fact", json=data)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Result: {result['verdict']}")
            print(f"Reasoning: {result['reasoning']}")
            print(f"Citations: {result['citations']}")
            
            if result['verdict'] == "REFUTED":
                print("🎯 Correct Verdict!")
            else:
                print("⚠️ Unexpected Verdict.")
        else:
            print(f"❌ Request Failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    test_fact_verification()
