import requests
import json
import textwrap

BASE_URL = "http://127.0.0.1:8002"

def test_code_verification():
    print("🛡️ Testing Code Security Verifier...")
    
    # 1. Test Safe Code
    safe_code = textwrap.dedent("""
    def calculate_sum(a, b):
        return a + b
    """)
    print(f"\nTesting Safe Code...")
    try:
        response = requests.post(f"{BASE_URL}/verify/code", json={"code": safe_code})
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Result: Safe={result['is_safe']}")
            if result['is_safe']:
                print("🎯 Correct Verdict!")
            else:
                print(f"⚠️ Unexpected Verdict: {result['issues']}")
        else:
            print(f"❌ Request Failed: {response.text}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")

    # 2. Test Dangerous Code (eval)
    dangerous_code_eval = textwrap.dedent("""
    user_input = "print('hacked')"
    eval(user_input)
    """)
    print(f"\nTesting Dangerous Code (eval)...")
    try:
        response = requests.post(f"{BASE_URL}/verify/code", json={"code": dangerous_code_eval})
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Result: Safe={result['is_safe']}")
            print(f"Issues: {result['issues']}")
            if not result['is_safe'] and "Use of dangerous function: eval" in result['issues']:
                print("🎯 Correct Verdict!")
            else:
                print("⚠️ Unexpected Verdict.")
        else:
            print(f"❌ Request Failed: {response.text}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")

    # 3. Test Dangerous Code (Secret)
    dangerous_code_secret = textwrap.dedent("""
    aws_key = "AKIA1234567890ABCDEF"
    """)
    print(f"\nTesting Dangerous Code (Secret)...")
    try:
        response = requests.post(f"{BASE_URL}/verify/code", json={"code": dangerous_code_secret})
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Result: Safe={result['is_safe']}")
            print(f"Issues: {result['issues']}")
            if not result['is_safe'] and "Found potential secret: AWS Access Key" in result['issues']:
                print("🎯 Correct Verdict!")
            else:
                print("⚠️ Unexpected Verdict.")
        else:
            print(f"❌ Request Failed: {response.text}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    test_code_verification()
