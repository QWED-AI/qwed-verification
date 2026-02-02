import requests
import time
import sys

BASE_URL = "http://localhost:8000"
EMAIL = "rahul@qwedai.com"
PASSWORD = "secure_password_123"
ORG_NAME = "QWED Internal"

def wait_for_server():
    print("⏳ Waiting for server to be ready...")
    for _ in range(30):
        try:
            resp = requests.get(f"{BASE_URL}/health")
            if resp.status_code == 200:
                print("✅ Server is online!")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    print("❌ Server timed out. Please ensure it is running.")
    return False

def run_setup():
    # 1. Sign Up
    print(f"\n1️⃣ Signing up as {EMAIL}...")
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json={
            "email": EMAIL,
            "password": PASSWORD,
            "organization_name": ORG_NAME
        })
        if resp.status_code == 200:
            token = resp.json()["access_token"]
            print("✅ Signup successful!")
        elif resp.status_code == 400 and "already registered" in resp.text:
            print("ℹ️ User already exists, signing in...")
            resp = requests.post(f"{BASE_URL}/auth/signin", json={
                "email": EMAIL,
                "password": PASSWORD
            })
            resp.raise_for_status()
            token = resp.json()["access_token"]
            print("✅ Signin successful!")
        else:
            print(f"❌ Signup failed: {resp.text}")
            return
    except Exception as e:
        print(f"❌ Auth failed: {e}")
        return

    headers = {"Authorization": f"Bearer {token}"}

    # 2. Generate API Key
    print("\n2️⃣ Generating API Key...")
    try:
        resp = requests.post(f"{BASE_URL}/auth/api-keys", json={"name": "Integration Test Key"}, headers=headers)
        resp.raise_for_status()
        api_key = resp.json()["key"]
        print("✅ API Key generated successfully.")
    except Exception as e:
        print(f"❌ API Key generation failed: {e}")
        return

    # 3. Verify Content (The Real Test)
    print("\n3️⃣ Testing Verification Engine...")
    query = "What is the derivative of x^2?"
    try:
        verify_headers = {"x-api-key": api_key}
        resp = requests.post(f"{BASE_URL}/verify/natural_language", json={"query": query}, headers=verify_headers)
        
        if resp.status_code == 200:
            result = resp.json()
            print(f"✅ Verification Successful!")
            print(f"   Query: {query}")
            print(f"   Status: {result.get('status')}")
            print(f"   Confidence: {result.get('confidence')}")
        else:
            print(f"❌ Verification failed: {resp.status_code} - {resp.text}")
            return
    except Exception as e:
        print(f"❌ Verification request failed: {e}")
        return

    # 4. Check Audit Logs
    print("\n4️⃣ Checking Audit Logs...")
    try:
        resp = requests.get(f"{BASE_URL}/audit/logs", headers=headers)
        resp.raise_for_status()
        logs = resp.json()["logs"]
        
        # Find our log
        found = False
        for log in logs:
            if log["request_input"] == query:
                found = True
                print(f"✅ Audit Log found for query: '{query}'")
                print(f"   Result: {log['verification_result'][:50]}...")
                break
        
        if not found:
            print("❌ Audit log NOT found!")
    except Exception as e:
        print(f"❌ Audit check failed: {e}")

if __name__ == "__main__":
    if wait_for_server():
        run_setup()
