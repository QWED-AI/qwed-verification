"""
Test script for QWED authentication endpoints.
Tests signup, signin, API key generation, and revocation.
"""
import requests
import json

BASE_URL = "http://localhost:8000"

def test_signup():
    """Test user signup."""
    print("\n=== Testing Signup ===")
    response = requests.post(f"{BASE_URL}/auth/signup", json={
        "email": "test@qwed.ai",
        "password": "secure_password_123",
        "organization_name": "Test Corp"
    })
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"✓ User created: {data['user']['email']}")
        print(f"✓ Token: {data['access_token'][:20]}...")
        return data['access_token']
    else:
        print(f"✗ Error: {response.text}")
        return None

def test_signin(email, password):
    """Test user signin."""
    print("\n=== Testing SignIn ===")
    response = requests.post(f"{BASE_URL}/auth/signin", json={
        "email": email,
        "password": password
    })
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"✓ Logged in: {data['user']['email']}")
        print(f"✓ Role: {data['user']['role']}")
        return data['access_token']
    else:
        print(f"✗ Error: {response.text}")
        return None

def test_get_me(token):
    """Test getting current user."""
    print("\n=== Testing Get Me ===")
    response = requests.get(
        f"{BASE_URL}/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"✓ User: {data['email']}")
        print(f"✓ Org ID: {data['org_id']}")
    else:
        print(f"✗ Error: {response.text}")

def test_create_api_key(token):
    """Test API key creation."""
    print("\n=== Testing API Key Creation ===")
    response = requests.post(
        f"{BASE_URL}/auth/api-keys",
        json={"name": "Production Key"},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"✓ API Key created: {data['key'][:20]}...")
        print(f"✓ ID: {data['id']}")
        return data['id'], data['key']
    else:
        print(f"✗ Error: {response.text}")
        return None, None

def test_list_api_keys(token):
    """Test listing API keys."""
    print("\n=== Testing List API Keys ===")
    response = requests.get(
        f"{BASE_URL}/auth/api-keys",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        keys = response.json()
        print(f"✓ Found {len(keys)} API key(s)")
        for key in keys:
            print(f"  - {key['name']}: {key['key_preview']}")
    else:
        print(f"✗ Error: {response.text}")

def test_revoke_api_key(token, key_id):
    """Test revoking an API key."""
    print("\n=== Testing API Key Revocation ===")
    response = requests.delete(
        f"{BASE_URL}/auth/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"✓ API Key revoked")
    else:
        print(f"✗ Error: {response.text}")

if __name__ == "__main__":
    print("=" * 50)
    print("QWED Authentication Test Suite")
    print("=" * 50)
    
    # Test 1: Signup
    token = test_signup()
    
    if token:
        # Test 2: Get current user
        test_get_me(token)
        
        # Test 3: Create API key
        key_id, api_key = test_create_api_key(token)
        
        # Test 4: List API keys
        test_list_api_keys(token)
        
        # Test 5: Revoke API key
        if key_id:
            test_revoke_api_key(token, key_id)
        
        # Test 6: Sign in with same user
        test_signin("test@qwed.ai", "secure_password_123")
    
    print("\n" + "=" * 50)
    print("Test Suite Complete")
    print("=" * 50)
