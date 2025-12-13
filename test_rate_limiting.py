"""
Test script for QWED rate limiting.

Tests:
1. Per-API-key rate limiting (100 requests/minute)
2. 429 response with Retry-After header
"""

import requests
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_rate_limiting():
    print("=" * 60)
    print("QWED Rate Limiting Test")
    print("=" * 60)
    
    # Step 1: Sign up and get API key
    print("\n1️⃣ Creating test user and API key...")
    
    # Sign up
    signup_response = requests.post(
        f"{BASE_URL}/auth/signup",
        json={
            "email": "ratelimit_test@test.com",
            "password": "testpass123",
            "organization_name": "RateLimit Test Org"
        }
    )
    
    if signup_response.status_code == 200:
        print("✅ User created successfully")
        token = signup_response.json()["access_token"]
    else:
        print(f"⚠️ User might already exist, trying to sign in...")
        signin_response = requests.post(
            f"{BASE_URL}/auth/signin",
            json={
                "email": "ratelimit_test@test.com",
                "password": "testpass123"
            }
        )
        if signin_response.status_code != 200:
            print(f"❌ Failed to sign in: {signin_response.text}")
            return
        token = signin_response.json()["access_token"]
        print("✅ Signed in successfully")
    
    # Generate API key
    apikey_response = requests.post(
        f"{BASE_URL}/auth/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Rate Limit Test Key"}
    )
    
    if apikey_response.status_code != 200:
        print(f"❌ Failed to generate API key: {apikey_response.text}")
        return
    
    api_key = apikey_response.json()["key"]
    print(f"✅ API key generated: {api_key[:20]}...")
    
    # Step 2: Test per-key rate limiting
    print("\n2️⃣ Testing per-API-key rate limiting (limit: 100 req/min)...")
    print("Making rapid requests...")
    
    success_count = 0
    rate_limited = False
    rate_limit_at = 0
    
    for i in range(105):
        try:
            response = requests.post(
                f"{BASE_URL}/verify/natural_language",
                headers={"x-api-key": api_key},
                json={"query": f"What is 2+2? Request #{i+1}"},
                timeout=5
            )
            
            if response.status_code == 200:
                success_count += 1
                if (i + 1) % 20 == 0:
                    print(f"  ✓ {i+1} requests successful...")
            elif response.status_code == 429:
                rate_limited = True
                rate_limit_at = i + 1
                retry_after = response.headers.get('Retry-After', 'unknown')
                print(f"\n🚫 Rate limit hit at request #{i+1}")
                print(f"  Status: {response.status_code}")
                print(f"  Message: {response.json().get('detail', 'No detail')}")
                print(f"  Retry-After: {retry_after} seconds")
                break
            else:
                print(f"  ⚠️ Unexpected status {response.status_code} at request #{i+1}")
                
        except requests.exceptions.Timeout:
            print(f"  ⏱️ Request #{i+1} timed out")
        except Exception as e:
            print(f"  ❌ Error at request #{i+1}: {e}")
            break
    
    # Step 3: Summary
    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"✅ Successful requests: {success_count}")
    print(f"🚫 Rate limited at: Request #{rate_limit_at}" if rate_limited else "⚠️ No rate limit encountered")
    
    if rate_limited and rate_limit_at <= 101:
        print("\n✅ PASS: Rate limiting is working correctly!")
        print(f"   Expected limit: 100 requests")
        print(f"   Actual limit: {rate_limit_at - 1} requests")
    else:
        print("\n❌ FAIL: Rate limiting may not be working as expected")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    try:
        test_rate_limiting()
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
