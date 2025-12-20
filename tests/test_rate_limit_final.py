"""Test rate limiting with 105 requests"""
import requests
import time

API_KEY = "qwed_live_oF7_B3zrWowNh-An7z2NwxX9l9e13SFOlOTAuLkyx50"
BASE_URL = "http://localhost:8000"

print("Testing rate limiting...")
print("Making 105 requests rapidly...")
print("="*60)

success_count = 0
rate_limited_at = None

for i in range(1, 106):
    response = requests.post(
        f"{BASE_URL}/verify/natural_language",
        headers={"x-api-key": API_KEY},
        json={"query": f"Test {i}"}
    )
    
    if response.status_code == 200:
        success_count += 1
        if i % 20 == 0:
            print(f"✅ Request {i}: SUCCESS")
    elif response.status_code == 429:
        rate_limited_at = i
        print(f"\n🚫 Rate limit hit at request #{i}")
        print(f"   Response: {response.json()}")
        print(f"   Retry-After: {response.headers.get('Retry-After')} seconds")
        break
    else:
        print(f"⚠️ Request {i}: Status {response.status_code}")

print("\n" + "="*60)
print("RESULTS:")
print(f"✅ Successful requests: {success_count}")
if rate_limited_at:
    print(f"🚫 Rate limited at request: #{rate_limited_at}")
    print(f"\n✅ TEST PASSED! Rate limiting works correctly.")
    print(f"   Expected limit: ~100 requests")
    print(f"   Actual limit: {rate_limited_at - 1} requests")
else:
    print("⚠️ No rate limit encountered (unexpected)")
print("="*60)
