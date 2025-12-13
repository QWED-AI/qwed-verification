# Rate Limiting - Testing Script

This script tests the QWED rate limiting implementation.

## Test Plan

### Test 1: Per-API-Key Rate Limiting
- Make 101 requests with the same API key
- Expected: First 100 succeed, 101st returns 429

### Test 2: Global Rate Limiting
- Make 1001 requests from different API keys
- Expected: First 1000 succeed, 1001st returns 429

### Test 3: Rate Limit Reset
- Hit rate limit, wait 60 seconds, try again
- Expected: Requests succeed after window expires

## Run Tests

```python
import requests
import time

BASE_URL = "http://localhost:8000"
API_KEY = "your-api-key-here"

# Test 1: Per-key limit
print("Test 1: Per-API-Key Rate Limiting")
for i in range(102):
    response = requests.post(
        f"{BASE_URL}/verify/natural_language",
        headers={"x-api-key": API_KEY},
        json={"query": f"What is 2+2? (Request {i+1})"}
    )
    print(f"Request {i+1}: Status {response.status_code}")
    if response.status_code == 429:
        print(f"✅ Rate limit hit at request {i+1}")
        print(f"Retry-After: {response.headers.get('Retry-After')} seconds")
        break

# Test 2: Check reset time
print("\nTest 2: Checking reset time...")
time.sleep(2)
response = requests.post(
    f"{BASE_URL}/verify/natural_language",
    headers={"x-api-key": API_KEY},
    json={"query": "Test after rate limit"}
)
print(f"Status: {response.status_code}")
if response.status_code == 429:
    print(f"Still limited. Retry-After: {response.headers.get('Retry-After')}s")
```

## Expected Output

```
Request 1: Status 200
Request 2: Status 200
...
Request 100: Status 200
Request 101: Status 429
✅ Rate limit hit at request 101
Retry-After: 59 seconds
```
