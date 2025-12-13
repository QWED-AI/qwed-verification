"""Simple test to see the actual error"""
import requests

API_KEY = "qwed_live_oF7_B3zrWowNh-An7z2NwxX9l9e13SFOlOTAuLkyx50"

response = requests.post(
    "http://localhost:8000/verify/natural_language",
    headers={"x-api-key": API_KEY},
    json={"query": "What is 2+2?"}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
