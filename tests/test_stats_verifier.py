import requests
import pandas as pd
import io

BASE_URL = "http://127.0.0.1:8002"

def test_stats_verification():
    print("📊 Testing Statistical Verifier...")
    
    # 1. Create a dummy CSV
    csv_content = """Date,Product,Sales,Region
2023-01-01,Widget A,100,North
2023-01-02,Widget B,150,South
2023-01-03,Widget A,120,North
2023-01-04,Widget C,200,East
2023-01-05,Widget B,130,South
"""
    
    # 2. Define Query
    query = "What is the total sales for Widget A?"
    expected_answer = "220" # 100 + 120
    
    print(f"\nQuery: {query}")
    print("Uploading CSV...")
    
    # 3. Send Request
    files = {
        'file': ('sales.csv', csv_content, 'text/csv')
    }
    data = {
        'query': query,
        'provider': 'azure_openai'
    }
    
    try:
        response = requests.post(f"{BASE_URL}/verify/stats", files=files, data=data)
        
        if response.status_code == 200:
            result = response.json()
            print("\n✅ Verification Success!")
            print(f"Result: {result['result']}")
            print(f"Generated Code:\n{result['code']}")
            
            if str(result['result']) == expected_answer:
                print("🎯 Answer Matches Expected!")
            else:
                print(f"⚠️ Answer Mismatch. Expected {expected_answer}, got {result['result']}")
        else:
            print(f"❌ Request Failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    test_stats_verification()
