"""
Advanced Logic Evaluation Script.
Runs complex logic puzzles against the active provider.
"""

import json
import os
import time
import requests
from typing import List, Dict

BASE_URL = "http://127.0.0.1:8000"

def load_puzzles(path: str) -> List[Dict]:
    with open(path, 'r') as f:
        return json.load(f)

def evaluate_logic():
    dataset_path = os.path.join(os.path.dirname(__file__), "tests", "logic_puzzles.json")
    puzzles = load_puzzles(dataset_path)
    
    provider = os.getenv("ACTIVE_PROVIDER", "azure_openai")
    print(f"🚀 Starting Logic Evaluation on {len(puzzles)} puzzles...")
    print(f"🤖 Active Provider: {provider}")
    print("-" * 60)
    
    passed = 0
    
    for item in puzzles:
        print(f"🧩 [{item['id']}] {item['category']}")
        print(f"Query: {item['query'][:100]}...")
        
        try:
            response = requests.post(
                f"{BASE_URL}/verify/logic",
                json={"query": item['query']}
            )
            
            if response.status_code == 200:
                result = response.json()
                status = result['status']
                
                print(f"  Result: {status}")
                if status == "SAT":
                    print(f"  Model: {result.get('model')}")
                
                if status == item['expected_status']:
                    print("  ✅ PASSED")
                    passed += 1
                else:
                    print(f"  ❌ FAILED (Expected {item['expected_status']}, got {status})")
                    if result.get('error'):
                        print(f"  Error: {result['error']}")
            else:
                print(f"  ❌ API Error: {response.status_code}")
                print(f"  {response.text}")
                
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            
        print("-" * 30)
        
    print(f"\n📊 Score: {passed}/{len(puzzles)} ({passed/len(puzzles)*100:.1f}%)")

if __name__ == "__main__":
    evaluate_logic()
