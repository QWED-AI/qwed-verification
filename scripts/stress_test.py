"""
Rigorous Stress Test for QWED Verification Engine.
Simulates high load and malicious attacks to verify stability.
Uses ThreadPoolExecutor for concurrency.
"""

import concurrent.futures
import requests
import time
import json
import random

BASE_URL = "http://127.0.0.1:8001"

# Mix of queries
QUERIES = [
    # Valid Logic
    "Find x where x > 5 and x < 10",
    "Schedule A before B",
    "Map coloring with 3 regions",
    
    # Invalid Syntax (Should be fixed by Sanitizer or Reflection)
    "x = 5", 
    "A | B",
    
    # Malicious (Should be blocked by SafeEvaluator)
    "x > 0 and __import__('os').system('echo HACKED') == 0",
    "eval('print(1)') == 1",
    
    # Complex Chain
    " and ".join([f"x{i} > x{i+1}" for i in range(20)]) 
]

def send_request(query_id, query):
    start = time.time()
    try:
        response = requests.post(f"{BASE_URL}/verify/logic", json={"query": query}, timeout=30)
        latency = time.time() - start
        status = response.status_code
        
        try:
            data = response.json()
            result_status = data.get("status", "UNKNOWN")
        except:
            result_status = "PARSE_ERROR"
            
        return {
            "id": query_id,
            "status": status,
            "result": result_status,
            "latency": latency,
            "query": query[:30] + "..."
        }
    except Exception as e:
        return {
            "id": query_id,
            "status": "CONN_ERR",
            "result": str(e),
            "latency": time.time() - start,
            "query": query[:30] + "..."
        }

def run_stress_test(num_requests=50, concurrency=10):
    print(f"🚀 Starting Stress Test: {num_requests} requests (Concurrency: {concurrency})")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for i in range(num_requests):
            query = random.choice(QUERIES)
            futures.append(executor.submit(send_request, i, query))
            
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            print(".", end="", flush=True)
    print("\n")
        
    # Analyze Results
    success = 0
    blocked = 0
    errors = 0
    latencies = []
    
    for r in results:
        latencies.append(r['latency'])
        if r['status'] == 200:
            if r['result'] in ['SAT', 'UNSAT']:
                success += 1
            elif r['result'] == 'ERROR':
                # Check if it was a blocked attack
                if "Unsafe" in str(r) or "malicious" in str(r) or "not defined" in str(r):
                    blocked += 1
                else:
                    # If it's a malicious query, ERROR is GOOD.
                    if "import" in r['query'] or "eval" in r['query']:
                        blocked += 1
                    else:
                        errors += 1
        else:
            errors += 1
            
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    
    print("-" * 40)
    print(f"📊 Stress Test Results")
    print(f"Total Requests: {num_requests}")
    print(f"✅ Successful/Handled: {success}")
    print(f"🛡️ Blocked Attacks: {blocked}")
    print(f"❌ Failed/Crashed: {errors}")
    print(f"⏱️ Avg Latency: {avg_latency:.4f}s")
    print(f"🐢 Max Latency: {max_latency:.4f}s")
    print("-" * 40)
    
    if errors == 0:
        print("🏆 SYSTEM STABLE")
    else:
        print("⚠️ SYSTEM UNSTABLE (Check logs)")
        # Print first error detail
        for r in results:
            if r['status'] != 200 or (r['result'] not in ['SAT', 'UNSAT'] and "Unsafe" not in str(r) and "malicious" not in str(r) and "not defined" not in str(r)):
                print(f"Sample Failure: {r}")
                break

if __name__ == "__main__":
    run_stress_test(num_requests=50, concurrency=10)
