import requests
import json
import io
import textwrap
import time

BASE_URL = "http://127.0.0.1:8002"

def print_header(title):
    print("\n" + "=" * 60)
    print(f"🧪 {title}")
    print("=" * 60)

def test_engine_1_math():
    print_header("Testing Engine 1: Math Verifier (SymPy)")
    query = "What is 15% of 200?"
    print(f"Query: '{query}'")
    
    try:
        response = requests.post(f"{BASE_URL}/verify/natural_language", json={"query": query})
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Status: {result['status']}")
            print(f"✅ Answer: {result['final_answer']}")
            if result['final_answer'] == 30.0:
                return True
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_engine_2_logic():
    print_header("Testing Engine 2: Logic Verifier (Z3)")
    query = "Find two integers x and y where x is greater than y and their sum is 10."
    print(f"Query: '{query}'")
    
    try:
        response = requests.post(f"{BASE_URL}/verify/logic", json={"query": query})
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Status: {result['status']}")
            if result['status'] == 'SAT':
                print(f"✅ Model: {result['model']}")
                return True
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_engine_3_stats():
    print_header("Testing Engine 3: Statistical Verifier (Pandas)")
    csv_content = "Date,Product,Sales\n2023-01-01,Widget A,100\n2023-01-02,Widget B,150\n2023-01-03,Widget A,120"
    query = "What is the total sales for Widget A?"
    print(f"Query: '{query}'")
    
    try:
        files = {'file': ('test.csv', csv_content, 'text/csv')}
        data = {'query': query}
        response = requests.post(f"{BASE_URL}/verify/stats", files=files, data=data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Result: {result['result']}")
            print(f"✅ Code: {result['code']}")
            if str(result['result']) == "220":
                return True
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_engine_4_facts():
    print_header("Testing Engine 4: Fact Verifier (Citation)")
    context = "The policy covers water damage from burst pipes but excludes floods."
    claim = "The policy covers floods."
    print(f"Claim: '{claim}'")
    
    try:
        data = {"claim": claim, "context": context}
        response = requests.post(f"{BASE_URL}/verify/fact", json=data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Verdict: {result['verdict']}")
            print(f"✅ Reasoning: {result['reasoning']}")
            if result['verdict'] == "REFUTED":
                return True
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_engine_5_code():
    print_header("Testing Engine 5: Code Security Verifier")
    code = "import os; os.system('rm -rf /')"
    print(f"Code: '{code}'")
    
    try:
        response = requests.post(f"{BASE_URL}/verify/code", json={"code": code})
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Safe: {result['is_safe']}")
            print(f"✅ Issues: {result['issues']}")
            if not result['is_safe']:
                return True
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def run_comprehensive_test():
    print("\n🚀 Starting Comprehensive System Test...")
    print(f"Target: {BASE_URL}")
    
    results = {
        "Engine 1 (Math)": test_engine_1_math(),
        "Engine 2 (Logic)": test_engine_2_logic(),
        "Engine 3 (Stats)": test_engine_3_stats(),
        "Engine 4 (Facts)": test_engine_4_facts(),
        "Engine 5 (Code)": test_engine_5_code()
    }
    
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    all_passed = True
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name}: {status}")
        if not passed:
            all_passed = False
            
    if all_passed:
        print("\n🎉 ALL SYSTEMS GO! QWED is fully operational.")
    else:
        print("\n⚠️ Some systems failed checks.")

if __name__ == "__main__":
    run_comprehensive_test()
