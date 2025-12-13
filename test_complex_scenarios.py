import requests
import json
import textwrap
import base64
import math

BASE_URL = "http://127.0.0.1:8002"

def print_header(title):
    print("\n" + "=" * 60)
    print(f"🧪 {title}")
    print("=" * 60)

def test_complex_math():
    print_header("1. Complex Math: Calculus")
    query = "What is the derivative of x**3 + 2*x**2 + 5 at x = 3?"
    print(f"Query: '{query}'")
    
    try:
        response = requests.post(f"{BASE_URL}/verify/natural_language", json={"query": query})
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Status: {result['status']}")
            print(f"✅ Answer: {result['final_answer']}")
            
            # Derivative is 3x^2 + 4x. At x=3: 3(9) + 4(3) = 27 + 12 = 39.
            val = float(result['final_answer'])
            if math.isclose(val, 39.0, rel_tol=1e-5):
                print("🎯 Correct!")
                return True
            else:
                print(f"⚠️ Expected 39.0, got {val}")
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_complex_logic():
    print_header("2. Complex Logic: Map Coloring")
    query = "Color a map with 3 regions (A, B, C) using Red, Green, Blue such that A touches B, B touches C, and A touches C. No adjacent regions can have the same color."
    print(f"Query: '{query}'")
    
    try:
        response = requests.post(f"{BASE_URL}/verify/logic", json={"query": query})
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Status: {result['status']}")
            if result['status'] == 'SAT':
                print(f"✅ Model: {result['model']}")
                # Check distinct colors
                colors = list(result['model'].values())
                unique_colors = set(str(c) for c in colors)
                if len(unique_colors) == 3:
                    print("🎯 Correct! 3 distinct colors used.")
                    return True
                else:
                    print(f"⚠️ Model does not use distinct colors: {unique_colors}")
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_complex_stats():
    print_header("3. Complex Stats: Groupby & Aggregation")
    csv_content = "Category,Value\nA,10\nA,20\nB,30\nB,40\nC,50"
    query = "What is the average value for Category A?"
    print(f"Query: '{query}'")
    
    try:
        files = {'file': ('test.csv', csv_content, 'text/csv')}
        data = {'query': query}
        response = requests.post(f"{BASE_URL}/verify/stats", files=files, data=data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Result: {result['result']}")
            # Average of 10 and 20 is 15.
            if str(result['result']) == "15.0":
                print("🎯 Correct!")
                return True
            else:
                print(f"⚠️ Expected 15.0, got {result['result']}")
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_complex_facts():
    print_header("4. Complex Facts: Synthesis")
    context = """
    The project started in 2020.
    It was delayed by 2 years due to the pandemic.
    It finally launched in 2023.
    """
    claim = "The project launched 3 years after it started."
    print(f"Claim: '{claim}'")
    
    try:
        data = {"claim": claim, "context": context}
        response = requests.post(f"{BASE_URL}/verify/fact", json=data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Verdict: {result['verdict']}")
            print(f"✅ Reasoning: {result['reasoning']}")
            # 2020 to 2023 is 3 years.
            if result['verdict'] == "SUPPORTED":
                print("🎯 Correct!")
                return True
            else:
                print("⚠️ Expected SUPPORTED.")
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def test_obfuscated_code():
    print_header("5. Obfuscated Code Security")
    # base64 encoded "import os; os.system('ls')"
    # This tests if the verifier can catch obfuscation or if it fails (which is also a finding).
    # Currently, our verifier is static AST/Regex, so it might MISS this if not decoded.
    # BUT, we should test if it catches the *attempt* or if we need to improve it.
    # Let's test a simpler obfuscation: eval(base64.b64decode(...))
    
    code = textwrap.dedent("""
    import base64
    payload = "cHJpbnQoJ2hhY2tlZCcp"
    eval(base64.b64decode(payload))
    """)
    print(f"Code: (Obfuscated eval)")
    
    try:
        response = requests.post(f"{BASE_URL}/verify/code", json={"code": code})
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Safe: {result['is_safe']}")
            print(f"✅ Issues: {result['issues']}")
            # Should catch 'eval'
            if not result['is_safe'] and "Use of dangerous function: eval" in result['issues']:
                print("🎯 Correct! Caught eval.")
                return True
            else:
                print("⚠️ Failed to catch eval.")
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    return False

def run_complex_tests():
    print("\n🚀 Starting Advanced Scenario Tests...")
    
    results = {
        "Math (Calculus)": test_complex_math(),
        "Logic (Map Coloring)": test_complex_logic(),
        "Stats (Groupby)": test_complex_stats(),
        "Facts (Synthesis)": test_complex_facts(),
        "Code (Obfuscation)": test_obfuscated_code()
    }
    
    print("\n" + "=" * 60)
    print("📊 Advanced Test Summary")
    print("=" * 60)
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name}: {status}")

if __name__ == "__main__":
    run_complex_tests()
