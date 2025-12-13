"""
Adversarial Legal Tests - Indian Context (IPC vs BNS)
Tests if LLMs can distinguish between the old Indian Penal Code (IPC) and the new Bharatiya Nyaya Sanhita (BNS) 2023.
Includes "Time Travel" traps and Source Citation checks.

Run: python benchmarks/deep_suite/adversarial_legal_tests.py
"""

import requests
import json
from datetime import datetime
import os

# Configuration
BASE_URL = "http://13.71.22.94:8000"
API_KEY = "qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI"

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

LEGAL_TESTS = [
    # 1. The "420" Trap (Cheating)
    {
        "id": "legal_bns_cheating",
        "query": "I have been accused of cheating and dishonestly inducing delivery of property. Under the new Bharatiya Nyaya Sanhita (BNS), which section applies?",
        "expected_keywords": ["Section 318", "318(4)"],
        "forbidden_keywords": ["Section 420"],
        "why_test": "Section 420 is repealed. BNS Section 318 is the new law.",
        "provider": "claude_opus"
    },

    # 2. The "302" Trap (Murder)
    {
        "id": "legal_bns_murder",
        "query": "What is the punishment for murder under the Bharatiya Nyaya Sanhita (BNS)? Cite the specific section.",
        "expected_keywords": ["Section 103"],
        "forbidden_keywords": ["Section 302"],
        "why_test": "IPC 302 is now BNS 103. Common hallucination.",
        "provider": "anthropic"
    },

    # 3. The "Sedition" Trap
    {
        "id": "legal_bns_sedition",
        "query": "Does the Bharatiya Nyaya Sanhita (BNS) have a section specifically titled 'Sedition' like IPC 124A?",
        "expected_keywords": ["No", "removed", "Section 152", "sovereignty"],
        "forbidden_keywords": ["Yes", "Section 124A is retained"],
        "why_test": "Sedition is replaced by 'Acts endangering sovereignty'.",
        "provider": "claude_opus"
    },

    # 4. Fake Section Hallucination
    {
        "id": "legal_fake_section",
        "query": "Explain the provisions of Section 500 of the Bharatiya Nyaya Sanhita (BNS).",
        "expected_keywords": ["does not exist", "invalid", "no such section"],
        "forbidden_keywords": ["defamation", "punishment"], # IPC 500 was defamation
        "why_test": "BNS only has 358 sections. Section 500 is a hallucination.",
        "provider": "anthropic"
    },

    # 5. Time Travel Trap (New!)
    {
        "id": "legal_time_trap",
        "query": "A crime was committed on June 30, 2024. Which law applies to the investigation - IPC or BNS?",
        "expected_keywords": ["IPC", "Indian Penal Code"],
        "forbidden_keywords": ["BNS", "Bharatiya Nyaya Sanhita"],
        "why_test": "BNS came into effect July 1, 2024. Crimes before that are IPC.",
        "provider": "claude_opus"
    },

    # 6. Source Citation Trap (New!)
    {
        "id": "legal_source_citation",
        "query": "Which section of BNS covers cheating? Cite the official source act year.",
        "expected_keywords": ["2023"],
        "forbidden_keywords": ["2022", "2024"],
        "why_test": "BNS is the Act of 2023. Models often hallucinate 2022 drafts.",
        "provider": "anthropic"
    }
]

def check_safety_first(answer, test):
    """Ensure AI warns BEFORE giving potentially dangerous info (less relevant for legal facts, but good practice)."""
    # For legal facts, we mostly care about correctness, but let's check for disclaimer if advice is given.
    # This is a placeholder for the medical tests where it matters more.
    return True, "Safe"

def run_test(test):
    print(f"\nTest: {test['id']}")
    print(f"Query: {test['query']}")
    
    payload = {
        "user_query": test['query'],
        "provider": test['provider']
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/verify/natural_language",
            headers=HEADERS,
            json=payload,
            timeout=30
        )
        data = response.json()
        answer = data.get("reasoning", "") + " " + str(data.get("result", ""))
        
        print(f"AI Answer: {answer[:300]}...") # Print first 300 chars
        
        # Check keywords
        passed = True
        missing = []
        found_forbidden = []
        
        for k in test['expected_keywords']:
            if k.lower() not in answer.lower():
                passed = False
                missing.append(k)
                
        for k in test.get('forbidden_keywords', []):
            if k.lower() in answer.lower():
                passed = False
                found_forbidden.append(k)
        
        # Safety Check (Optional for Legal Facts, but good to have)
        # safety_passed, safety_msg = check_safety_first(answer, test)
        # if not safety_passed:
        #     passed = False
        #     print(f"❌ FAILED SAFETY CHECK: {safety_msg}")

        if passed:
            print("✅ PASSED")
        else:
            print("❌ FAILED")
            if missing: print(f"   Missing: {missing}")
            if found_forbidden: print(f"   Found Forbidden: {found_forbidden}")
            
        return {
            "id": test['id'],
            "query": test['query'],
            "expected": test['expected_keywords'],
            "forbidden": test.get('forbidden_keywords', []),
            "ai_answer": answer,
            "passed": passed,
            "missing": missing,
            "found_forbidden": found_forbidden
        }
        
    except Exception as e:
        print(f"Error: {e}")
        return {
            "id": test['id'],
            "error": str(e),
            "passed": False
        }

if __name__ == "__main__":
    print("Running Adversarial Legal Tests (IPC vs BNS)...")
    results = []
    passed_count = 0
    
    for t in LEGAL_TESTS:
        res = run_test(t)
        results.append(res)
        if res.get("passed"):
            passed_count += 1
            
    print(f"\nResult: {passed_count}/{len(LEGAL_TESTS)} passed")
    
    # Save Report
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": len(LEGAL_TESTS),
        "passed": passed_count,
        "failed": len(LEGAL_TESTS) - passed_count,
        "results": results
    }
    
    with open("adversarial_legal_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("Saved full log to adversarial_legal_report.json")
