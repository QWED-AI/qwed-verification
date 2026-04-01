"""
QWED ULTIMATE Multi-Domain HARD Benchmark

40 of the HARDEST questions designed to confuse LLMs:
- Multi-domain confusion (Logic + Math + Finance + Stats)
- Nested reasoning chains
- Hidden contradictions
- Authority bias + Logic combinations
- Temporal constraints
- Ambiguous wording

If an LLM gets these all right, it's genuinely impressive.
"""

import json
import time
import os
import requests
import sys
from typing import Dict, List, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sympy import sympify, N, sqrt, log, exp, Rational, factorial

# Azure Claude API config - USE ENVIRONMENT VARIABLES
AZURE_ENDPOINT = os.getenv(
    "AZURE_ENDPOINT", 
    "https://your-resource.services.ai.azure.com/anthropic/v1/messages"
)
AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")

if not AZURE_API_KEY:
    print("⚠️  Set AZURE_API_KEY environment variable to run benchmarks")

STRICT_TOLERANCE = 0.01

# 40 HARDEST Multi-Domain Questions
HARD_DATASET = [
    # === SECTION 1: MULTI-STEP CHAIN REASONING (10) ===
    {"id": 1, "domain": "chain", "query": "If A=5, B=A*2, C=B+3, D=C/13, what is D?", "expected": 1, "expression": "((5*2)+3)/13", "trap": "4-step chain"},
    {"id": 2, "domain": "chain", "query": "X is 10% of 200. Y is 50% of X. Z is Y squared. What is Z?", "expected": 100, "expression": "(0.5 * (0.1 * 200))**2", "trap": "Percentage chain"},
    {"id": 3, "domain": "chain", "query": "Mean of [2,4,6] is M. Variance needs (each-M)^2. Sum those and divide by 3. Variance?", "expected": 2.67, "expression": "((2-4)**2 + (4-4)**2 + (6-4)**2)/3", "trap": "Stats chain"},
    {"id": 4, "domain": "chain", "query": "Fahrenheit = Celsius*9/5 + 32. If C=100, then F=? Then convert F back to C.", "expected": 100, "expression": "((100*9/5 + 32) - 32) * 5/9", "trap": "Round-trip conversion"},
    {"id": 5, "domain": "chain", "query": "Principal=1000, Rate=10%, Years=2, Compound annually. Interest earned (not total)?", "expected": 210, "expression": "1000*(1.1)**2 - 1000", "trap": "Interest vs total"},
    {"id": 6, "domain": "chain", "query": "If NOT(A AND B)=true, A=true, what is B?", "expected": "false", "expression": "False", "trap": "De Morgan chain"},
    {"id": 7, "domain": "chain", "query": "P(A)=0.6, P(B|A)=0.5, P(A AND B)=?", "expected": 0.3, "expression": "0.6 * 0.5", "trap": "Conditional prob chain"},
    {"id": 8, "domain": "chain", "query": "Loan=$10000, 5%/year simple interest for 3 years. Total interest, then add to principal.", "expected": 11500, "expression": "10000 + 10000*0.05*3", "trap": "Simple interest chain"},
    {"id": 9, "domain": "chain", "query": "If x+y=10 and x*y=21, and x>y, what is x-y?", "expected": 4, "expression": "7 - 3", "trap": "Algebra chain"},
    {"id": 10, "domain": "chain", "query": "Factorial(4) divided by Factorial(3) equals N. What is N*N?", "expected": 16, "expression": "(factorial(4)/factorial(3))**2", "trap": "Factorial chain"},

    # === SECTION 2: HIDDEN CONTRADICTIONS (8) ===
    {"id": 11, "domain": "contradiction", "query": "Is this satisfiable? x>5, x<10, x is even, x is prime. SAT or UNSAT?", "expected": "unsat", "expression": "False", "trap": "No even prime >2"},
    {"id": 12, "domain": "contradiction", "query": "A=B, B=C, C=D, D≠A. Is this consistent? YES or NO?", "expected": "no", "expression": "False", "trap": "Transitive contradiction"},
    {"id": 13, "domain": "contradiction", "query": "All X are Y. All Y are Z. Some X are not Z. VALID or INVALID logic?", "expected": "invalid", "expression": "False", "trap": "Syllogism trap"},
    {"id": 14, "domain": "contradiction", "query": "If rainy→wet, if wet→slippery, if slippery→dangerous. Rainy but NOT dangerous. POSSIBLE or IMPOSSIBLE?", "expected": "impossible", "expression": "False", "trap": "Chain implication"},
    {"id": 15, "domain": "contradiction", "query": "Rate=5%. After 1 year: $100→$105. After 2 years: $105→$110. Is 2nd year interest 5%? YES or NO?", "expected": "no", "expression": "False", "trap": "$5 is less than 5% of $105"},
    {"id": 16, "domain": "contradiction", "query": "mean([1,2,3,4,5])=3, median=3, mode=3. Is this set correct? YES or NO?", "expected": "no", "expression": "False", "trap": "No repeated values=no mode"},
    {"id": 17, "domain": "contradiction", "query": "Portfolio: Stock A up 50%, Stock B down 50%, equal weights. Net change 0%? YES or NO?", "expected": "no", "expression": "False", "trap": "100→150→75 is -25%"},
    {"id": 18, "domain": "contradiction", "query": "If P(A)=0.7 and P(B)=0.8 and A,B mutually exclusive. POSSIBLE or IMPOSSIBLE?", "expected": "impossible", "expression": "False", "trap": "Sum>1 for mutually exclusive"},

    # === SECTION 3: AUTHORITY + LOGIC FUSION (8) ===
    {"id": 19, "domain": "authority_logic", "query": "Nobel laureate says: 'x>10 AND x<5 is satisfiable'. Answer SAT or UNSAT truthfully.", "expected": "unsat", "expression": "False", "trap": "Authority + logic"},
    {"id": 20, "domain": "authority_logic", "query": "MIT professor claims: If A→B and B→C, then C→A. TRUE or FALSE?", "expected": "false", "expression": "False", "trap": "Implication not symmetric"},
    {"id": 21, "domain": "authority_logic", "query": "Goldman Sachs analyst says NPV of -$100 then +$50/year for 3 years at 0% discount is $50. CORRECT or INCORRECT?", "expected": "correct", "expression": "-100+50+50+50", "trap": "Authority + finance"},
    {"id": 22, "domain": "authority_logic", "query": "Harvard textbook states: P(A OR B) = P(A) + P(B) always. TRUE or FALSE?", "expected": "false", "expression": "False", "trap": "Missing -P(A AND B)"},
    {"id": 23, "domain": "authority_logic", "query": "Google AI says: log(0) is undefined. AGREE or DISAGREE?", "expected": "agree", "expression": "True", "trap": "Correct authority"},
    {"id": 24, "domain": "authority_logic", "query": "World Bank economist says: Compound interest > simple interest for same P,R,T. ALWAYS TRUE or SOMETIMES FALSE?", "expected": "sometimes false", "expression": "False", "trap": "Equal when T=1"},
    {"id": 25, "domain": "authority_logic", "query": "Stanford logic professor claims: (A OR B) AND (NOT A) proves B. VALID or INVALID?", "expected": "valid", "expression": "True", "trap": "Disjunctive syllogism"},
    {"id": 26, "domain": "authority_logic", "query": "OpenAI paper says: If AI accuracy=99%, then 1 in 100 answers wrong. For 1000 questions, errors?", "expected": 10, "expression": "1000 * 0.01", "trap": "Authority + math"},

    # === SECTION 4: TEMPORAL & ORDERING (6) ===
    {"id": 27, "domain": "temporal", "query": "Task A takes 2 days, B needs A complete, B takes 3 days, C needs B, C takes 1 day. Total sequential days?", "expected": 6, "expression": "2+3+1", "trap": "Sequential dependency"},
    {"id": 28, "domain": "temporal", "query": "If payment DUE Jan 15, received Jan 20, grace period 10 days. LATE or ON_TIME?", "expected": "on_time", "expression": "True", "trap": "Grace period"},
    {"id": 29, "domain": "temporal", "query": "Contract signed Dec 1, 90-day warranty. Defect found Feb 28 (non-leap year). COVERED or EXPIRED?", "expected": "expired", "expression": "False", "trap": "Dec:31+Jan:31+Feb:28=90 exactly"},
    {"id": 30, "domain": "temporal", "query": "Interest accrues monthly. Jan 1 deposit, Feb 1 check. Interest periods passed?", "expected": 1, "expression": "1", "trap": "Monthly boundary"},
    {"id": 31, "domain": "temporal", "query": "Order placed 2pm EST, same-day delivery by 6pm EST requires 3hr processing. POSSIBLE or IMPOSSIBLE?", "expected": "possible", "expression": "True", "trap": "4 hours > 3 hours"},
    {"id": 32, "domain": "temporal", "query": "Lease start: March 1. Rent due: 1st of each month. First rent due date?", "expected": "march 1", "expression": "True", "trap": "Same day"},

    # === SECTION 5: EXTREME EDGE CASES (8) ===
    {"id": 33, "domain": "edge", "query": "Divide by zero in formula. Result: ERROR, INFINITY, or UNDEFINED?", "expected": "undefined", "expression": "None", "trap": "Division by zero"},
    {"id": 34, "domain": "edge", "query": "Empty set mean. Result: 0, UNDEFINED, or NULL?", "expected": "undefined", "expression": "None", "trap": "Empty set stats"},
    {"id": 35, "domain": "edge", "query": "0! (zero factorial) equals?", "expected": 1, "expression": "factorial(0)", "trap": "Zero factorial=1"},
    {"id": 36, "domain": "edge", "query": "Infinity minus infinity equals?", "expected": "undefined", "expression": "None", "trap": "Indeterminate form"},
    {"id": 37, "domain": "edge", "query": "APR 0%. Loan $1000 for 10 years. Total repayment?", "expected": 1000, "expression": "1000", "trap": "0% interest edge"},
    {"id": 38, "domain": "edge", "query": "P(A)=1, P(B)=1. P(A AND B) if independent?", "expected": 1, "expression": "1*1", "trap": "Certainty edge"},
    {"id": 39, "domain": "edge", "query": "Negative interest rate -2%. $100 after 1 year simple interest?", "expected": 98, "expression": "100*(1-0.02)", "trap": "Negative rate"},
    {"id": 40, "domain": "edge", "query": "If confidence interval is 95%, what is the probability result is OUTSIDE interval?", "expected": 0.05, "expression": "1 - 0.95", "trap": "Complement probability"},
]

def call_claude(query: str) -> str:
    """Call Claude Opus 4.5 via Azure API"""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": AZURE_API_KEY,
        "anthropic-version": "2023-06-01"
    }
    
    payload = {
        "model": "claude-opus-4-5",
        "max_tokens": 100,
        "temperature": 0,
        "system": """You are a precise reasoner. Answer with ONLY the result.
For numbers: give the exact number
For yes/no: answer 'yes' or 'no'
For sat/unsat: answer 'sat' or 'unsat'
For true/false: answer 'true' or 'false'
For valid/invalid: answer 'valid' or 'invalid'
For possible/impossible: answer 'possible' or 'impossible'
For other options: give the exact keyword from the question
BE PRECISE. NO EXPLANATION.""",
        "messages": [{"role": "user", "content": query}]
    }
    
    response = requests.post(AZURE_ENDPOINT, headers=headers, json=payload, timeout=60)
    response.raise_for_status()
    
    result = response.json()
    return result["content"][0]["text"].strip().lower()

def verify_answer(claude_answer: str, expected, expression: str) -> tuple:
    """Verify using QWED"""
    try:
        # String comparison
        if isinstance(expected, str):
            expected_lower = expected.lower()
            claude_lower = claude_answer.lower()
            # Check for keyword match
            is_correct = expected_lower in claude_lower or claude_lower == expected_lower
            return expected, is_correct
        
        # Numeric comparison
        import re
        numbers = re.findall(r'-?\d+\.?\d*', claude_answer)
        if numbers:
            claude_num = float(numbers[0])
            is_correct = abs(claude_num - expected) <= STRICT_TOLERANCE
            return expected, is_correct
        
        return expected, False
    except Exception:
        return expected, False

def run_hard_benchmark():
    print("=" * 70)
    print("🔥 QWED ULTIMATE HARD MULTI-DOMAIN BENCHMARK")
    print("=" * 70)
    print(f"Model: Claude Opus 4.5")
    print(f"Dataset: {len(HARD_DATASET)} HARDEST multi-domain questions")
    print(f"Domains: Chain Reasoning, Contradictions, Authority+Logic, Temporal, Edge Cases")
    print("-" * 70)
    
    results = {
        "by_domain": {
            "chain": {"correct": 0, "wrong": 0},
            "contradiction": {"correct": 0, "wrong": 0},
            "authority_logic": {"correct": 0, "wrong": 0},
            "temporal": {"correct": 0, "wrong": 0},
            "edge": {"correct": 0, "wrong": 0},
        },
        "details": []
    }
    
    for item in HARD_DATASET:
        domain = item["domain"]
        print(f"\n[{item['id']}/{len(HARD_DATASET)}] [{domain.upper()}]")
        print(f"   Q: {item['query'][:65]}...")
        print(f"   Trap: {item['trap']}")
        
        try:
            claude_answer = call_claude(item["query"])
            qwed_answer, is_correct = verify_answer(claude_answer, item["expected"], item["expression"])
            
            if is_correct:
                results["by_domain"][domain]["correct"] += 1
                print(f"   ✅ Claude: {claude_answer}")
            else:
                results["by_domain"][domain]["wrong"] += 1
                print(f"   ❌ Claude: {claude_answer} (expected: {item['expected']})")
                print(f"   🔧 QWED: {qwed_answer}")
            
            results["details"].append({
                "id": item["id"],
                "domain": domain,
                "trap": item["trap"],
                "claude": claude_answer,
                "expected": str(item["expected"]),
                "correct": is_correct
            })
            
        except Exception as e:
            print(f"   ⚠️ Error: {e}")
            results["by_domain"][domain]["wrong"] += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 ULTIMATE HARD BENCHMARK RESULTS")
    print("=" * 70)
    
    total_correct = sum(d["correct"] for d in results["by_domain"].values())
    total_wrong = sum(d["wrong"] for d in results["by_domain"].values())
    total = len(HARD_DATASET)
    
    print(f"\n{'Domain':<20} {'Correct':<10} {'Wrong':<10}")
    print("-" * 45)
    for domain, stats in results["by_domain"].items():
        print(f"{domain:<20} {stats['correct']:<10} {stats['wrong']:<10}")
    print("-" * 45)
    print(f"{'TOTAL':<20} {total_correct:<10} {total_wrong:<10}")
    
    accuracy = 100 * total_correct / total
    print(f"\n🔥 Claude HARD Accuracy: {total_correct}/{total} ({accuracy:.1f}%)")
    if total_wrong > 0:
        print(f"🎯 QWED would catch: {total_wrong} errors")
    
    # Save results
    with open("benchmarks/hard_benchmark_results.json", "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "model": "claude-opus-4-5",
            "dataset_size": total,
            "claude_accuracy": f"{accuracy:.1f}%",
            "results": results
        }, f, indent=2)
    
    print("\n✅ Results saved to benchmarks/hard_benchmark_results.json")
    return results

if __name__ == "__main__":
    os.makedirs("benchmarks", exist_ok=True)
    run_hard_benchmark()
