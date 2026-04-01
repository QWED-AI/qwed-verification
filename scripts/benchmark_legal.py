"""
QWED Legal/Compliance Benchmark - 40 HARDEST Questions

Tests LLM's ability to verify:
- Indian regulations (GST, RBI, SEBI, IT Act)
- Global regulations (GDPR, HIPAA, SOX, PCI-DSS)
- Contract terms and conditions
- Compliance calculations
- Legal reasoning

Critical for banking, fintech, legal tech, and enterprise compliance.
"""

import json
import time
import os
import requests
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Azure Claude API config - USE ENVIRONMENT VARIABLES
AZURE_ENDPOINT = os.getenv(
    "AZURE_ENDPOINT", 
    "https://your-resource.services.ai.azure.com/anthropic/v1/messages"
)
AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")

if not AZURE_API_KEY:
    print("⚠️  Set AZURE_API_KEY environment variable to run benchmarks")

# 40 Legal/Compliance Questions (Indian + Global)
LEGAL_DATASET = [
    # === INDIAN GST (8) ===
    {"id": 1, "domain": "gst", "query": "GST on food items in restaurant with AC: 5% or 18%?", "expected": "5", "trap": "Restaurant GST is 5%"},
    {"id": 2, "domain": "gst", "query": "GST on software services (SaaS) in India: 18% or 28%?", "expected": "18", "trap": "Software is 18%"},
    {"id": 3, "domain": "gst", "query": "GST registration mandatory if turnover exceeds: 20 lakh or 40 lakh for goods?", "expected": "40", "trap": "40L for goods, 20L for services"},
    {"id": 4, "domain": "gst", "query": "E-way bill required for goods value above: 50000 or 100000 INR?", "expected": "50000", "trap": "50K threshold"},
    {"id": 5, "domain": "gst", "query": "GSTR-3B due date for normal taxpayer: 20th or 25th of next month?", "expected": "20", "trap": "20th for GSTR-3B"},
    {"id": 6, "domain": "gst", "query": "Input Tax Credit available on: Business expenses or Personal expenses?", "expected": "business", "trap": "ITC only for business"},
    {"id": 7, "domain": "gst", "query": "GST on educational services by recognized institution: EXEMPT or 18%?", "expected": "exempt", "trap": "Education exempt"},
    {"id": 8, "domain": "gst", "query": "Reverse charge applies when buying from: Registered or Unregistered dealer?", "expected": "unregistered", "trap": "RCM for unregistered"},

    # === RBI & BANKING (India) (8) ===
    {"id": 9, "domain": "rbi", "query": "RTGS minimum amount: 2 lakh or No minimum now?", "expected": "no minimum", "trap": "Minimum removed in 2020"},
    {"id": 10, "domain": "rbi", "query": "NEFT operates: 24x7 or Banking hours only?", "expected": "24x7", "trap": "NEFT 24x7 since Dec 2019"},
    {"id": 11, "domain": "rbi", "query": "Bank Savings account interest up to ₹10,000 taxable under: Section 80TTA (deduction) or fully taxable?", "expected": "80tta", "trap": "80TTA allows 10K deduction"},
    {"id": 12, "domain": "rbi", "query": "FD interest TDS threshold: 40000 or 50000 for senior citizens?", "expected": "50000", "trap": "50K for seniors, 40K for others"},
    {"id": 13, "domain": "rbi", "query": "UPI transaction limit: 1 lakh or 2 lakh per transaction?", "expected": "1", "trap": "1 lakh default limit"},
    {"id": 14, "domain": "rbi", "query": "Cash withdrawal limit from ATM per day: 20000 or 25000 typically?", "expected": "25000", "trap": "Usually 25K"},
    {"id": 15, "domain": "rbi", "query": "PAN mandatory for cash transactions above: 50000 or 200000?", "expected": "50000", "trap": "50K needs PAN"},
    {"id": 16, "domain": "rbi", "query": "Foreign remittance under LRS limit per year: 2.5 lakh USD or 250000 USD?", "expected": "250000", "trap": "$250K LRS limit"},

    # === GDPR (Global) (8) ===
    {"id": 17, "domain": "gdpr", "query": "GDPR applies to: Only EU companies or Any company processing EU citizen data?", "expected": "any", "trap": "Applies globally for EU data"},
    {"id": 18, "domain": "gdpr", "query": "Data breach notification deadline under GDPR: 72 hours or 30 days?", "expected": "72", "trap": "72 hours to authority"},
    {"id": 19, "domain": "gdpr", "query": "Right to be forgotten under GDPR: Absolute right or Conditional right?", "expected": "conditional", "trap": "Has exceptions"},
    {"id": 20, "domain": "gdpr", "query": "GDPR max fine: 2% revenue or 4% revenue or 20M EUR?", "expected": "4", "trap": "4% or 20M, whichever higher"},
    {"id": 21, "domain": "gdpr", "query": "DPO (Data Protection Officer) mandatory for: All companies or Only certain types?", "expected": "certain", "trap": "Only public/large scale processing"},
    {"id": 22, "domain": "gdpr", "query": "GDPR consent must be: Implied or Explicit?", "expected": "explicit", "trap": "Clear affirmative action"},
    {"id": 23, "domain": "gdpr", "query": "Data portability under GDPR: Machine readable format required or Any format?", "expected": "machine readable", "trap": "Structured format required"},
    {"id": 24, "domain": "gdpr", "query": "Privacy by Design under GDPR: Recommended or Mandatory?", "expected": "mandatory", "trap": "Article 25 mandate"},

    # === SEBI & Companies Act (India) (8) ===
    {"id": 25, "domain": "sebi", "query": "Insider trading prohibition applies: Pre-IPO or Post-listing or Both?", "expected": "both", "trap": "Both stages covered"},
    {"id": 26, "domain": "sebi", "query": "Related party transaction approval: Audit committee or Board or Shareholders?", "expected": "audit committee", "trap": "AC approves RPT"},
    {"id": 27, "domain": "sebi", "query": "Minimum public holding for listed company: 25% or 35%?", "expected": "25", "trap": "25% minimum public"},
    {"id": 28, "domain": "sebi", "query": "Board meeting frequency for listed company: Every quarter or Every 6 months?", "expected": "quarter", "trap": "Quarterly minimum"},
    {"id": 29, "domain": "sebi", "query": "Independent director tenure max: 5 years or 2 terms of 5 years each?", "expected": "2 terms", "trap": "Max 2 consecutive terms"},
    {"id": 30, "domain": "sebi", "query": "CSR spending mandatory for: All companies or Net worth/turnover threshold?", "expected": "threshold", "trap": "5cr profit or 1000cr turnover"},
    {"id": 31, "domain": "sebi", "query": "Buyback of shares max: 10% or 25% of paid-up capital?", "expected": "25", "trap": "25% max buyback"},
    {"id": 32, "domain": "sebi", "query": "LODR compliance required from: Date of listing or Date of filing?", "expected": "listing", "trap": "From listing date"},

    # === CONTRACT & COMPLIANCE (Global) (8) ===
    {"id": 33, "domain": "contract", "query": "Force majeure clause excuses: All delays or Only unforeseeable events?", "expected": "unforeseeable", "trap": "Must be unforeseeable"},
    {"id": 34, "domain": "contract", "query": "Non-compete clause valid in: All states or Varies by jurisdiction?", "expected": "varies", "trap": "California bans them"},
    {"id": 35, "domain": "contract", "query": "Penalty clause enforceable: As written or Limited to actual damages?", "expected": "actual damages", "trap": "Courts limit to actual loss"},
    {"id": 36, "domain": "contract", "query": "SOX compliance required for: All US companies or Public companies?", "expected": "public", "trap": "Only public companies"},
    {"id": 37, "domain": "contract", "query": "PCI-DSS applies to: Payment processors only or Any company handling card data?", "expected": "any", "trap": "All card handlers"},
    {"id": 38, "domain": "contract", "query": "HIPAA breach notification: Within 60 days or Within 30 days?", "expected": "60", "trap": "60 days for HIPAA"},
    {"id": 39, "domain": "contract", "query": "Arbitration clause: Always enforceable or Can be challenged?", "expected": "challenged", "trap": "Unconscionability defense"},
    {"id": 40, "domain": "contract", "query": "NDA typically survives contract termination: Yes or No?", "expected": "yes", "trap": "Survival clause common"},
]

def call_claude(query: str) -> str:
    """Call Claude Opus 4.5"""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": AZURE_API_KEY,
        "anthropic-version": "2023-06-01"
    }
    
    payload = {
        "model": "claude-opus-4-5",
        "max_tokens": 50,
        "temperature": 0,
        "system": """You are a legal and compliance expert for Indian and Global regulations.
Answer with ONLY the keyword or number that answers the question.
Be precise. Just the answer, nothing else.
For numbers, give just the number.
For yes/no, say 'yes' or 'no'.
For choices like 'A or B', give just the correct option.""",
        "messages": [{"role": "user", "content": query}]
    }
    
    response = requests.post(AZURE_ENDPOINT, headers=headers, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()["content"][0]["text"].strip().lower()

def run_legal_benchmark():
    print("=" * 70)
    print("⚖️  QWED LEGAL/COMPLIANCE BENCHMARK")
    print("=" * 70)
    print(f"Model: Claude Opus 4.5")
    print(f"Dataset: {len(LEGAL_DATASET)} legal/compliance questions")
    print(f"Domains: GST, RBI, GDPR, SEBI, Contract Law")
    print("-" * 70)
    
    results = {
        "by_domain": {
            "gst": {"correct": 0, "wrong": 0},
            "rbi": {"correct": 0, "wrong": 0},
            "gdpr": {"correct": 0, "wrong": 0},
            "sebi": {"correct": 0, "wrong": 0},
            "contract": {"correct": 0, "wrong": 0},
        },
        "details": []
    }
    
    for item in LEGAL_DATASET:
        domain = item["domain"]
        print(f"\n[{item['id']}/{len(LEGAL_DATASET)}] [{domain.upper()}]")
        print(f"   Q: {item['query'][:60]}...")
        print(f"   Trap: {item['trap']}")
        
        try:
            claude = call_claude(item["query"])
            expected = str(item["expected"]).lower()
            # Check if expected is in claude's answer or exact match
            is_correct = expected in claude or claude == expected
            
            if is_correct:
                results["by_domain"][domain]["correct"] += 1
                print(f"   ✅ Claude: {claude}")
            else:
                results["by_domain"][domain]["wrong"] += 1
                print(f"   ❌ Claude: {claude} (expected: {expected})")
            
            results["details"].append({
                "id": item["id"], "domain": domain, "trap": item["trap"],
                "claude": claude, "expected": expected, "correct": is_correct
            })
        except Exception as e:
            print(f"   ⚠️ Error: {e}")
            results["by_domain"][domain]["wrong"] += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 LEGAL/COMPLIANCE RESULTS")
    print("=" * 70)
    
    total_correct = sum(d["correct"] for d in results["by_domain"].values())
    total_wrong = sum(d["wrong"] for d in results["by_domain"].values())
    
    print(f"\n{'Domain':<15} {'Correct':<10} {'Wrong':<10}")
    print("-" * 40)
    for domain, stats in results["by_domain"].items():
        print(f"{domain:<15} {stats['correct']:<10} {stats['wrong']:<10}")
    print("-" * 40)
    print(f"{'TOTAL':<15} {total_correct:<10} {total_wrong:<10}")
    
    accuracy = 100 * total_correct / len(LEGAL_DATASET)
    print(f"\n⚖️  Claude Legal Accuracy: {total_correct}/{len(LEGAL_DATASET)} ({accuracy:.1f}%)")
    if total_wrong > 0:
        print(f"\n⚠️  In compliance, wrong answers = regulatory penalties!")
    
    with open("benchmarks/legal_benchmark_results.json", "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "accuracy": f"{accuracy:.1f}%", "results": results}, f, indent=2)
    
    print("\n✅ Results saved to benchmarks/legal_benchmark_results.json")
    return results

if __name__ == "__main__":
    os.makedirs("benchmarks", exist_ok=True)
    run_legal_benchmark()
