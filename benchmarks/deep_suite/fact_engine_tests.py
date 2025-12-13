"""
Fact Engine Adversarial Tests - Test citation-based fact verification
Tests if Claude correctly verifies claims against context and detects misinformation.

Run: python benchmarks/deep_suite/fact_engine_tests.py
"""

import requests
import json
from datetime import datetime
from typing import Dict, List

# Configuration
BASE_URL = "http://13.71.22.94:8000"
API_KEY = "qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI"

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

FACT_ENGINE_TESTS = [
    # Category A: Clearly supported claims
    {
        "id": "fact_supported_01",
        "claim": "The company's revenue increased by 25% in Q3",
        "context": "Financial Report Q3 2024: Revenue grew from $40M in Q2 to $50M in Q3, representing a 25% increase.",
        "expected_verdict": "SUPPORTED",
        "why_test": "Direct factual match",
        "provider": "anthropic"
    },
    
    {
        "id": "fact_supported_02",
        "claim": "The policy covers water damage",
        "context": "Insurance Policy Section 4: This policy provides coverage for damages caused by water, fire, and theft.",
        "expected_verdict": "SUPPORTED",
        "why_test": "Explicit statement in context",
        "provider": "claude_opus"
    },
    
    # Category B: Clearly refuted claims
    {
        "id": "fact_refuted_01",
        "claim": "The product launch was successful",
        "context": "Product Launch Report: The launch failed to meet targets, with only 1,000 units sold versus the 10,000 unit goal.",
        "expected_verdict": "REFUTED",
        "why_test": "Context contradicts claim",
        "provider": "anthropic"
    },
    
    {
        "id": "fact_refuted_02",
        "claim": "All employees received a bonus",
        "context": "HR Memo: Due to budget constraints, bonuses were only given to senior management this year.",
        "expected_verdict": "REFUTED",
        "why_test": "Partial truth should be refuted",
        "provider": "claude_opus"
    },
    
    # Category C: Not enough info
    {
        "id": "fact_neutral_01",
        "claim": "The CEO resigned in 2023",
        "context": "Company News 2024: We announced a new product line and expanded to 3 new markets.",
        "expected_verdict": "NOT_ENOUGH_INFO",
        "why_test": "Context doesn't mention CEO",
        "provider": "anthropic"
    },
    
    # Category D: Subtle misinformation (LLMs often fail)
    {
        "id": "fact_subtle_01",
        "claim": "Sales increased every month in Q1",
        "context": "Q1 Sales: January $10M, February $12M, March $11M. Overall Q1 sales were strong.",
        "expected_verdict": "REFUTED",
        "why_test": "March decreased from February - LLMs miss this",
        "provider": "claude_opus"
    },
    
    {
        "id": "fact_subtle_02",
        "claim": "The majority of customers are satisfied",
        "context": "Customer Survey Results: 45% satisfied, 30% neutral, 25% dissatisfied.",
        "expected_verdict": "REFUTED",
        "why_test": "45% is not majority - LLMs confuse plurality with majority",
        "provider": "anthropic"
    },
    
    {
        "id": "fact_subtle_03",
        "claim": "Revenue doubled in 2024",
        "context": "2023 Revenue: $50M. 2024 Revenue: $95M. This represents a 90% increase year-over-year.",
        "expected_verdict": "REFUTED",
        "why_test": "90% ≠ 100% (doubled) - LLMs round up",
        "provider": "claude_opus"
    },
    
    # Category E: Numerical precision
    {
        "id": "fact_precision_01",
        "claim": "The interest rate is 5%",
        "context": "Loan Agreement: The annual percentage rate (APR) is 4.95%.",
        "expected_verdict": "REFUTED",
        "why_test": "4.95% ≠ 5% exactly",
        "provider": "anthropic"
    },
    
    {
        "id": "fact_precision_02",
        "claim": "Approximately 1000 people attended",
        "context": "Event Report: Total attendance was 987 people.",
        "expected_verdict": "SUPPORTED",
        "why_test": "'Approximately' should allow 987 ≈ 1000",
        "provider": "claude_opus"
    },
    
    # Category F: Temporal logic
    {
        "id": "fact_temporal_01",
        "claim": "The project was completed before the deadline",
        "context": "Project Timeline: Deadline was December 31, 2024. Project completed on January 5, 2025.",
        "expected_verdict": "REFUTED",
        "why_test": "Jan 5 is after Dec 31",
        "provider": "anthropic"
    },
    
    # Category G: Logical inference (should NOT infer)
    {
        "id": "fact_inference_01",
        "claim": "The company is profitable",
        "context": "Financial Statement: Revenue $100M, Expenses $80M.",
        "expected_verdict": "NOT_ENOUGH_INFO",
        "why_test": "Should not infer profit from revenue-expenses (could have debt, etc.)",
        "provider": "claude_opus"
    },
]


class FactEngineTester:
    """Test Fact Engine with adversarial claims."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"x-api-key": api_key, "Content-Type": "application/json"}
        self.results = []
    
    def run_test(self, test: Dict) -> Dict:
        """Run a single fact verification test."""
        print(f"\n{'='*80}")
        print(f"Test: {test['id']}")
        print(f"Claim: {test['claim']}")
        print(f"Expected: {test['expected_verdict']}")
        print(f"Provider: {test['provider']}")
        print(f"{'='*80}")
        
        payload = {
            "claim": test['claim'],
            "context": test['context'],
            "provider": test['provider']
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/verify/fact",
                headers=self.headers,
                json=payload,
                timeout=60
            )
            
            data = response.json()
            verdict = data.get("verdict", "UNKNOWN")
            
            # Check if verdict matches expected
            test_passed = (verdict == test['expected_verdict'])
            
            result = {
                "test_id": test['id'],
                "claim": test['claim'],
                "expected_verdict": test['expected_verdict'],
                "actual_verdict": verdict,
                "test_passed": test_passed,
                "reasoning": data.get("reasoning", ""),
                "why_test": test['why_test'],
                "provider": test['provider'],
                "timestamp": datetime.now().isoformat()
            }
            
            if test_passed:
                print(f"\n✅ TEST PASSED - Verdict: {verdict}")
            else:
                print(f"\n❌ TEST FAILED")
                print(f"   Expected: {test['expected_verdict']}, Got: {verdict}")
            
            return result
            
        except Exception as e:
            return {
                "test_id": test['id'],
                "error": str(e),
                "test_passed": False,
                "timestamp": datetime.now().isoformat()
            }
    
    def run_all_tests(self) -> List[Dict]:
        """Run all fact engine tests."""
        print(f"\n{'#'*80}")
        print(f"# FACT ENGINE ADVERSARIAL TESTING")
        print(f"# Testing Citation-Based Fact Verification")
        print(f"# Total Tests: {len(FACT_ENGINE_TESTS)}")
        print(f"{'#'*80}\n")
        
        for test in FACT_ENGINE_TESTS:
            result = self.run_test(test)
            self.results.append(result)
        
        return self.results
    
    def save_report(self, filename: str = "fact_engine_report.json"):
        """Save report."""
        passed = [r for r in self.results if r.get('test_passed', False)]
        failed = [r for r in self.results if not r.get('test_passed', False)]
        
        report = {
            "test_type": "FACT_ENGINE_VERIFICATION",
            "summary": {
                "total_tests": len(self.results),
                "tests_passed": len(passed),
                "tests_failed": len(failed),
                "accuracy": f"{(len(passed)/len(self.results)*100):.1f}%"
            },
            "failed_tests": failed,
            "all_results": self.results,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*80}")
        print(f"REPORT: {filename}")
        print(f"Total: {report['summary']['total_tests']}")
        print(f"Passed: {report['summary']['tests_passed']}")
        print(f"Failed: {report['summary']['tests_failed']}")
        print(f"Accuracy: {report['summary']['accuracy']}")
        print(f"{'='*80}\n")
        
        if len(failed) > 0:
            print(f"\n❌ FAILED TESTS:")
            for fail in failed:
                print(f"\n  {fail['test_id']}")
                print(f"     Expected: {fail.get('expected_verdict')}, Got: {fail.get('actual_verdict')}")
        
        return report


if __name__ == "__main__":
    print("Starting Fact Engine Verification Testing...\n")
    
    tester = FactEngineTester(BASE_URL, API_KEY)
    results = tester.run_all_tests()
    report = tester.save_report()
    
    print("\n✅ Done! Check fact_engine_report.json")
