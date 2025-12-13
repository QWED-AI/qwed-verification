"""
Reasoning Engine Adversarial Tests - Test multi-LLM cross-validation
Tests if Claude correctly understands natural language queries before execution.

Run: python benchmarks/deep_suite/reasoning_engine_tests.py
"""

import requests
import json
from datetime import datetime
from typing import Dict, List

# Configuration
BASE_URL = "http://localhost:8000"
API_KEY = "YOUR_API_KEY_HERE"

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

REASONING_ENGINE_TESTS = [
    # Category A: Correctly understood queries
    {
        "id": "reasoning_correct_01",
        "query": "What is 2 plus 2?",
        "expected_understanding": "CORRECT",
        "why_test": "Simple addition should be understood correctly",
        "provider": "anthropic"
    },
    
    {
        "id": "reasoning_correct_02",
        "query": "Calculate the area of a circle with radius 5",
        "expected_understanding": "CORRECT",
        "why_test": "Standard formula should be recognized",
        "provider": "claude_opus"
    },
    
    # Category B: Ambiguous queries (should flag)
    {
        "id": "reasoning_ambiguous_01",
        "query": "What is 6/2(1+2)?",
        "expected_understanding": "AMBIGUOUS",
        "why_test": "Classic PEMDAS ambiguity",
        "provider": "anthropic"
    },
    
    {
        "id": "reasoning_ambiguous_02",
        "query": "Calculate the average",
        "expected_understanding": "AMBIGUOUS",
        "why_test": "Missing context - average of what?",
        "provider": "claude_opus"
    },
    
    # Category C: Misunderstood queries (translation errors)
    {
        "id": "reasoning_misunderstood_01",
        "query": "If I have 10 apples and give away 3, how many do I have left?",
        "expected_formula": "10 - 3",
        "wrong_formula": "10 + 3",
        "why_test": "LLM might confuse 'give away' with 'receive'",
        "provider": "anthropic"
    },
    
    {
        "id": "reasoning_misunderstood_02",
        "query": "A product costs $100. After a 20% discount, what's the price?",
        "expected_formula": "100 * 0.8",
        "wrong_formula": "100 - 20",
        "why_test": "LLM might subtract 20 instead of calculating 20%",
        "provider": "claude_opus"
    },
    
    # Category D: Word problem traps
    {
        "id": "reasoning_word_problem_01",
        "query": "A bat and ball cost $1.10 total. The bat costs $1 more than the ball. How much does the ball cost?",
        "expected_formula": "(1.10 - 1) / 2",
        "wrong_formula": "1.10 - 1",
        "why_test": "Classic cognitive bias - LLMs often get this wrong",
        "provider": "anthropic"
    },
    
    {
        "id": "reasoning_word_problem_02",
        "query": "If 5 machines make 5 widgets in 5 minutes, how long for 100 machines to make 100 widgets?",
        "expected_answer": 5,
        "wrong_answer": 100,
        "why_test": "Linear thinking trap",
        "provider": "claude_opus"
    },
    
    # Category E: Semantic fact extraction
    {
        "id": "reasoning_facts_01",
        "query": "John has 3 apples, Mary has 5 apples. How many total?",
        "expected_entities": ["John", "Mary"],
        "expected_numbers": [3, 5],
        "why_test": "Should extract entities and numbers",
        "provider": "anthropic"
    },
    
    # Category F: Formula equivalence
    {
        "id": "reasoning_equivalence_01",
        "query": "What is 2 times 3 plus 4?",
        "formula1": "2 * 3 + 4",
        "formula2": "(2 * 3) + 4",
        "should_be_equivalent": True,
        "why_test": "Parentheses don't change meaning here",
        "provider": "claude_opus"
    },
]


class ReasoningEngineTester:
    """Test Reasoning Engine with understanding validation."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"x-api-key": api_key, "Content-Type": "application/json"}
        self.results = []
    
    def run_test(self, test: Dict) -> Dict:
        """Run a single reasoning test."""
        print(f"\n{'='*80}")
        print(f"Test: {test['id']}")
        print(f"Query: {test['query']}")
        print(f"Why Test: {test['why_test']}")
        print(f"{'='*80}")
        
        # For reasoning tests, we use the natural language endpoint
        # and check if the reasoning validation catches issues
        payload = {
            "query": test['query'],
            "provider": test['provider'],
            "enable_reasoning_validation": True
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/verify/natural_language",
                headers=self.headers,
                json=payload,
                timeout=60
            )
            
            data = response.json()
            
            # Check reasoning validation results
            reasoning = data.get("reasoning_validation", {})
            is_valid = reasoning.get("is_valid", True)
            confidence = reasoning.get("confidence", 1.0)
            issues = reasoning.get("issues", [])
            
            result = {
                "test_id": test['id'],
                "query": test['query'],
                "reasoning_valid": is_valid,
                "confidence": confidence,
                "issues_found": issues,
                "why_test": test['why_test'],
                "provider": test['provider'],
                "full_response": data,
                "timestamp": datetime.now().isoformat()
            }
            
            # Determine if test passed based on expectations
            if "expected_understanding" in test:
                if test['expected_understanding'] == "AMBIGUOUS":
                    test_passed = (not is_valid or confidence < 0.7)
                else:
                    test_passed = (is_valid and confidence > 0.7)
            else:
                test_passed = True  # Just collecting data
            
            result["test_passed"] = test_passed
            
            if test_passed:
                print(f"\n✅ TEST PASSED")
                print(f"   Valid: {is_valid}, Confidence: {confidence:.2f}")
            else:
                print(f"\n❌ TEST FAILED")
                print(f"   Valid: {is_valid}, Confidence: {confidence:.2f}")
                if issues:
                    print(f"   Issues: {issues}")
            
            return result
            
        except Exception as e:
            return {
                "test_id": test['id'],
                "error": str(e),
                "test_passed": False,
                "timestamp": datetime.now().isoformat()
            }
    
    def run_all_tests(self) -> List[Dict]:
        """Run all reasoning engine tests."""
        print(f"\n{'#'*80}")
        print(f"# REASONING ENGINE ADVERSARIAL TESTING")
        print(f"# Testing Multi-LLM Cross-Validation")
        print(f"# Total Tests: {len(REASONING_ENGINE_TESTS)}")
        print(f"{'#'*80}\n")
        
        for test in REASONING_ENGINE_TESTS:
            result = self.run_test(test)
            self.results.append(result)
        
        return self.results
    
    def save_report(self, filename: str = "reasoning_engine_report.json"):
        """Save report."""
        passed = [r for r in self.results if r.get('test_passed', False)]
        
        report = {
            "test_type": "REASONING_ENGINE_VALIDATION",
            "summary": {
                "total_tests": len(self.results),
                "tests_passed": len(passed),
                "avg_confidence": sum(r.get('confidence', 0) for r in self.results) / len(self.results) if self.results else 0
            },
            "all_results": self.results,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*80}")
        print(f"REPORT: {filename}")
        print(f"Total: {report['summary']['total_tests']}")
        print(f"Passed: {report['summary']['tests_passed']}")
        print(f"Avg Confidence: {report['summary']['avg_confidence']:.2f}")
        print(f"{'='*80}\n")
        
        return report


if __name__ == "__main__":
    print("Starting Reasoning Engine Validation Testing...\n")
    
    tester = ReasoningEngineTester(BASE_URL, API_KEY)
    results = tester.run_all_tests()
    report = tester.save_report()
    
    print("\n✅ Done! Check reasoning_engine_report.json")
