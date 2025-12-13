"""
Adversarial Logic Tests - Designed to Catch Claude Sonnet 4.5 & Opus 4.5 Logic Errors
Tests Tower of Hanoi, Knights & Knaves, planning problems, and constraint satisfaction.

Run: python benchmarks/deep_suite/adversarial_logic_tests.py
"""

import requests
import json
from datetime import datetime
from typing import Dict, List

# Configuration
BASE_URL = "http://localhost:8000"  # Use Azure VM API
API_KEY = "YOUR_API_KEY_HERE"

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

# Logic test cases designed to trip LLMs
ADVERSARIAL_LOGIC_TESTS = [
    # Category A: Tower of Hanoi (sequence validation)
    {
        "id": "hanoi_3_disks",
        "query": "Give the exact optimal sequence of moves to solve Tower of Hanoi for 3 disks from peg A to peg C using peg B. Provide only the moves, one per line: 'Move disk X from peg Y to peg Z'.",
        "expected_moves": 7,  # 2^3 - 1 = 7 moves
        "why_hard": "LLMs often add extra moves, make illegal moves, or get the sequence wrong",
        "provider": "anthropic"
    },
    {
        "id": "hanoi_4_disks",
        "query": "Solve Tower of Hanoi for 4 disks. Provide the complete sequence of moves from peg A to peg C.",
        "expected_moves": 15,  # 2^4 - 1 = 15 moves
        "why_hard": "More complex, LLMs struggle with maintaining state across many steps",
        "provider": "claude_opus"
    },
    
    # Category B: Knights and Knaves (truth tables)
    {
        "id": "knights_knaves_01",
        "query": "On an island, knights always tell truth and knaves always lie. A says 'B is lying.' B says 'A is telling the truth.' Who is the knight and who is the knave? Show step-by-step logical deduction.",
        "expected_solution": "A is knight, B is knave",
        "why_hard": "Self-referential logic confuses LLMs - must build truth table",
        "provider": "anthropic"
    },
    {
        "id": "knights_knaves_02",
        "query": "A says 'I am a knave.' Is this possible? Explain the logical contradiction.",
        "expected_solution": "Impossible - leads to paradox",
        "why_hard": "Classic liar paradox, LLMs may not detect the contradiction",
        "provider": "claude_opus"
    },
    {
        "id": "knights_knaves_03",
        "query": "A says 'Either I am a knave or B is a knight.' B says 'A is a knave.' What are A and B?",
        "expected_solution": "A is knight, B is knight",
        "why_hard": "Requires evaluating disjunction in different cases",
        "provider": "anthropic"
    },
    
    # Category C: River crossing puzzles (state validation)
    {
        "id": "wolf_goat_cabbage",
        "query": "A farmer must cross a river with a wolf, goat, and cabbage. The boat holds only the farmer and one item. If left alone: wolf eats goat, goat eats cabbage. Provide the exact sequence of crossings (one action per line). Format: 'Farmer takes X across' or 'Farmer returns alone'.",
        "expected_moves": 7,
        "why_hard": "LLMs make illegal moves or forget constraints",
        "provider": "claude_opus"
    },
    {
        "id": "missionaries_cannibals",
        "query": "3 missionaries and 3 cannibals must cross a river. Boat holds 2 people. Cannibals cannot outnumber missionaries on either side. Give the exact sequence of boat trips.",
        "expected_moves": 11,
        "why_hard": "Complex state space, LLMs violate constraints",
        "provider": "anthropic"
    },
    
    # Category D: Constraint satisfaction
    {
        "id": "constraint_sat_01",
        "query": "Find values for x and y such that: x + y = 10, x > y, x is even, y is odd. List all possible solutions.",
        "expected_solutions": "Multiple valid pairs like (8,2), (6,4)",
        "why_hard": "Multiple constraints, LLMs miss edge cases",
        "provider": "anthropic"
    },
    {
        "id": "constraint_sat_02",
        "query": "Three variables x, y, z must satisfy: x < y < z, x + y + z = 15, all are prime numbers. Find all solutions.",
        "expected_solutions": "Multiple solutions involving primes",
        "why_hard": "Combining ordering, arithmetic, and primality constraints",
        "provider": "claude_opus"
    },
    
    # Category E: Logic puzzles (Einstein's riddle style)
    {
        "id": "logic_puzzle_01",
        "query": "Five houses in five colors. British lives in red house. Spaniard owns dog. Coffee drunk in green house. Ukrainian drinks tea. Green house immediately right of ivory. Who owns zebra? Provide systematic deduction.",
        "why_hard": "Classic Einstein riddle - requires systematic constraint propagation",  
        "provider": "anthropic"
    },
    
    # Category F: Boolean logic (SAT problems)
    {
        "id": "boolean_sat_01",
        "query": "Find an assignment for A, B, C that satisfies: (A OR B) AND (NOT A OR C) AND (NOT B OR NOT C). Show the truth table.",
        "why_hard": "3-SAT problem, LLMs may not systematically evaluate all cases",
        "provider": "claude_opus"
    },
    {
        "id": "boolean_sat_02",
        "query": "Is this formula satisfiable: (A AND B) AND (NOT A OR NOT B)? Prove your answer.",
        "expected_solution": "UNSAT - contradictory clauses",
        "why_hard": "Requires detecting contradiction via resolution",
        "provider": "anthropic"
    },
    
    # Category G: Graph theory constraints
    {
        "id": "graph_coloring",
        "query": "Color a graph with 5 nodes connected as: 1-2, 2-3, 3-4, 4-5, 5-1, 1-3. Use minimum colors where adjacent nodes have different colors. What's the minimum?",
        "expected_solution": "3 colors (it's a cycle with diagonal)",
        "why_hard": "Graph coloring is NP-hard, LLMs use heuristics incorrectly",
        "provider": "claude_opus"
    },
    
    # Category H: Sudoku-style constraints
    {
        "id": "sudoku_mini",
        "query": "Fill a 4x4 grid where each row and column contains 1,2,3,4. Top row starts: 1,_,_,4. Left column: 1,_,4,_. Provide the complete solution.",
        "why_hard": "Constraint propagation required, LLMs make invalid assignments",
        "provider": "anthropic"
    },
    
    # Category I: Temporal logic
    {
        "id": "temporal_01",
        "query": "Events: A happens before B. B happens before C. C happens before D. D happens before A. Is this timeline consistent? Explain.",
        "expected_solution": "INCONSISTENT - circular dependency",
        "why_hard": "Cycle detection in partial order",
        "provider": "claude_opus"
    },
    
    # Category J: Resource allocation
    {
        "id": "resource_allocation",
        "query": "3 tasks (A,B,C) need resources. A needs 2 units, B needs 3, C needs 2. Only 5 units available. B and C cannot run together. Which tasks can run simultaneously?",
        "why_hard": "Resource constraints + mutex constraints",
        "provider": "anthropic"
    },
]


class AdversarialLogicTester:
    """Run adversarial logic tests."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"x-api-key": api_key, "Content-Type": "application/json"}
        self.results = []
    
    def run_test(self, test: Dict) -> Dict:
        """Run a single logic test."""
        print(f"\n{'='*80}")
        print(f"Running: {test['id']}")
        print(f"Query: {test['query'][:100]}...")
        print(f"Provider: {test['provider']}")
        print(f"Why Hard: {test['why_hard']}")
        print(f"{'='*80}")
        
        payload = {
            "query": test['query'],
            "provider": test['provider']
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/verify/logic",
                headers=self.headers,
                json=payload,
                timeout=90
            )
            
            data = response.json()
            
            # Analyze result
            status = data.get("status")
            
            # Check if QWED detected issues
            detected_issue = (status == "UNSAT" or status == "ERROR" or 
                            "contradiction" in str(data).lower() or
                            "invalid" in str(data).lower())
            
            result = {
                "test_id": test['id'],
                "query": test['query'],
                "provider": test['provider'],
                "qwed_status": status,
                "detected_issue": detected_issue,
                "why_hard": test['why_hard'],
                "full_response": data,
                "timestamp": datetime.now().isoformat()
            }
            
            # Print result
            if detected_issue:
                print(f"\nðŸŽ¯ QWED DETECTED ISSUE:")
                print(f"   Status: {status}")
            else:
                print(f"\n   Status: {status}")
            
            return result
            
        except Exception as e:
            return {
                "test_id": test['id'],
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def run_all_tests(self) -> List[Dict]:
        """Run all logic tests."""
        print(f"\n{'#'*80}")
        print(f"# ADVERSARIAL LOGIC TESTING SUITE")
        print(f"# Testing Claude Sonnet 4.5 & Opus 4.5 against QWED Logic Engine")
        print(f"# Total Tests: {len(ADVERSARIAL_LOGIC_TESTS)}")
        print(f"{'#'*80}\n")
        
        for test in ADVERSARIAL_LOGIC_TESTS:
            result = self.run_test(test)
            self.results.append(result)
        
        return self.results
    
    def save_report(self, filename: str = "adversarial_logic_report.json"):
        """Save report."""
        report = {
            "summary": {
                "total_tests": len(self.results),
                "issues_detected": sum(1 for r in self.results if r.get('detected_issue', False))
            },
            "all_results": self.results,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*80}")
        print(f"LOGIC REPORT SAVED: {filename}")
        print(f"Total Tests: {report['summary']['total_tests']}")
        print(f"Issues Detected: {report['summary']['issues_detected']}")
        print(f"{'='*80}\n")
        
        return report


if __name__ == "__main__":
    print("Starting adversarial logic testing...")
    print("Make sure QWED API is running on localhost:8000\n")
    
    tester = AdversarialLogicTester(BASE_URL, API_KEY)
    results = tester.run_all_tests()
    report = tester.save_report()
    
    print("\nDone! Check adversarial_logic_report.json for full details.")

