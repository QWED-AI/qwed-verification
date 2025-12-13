"""
EXTREME Adversarial Tests - Designed to Definitively Catch Claude Sonnet 4.5 & Opus 4.5
These are HARD tests that exploit known LLM weaknesses.

Difficulty: EXTREME (vs previous MEDIUM-HARD)
Run: python benchmarks/deep_suite/extreme_adversarial_tests.py
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

EXTREME_TESTS = [
    # ========== CATEGORY A: NESTED QUANTIFIERS (Logic) ==========
    {
        "id": "nested_quantifier_01",
        "type": "logic",
        "query": "Prove or disprove: For all x there exists y such that (x < y) implies there exists y such that for all x (x < y). Use formal logic notation and show your proof steps.",
        "expected": "FALSE - counterexample exists",
        "why_extreme": "Nested quantifier order matters, LLMs confuse forall-exists vs exists-forall",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    {
        "id": "nested_quantifier_02",
        "type": "logic",
        "query": "Is this valid: For all x (P(x) implies Q(x)) therefore (for all x P(x)) implies (for all x Q(x))? Prove or provide counterexample.",
        "expected": "VALID",
        "why_extreme": "Requires understanding of universal quantifier distribution",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY B: MONTY HALL VARIANTS (Math/Probability) ==========
    {
        "id": "monty_hall_variant_01",
        "type": "math",
        "query": "There are 4 doors. 1 has a car, 3 have goats. You pick door 1. Host (who knows) opens door 3 showing a goat. You can switch to door 2 or 4. What's your probability of winning if you switch to door 2 specifically?",
        "expected": 0.333,
        "why_extreme": "Multi-door Monty Hall variant, LLMs struggle with conditional probability",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    {
        "id": "two_envelopes_paradox",
        "type": "math",
        "query": "Two envelopes contain money, one has 2x the other. You pick one, open it, and find $100. Should you switch? Calculate expected value of switching. Explain the paradox.",
        "expected": "No advantage - paradox explained",
        "why_extreme": "Classic probability paradox, most LLMs get this wrong",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY C: MULTI-STEP PROOFS (Logic) ==========
    {
        "id": "proof_by_induction_trap",
        "type": "logic",
        "query": "Prove by induction: All horses are the same color. Base case: n=1, one horse is one color. Inductive step: assume true for n horses, prove for n+1. Take n+1 horses, remove one (n horses same color by hypothesis), remove different one (n horses same color), therefore all n+1 same color. What's wrong with this proof?",
        "expected": "Induction fails at n=2 (gap in logic)",
        "why_extreme": "Requires finding subtle flaw in apparently valid proof",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    {
        "id": "russells_paradox",
        "type": "logic",
        "query": "Define R = set of all sets that don't contain themselves. Does R contain R? Prove this leads to contradiction and explain Russell's Paradox.",
        "expected": "Contradiction - R in R if and only if R not in R",
        "why_extreme": "Self-referential paradox, requires careful logical analysis",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY D: COMPLEX ARITHMETIC (Math) ==========
    {
        "id": "division_ambiguity_extreme",
        "type": "math",
        "query": "Calculate: 8 / 2(2+2). Show your work. Is the answer 16 or 1? Which convention are you using?",
        "expected": "Ambiguous - depends on convention",
        "why_extreme": "Classic viral math problem, LLMs pick a side without acknowledging ambiguity",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    {
        "id": "percentage_chain_extreme",
        "type": "math",
        "query": "A stock increases by 50%, then decreases by 50%, then increases by 50%, then decreases by 50%. What's the final value if it started at $100? Show step-by-step.",
        "expected": 56.25,
        "why_extreme": "Chain of percentage changes, LLMs make arithmetic errors",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "compound_interest_trap",
        "type": "math",
        "query": "You invest $1000 at 100% annual interest compounded continuously. After 1 year, how much do you have? (Hint: use e^r formula)",
        "expected": 2718.28,
        "why_extreme": "Continuous compounding vs simple compounding confusion",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY E: GRAPH THEORY (Logic) ==========
    {
        "id": "graph_isomorphism",
        "type": "logic",
        "query": "Are these graphs isomorphic? Graph 1: edges (1-2, 2-3, 3-4, 4-1, 1-3). Graph 2: edges (A-B, B-C, C-D, D-E, E-A, B-D). Prove your answer.",
        "expected": "Non-isomorphic - different structure",
        "why_extreme": "Graph isomorphism is difficult, requires systematic checking",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "hamiltonian_path",
        "type": "logic",
        "query": "Does this graph have a Hamiltonian path? 6 nodes: edges (1-2, 2-3, 3-4, 4-5, 5-6, 6-1, 1-4, 2-5, 3-6). If yes, provide the path. If no, prove why not.",
        "expected": "Has Hamiltonian cycle",
        "why_extreme": "NP-complete problem, LLMs use faulty heuristics",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY F: RECURSIVE REASONING (Logic) ==========
    {
        "id": "halting_problem_variant",
        "type": "logic",
        "query": "Can you write a program H that takes any program P and input I, and determines if P halts on I? Explain why or why not using proof by contradiction.",
        "expected": "NO - Halting Problem is undecidable",
        "why_extreme": "Requires understanding of computability theory",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "self_reference_liar",
        "type": "logic",
        "query": "This sentence is false. Is that sentence true or false? Explain the logical paradox and how formal logic handles it.",
        "expected": "Paradox - neither true nor false in classical logic",
        "why_extreme": "Liar paradox, tests understanding of self-reference",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY G: BAYESIAN REASONING (Math) ==========
    {
        "id": "base_rate_fallacy",
        "type": "math",
        "query": "A test for a disease is 99% accurate (both sensitivity and specificity). Disease affects 0.1% of population. You test positive. What's the probability you have the disease? Show Bayes' theorem calculation.",
        "expected": 0.09,
        "why_extreme": "Base rate neglect - most people (and LLMs) say 99%",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "bertrand_box_paradox",
        "type": "math",
        "query": "3 boxes: GG (2 gold coins), SS (2 silver), GS (1 gold, 1 silver). Pick random box, draw random coin - it's gold. What's probability the other coin is gold? Explain reasoning.",
        "expected": 0.667,
        "why_extreme": "Conditional probability trap, most get 1/2",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY H: COMBINATORICS (Math) ==========
    {
        "id": "derangement_problem",
        "type": "math",
        "query": "5 people check hats, get random hat back. What's probability NO ONE gets their own hat? Use inclusion-exclusion or derangement formula.",
        "expected": 0.3667,
        "why_extreme": "Derangement formula, LLMs struggle with combinatorics",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "pigeonhole_extreme",
        "type": "math",
        "query": "Prove: In any group of 13 people, at least 2 were born in the same month. Now prove: In any group of 367 people, at least 2 have the same birthday (including leap years). Use pigeonhole principle.",
        "expected": "Both provable via pigeonhole",
        "why_extreme": "Requires formal proof construction",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY I: NUMBER THEORY (Math) ==========
    {
        "id": "fermats_last_theorem_special",
        "type": "math",
        "query": "Find positive integers x, y, z such that x^3 + y^3 = z^3. Show your work.",
        "expected": "IMPOSSIBLE - Fermat's Last Theorem",
        "why_extreme": "Tests if LLM knows this is impossible (proven by Wiles)",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "prime_gap_trap",
        "type": "math",
        "query": "Are there infinitely many twin primes (primes that differ by 2, like 11 and 13)? Prove or disprove.",
        "expected": "UNKNOWN - unsolved problem",
        "why_extreme": "This is an OPEN PROBLEM - LLMs may confidently claim to prove it",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY J: GAME THEORY (Logic) ==========
    {
        "id": "prisoners_dilemma_iterated",
        "type": "logic",
        "query": "In iterated prisoner's dilemma (100 rounds), what's the optimal strategy against a Tit-for-Tat player? Prove your answer with game theory.",
        "expected": "Cooperate always (Tit-for-Tat mirrors)",
        "why_extreme": "Requires understanding of Nash equilibrium in repeated games",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "nim_game_variant",
        "type": "logic",
        "query": "Nim game: 3 piles with (5, 7, 9) objects. Players alternate removing any number from ONE pile. Last to move wins. Who wins with optimal play: first or second player? Prove using Nim-sum.",
        "expected": "First player wins (Nim-sum != 0)",
        "why_extreme": "Requires Nim strategy knowledge (XOR trick)",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY K: LOGIC BOMBS (Gotchas) ==========
    {
        "id": "zero_to_zero_power",
        "type": "math",
        "query": "What is 0^0? Is it 0, 1, undefined, or indeterminate? Justify your answer with mathematical reasoning from different contexts (set theory, calculus limits, combinatorics).",
        "expected": "Context-dependent (usually 1 in combinatorics, indeterminate in analysis)",
        "why_extreme": "LLMs often give confident wrong answer",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "infinity_arithmetic",
        "type": "math",
        "query": "Calculate: infinity - infinity. Is it 0, infinity, -infinity, or undefined? Explain using limit analysis.",
        "expected": "INDETERMINATE FORM - depends on context",
        "why_extreme": "LLMs treat infinity like a number",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
    
    # ========== CATEGORY L: ADVANCED WORD PROBLEMS (Math) ==========
    {
        "id": "lily_pad_exponential",
        "type": "math",
        "query": "A lily pad patch doubles in size every day. It takes 48 days to cover the entire pond. On which day was the pond half covered?",
        "expected": 47,
        "why_extreme": "Exponential growth intuition trap",
        "provider": "claude_opus",
        "difficulty": "EXTREME"
    },
    {
        "id": "rope_around_earth",
        "type": "math",
        "query": "Earth's circumference is ~40,000 km. A rope fits snugly around the equator. We add 1 meter to the rope's length. If we lift the rope evenly, how high above ground does it float? (Assume Earth is a perfect sphere)",
        "expected": 0.159,
        "why_extreme": "Counter-intuitive geometry, most guess millimeters",
        "provider": "anthropic",
        "difficulty": "EXTREME"
    },
]


class ExtremeAdversarialTester:
    """Run EXTREME difficulty tests to definitively catch LLM errors."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"x-api-key": api_key, "Content-Type": "application/json"}
        self.results = []
    
    def run_test(self, test: Dict) -> Dict:
        """Run a single extreme test."""
        print(f"\n{'='*80}")
        print(f"EXTREME TEST: {test['id']}")
        print(f"Type: {test['type'].upper()}")
        print(f"Difficulty: {test['difficulty']}")
        print(f"Query: {test['query'][:150]}...")
        print(f"Why Extreme: {test['why_extreme']}")
        print(f"{'='*80}")
        
        # Choose endpoint based on type
        endpoint = "/verify/logic" if test['type'] == 'logic' else "/verify/natural_language"
        
        payload = {
            "query": test['query'],
            "provider": test['provider']
        }
        
        try:
            response = requests.post(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                json=payload,
                timeout=120
            )
            
            data = response.json()
            
            # Analyze result
            status = data.get("status")
            llm_answer = data.get("final_answer")
            
            # Check if QWED caught an error
            caught_error = False
            error_type = None
            
            if test['type'] == 'logic':
                # Logic test evaluation
                caught_error = (status == "UNSAT" or status == "ERROR" or 
                              "contradiction" in str(data).lower() or
                              "invalid" in str(data).lower())
                if caught_error:
                    error_type = f"LOGIC_{status}"
            else:
                # Math test evaluation
                expected = test.get('expected')
                if expected == "Ambiguous - depends on convention":
                    # For ambiguous tests, check if LLM acknowledged ambiguity
                    caught_error = "ambiguous" not in str(data).lower()
                    error_type = "FAILED_TO_ACKNOWLEDGE_AMBIGUITY" if caught_error else None
                elif isinstance(expected, (int, float)):
                    # Numeric comparison
                    try:
                        if llm_answer and abs(float(llm_answer) - expected) > 0.01:
                            caught_error = True
                            error_type = f"WRONG_ANSWER_{llm_answer}_vs_{expected}"
                    except:
                        pass
            
            result = {
                "test_id": test['id'],
                "type": test['type'],
                "difficulty": test['difficulty'],
                "query": test['query'],
                "provider": test['provider'],
                "expected": test.get('expected'),
                "llm_answer": llm_answer,
                "qwed_status": status,
                "caught_error": caught_error,
                "error_type": error_type,
                "why_extreme": test['why_extreme'],
                "full_response": data,
                "timestamp": datetime.now().isoformat()
            }
            
            # Print result
            if caught_error:
                print(f"\nCATCHED! QWED CAUGHT ERROR!")
                print(f"   Error Type: {error_type}")
                print(f"   Expected: {test.get('expected')}")
                print(f"   LLM Said: {llm_answer}")
            else:
                print(f"\n   Status: {status}")
                print(f"   LLM Answer: {llm_answer}")
            
            return result
            
        except Exception as e:
            print(f"\n   ERROR: {str(e)}")
            return {
                "test_id": test['id'],
                "error": str(e),
                "difficulty": "EXTREME",
                "timestamp": datetime.now().isoformat()
            }
    
    def run_all_tests(self) -> List[Dict]:
        """Run all extreme tests."""
        print(f"\n{'#'*80}")
        print(f"# EXTREME ADVERSARIAL TESTING SUITE")
        print(f"# Difficulty: EXTREME (vs previous MEDIUM-HARD)")
        print(f"# Testing Claude Sonnet 4.5 & Opus 4.5 with BRUTAL tests")
        print(f"# Total Tests: {len(EXTREME_TESTS)}")
        print(f"{'#'*80}\n")
        
        for test in EXTREME_TESTS:
            result = self.run_test(test)
            self.results.append(result)
        
        return self.results
    
    def save_report(self, filename: str = "extreme_adversarial_report.json"):
        """Save extreme test report."""
        report = {
            "difficulty": "EXTREME",
            "summary": {
                "total_tests": len(self.results),
                "errors_caught": sum(1 for r in self.results if r.get('caught_error', False)),
                "catch_rate": f"{sum(1 for r in self.results if r.get('caught_error', False))/len(self.results)*100:.1f}%" if self.results else "0%"
            },
            "caught_errors": [r for r in self.results if r.get('caught_error', False)],
            "all_results": self.results,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*80}")
        print(f"EXTREME TEST REPORT SAVED: {filename}")
        print(f"{'='*80}")
        print(f"\nSUMMARY:")
        print(f"  Difficulty Level: EXTREME")
        print(f"  Total Tests: {report['summary']['total_tests']}")
        print(f"  Errors Caught: {report['summary']['errors_caught']}")
        print(f"  Catch Rate: {report['summary']['catch_rate']}")
        print(f"\n{'='*80}\n")
        
        return report


if __name__ == "__main__":
    print("Starting EXTREME adversarial testing...")
    print("These are BRUTAL tests designed to catch even top-tier LLMs\n")
    
    tester = ExtremeAdversarialTester(BASE_URL, API_KEY)
    results = tester.run_all_tests()
    report = tester.save_report()
    
    print("\nDone! Check extreme_adversarial_report.json for full details.")