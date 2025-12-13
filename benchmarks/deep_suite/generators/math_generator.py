"""
Math Problem Generator for Deep Benchmark Suite.
Generates problems across 4 difficulty levels: Easy, Medium, Hard, Collapse.
"""

import random
from typing import List, Dict, Any
from benchmarks.deep_suite.runner_base import Difficulty

class MathGenerator:
    def generate_suite(self, count_per_level: int = 5) -> List[Dict[str, Any]]:
        suite = []
        suite.extend(self._generate_easy(count_per_level))
        suite.extend(self._generate_medium(count_per_level))
        suite.extend(self._generate_hard(count_per_level))
        suite.extend(self._generate_collapse(count_per_level))
        return suite

    def _generate_easy(self, count: int) -> List[Dict[str, Any]]:
        """Basic Arithmetic & Order of Operations."""
        problems = []
        for i in range(count):
            a, b, c = random.randint(1, 10), random.randint(1, 10), random.randint(1, 10)
            op1, op2 = random.choice(['+', '-', '*']), random.choice(['+', '-', '*'])
            
            query = f"What is {a} {op1} {b} {op2} {c}?"
            # Python's eval handles order of operations correctly
            expected = eval(f"{a} {op1} {b} {op2} {c}")
            
            problems.append({
                "id": f"math_easy_{i}",
                "difficulty": Difficulty.EASY,
                "query": query,
                "expected": float(expected),
                "trap": "None"
            })
        return problems

    def _generate_medium(self, count: int) -> List[Dict[str, Any]]:
        """Algebra & Percentages."""
        problems = []
        for i in range(count):
            # Percentages
            total = random.randint(100, 1000)
            pct = random.randint(1, 99)
            query = f"What is {pct}% of {total}?"
            expected = (pct / 100) * total
            
            problems.append({
                "id": f"math_med_{i}",
                "difficulty": Difficulty.MEDIUM,
                "query": query,
                "expected": float(expected),
                "trap": "Percentage calculation"
            })
        return problems

    def _generate_hard(self, count: int) -> List[Dict[str, Any]]:
        """Multi-step Word Problems (GSM8K style)."""
        # Using a simplified template approach for now
        problems = []
        templates = [
            ("Sophie has {n1} apples. She eats {n2}. Then buys {n3} times what she has left.", 
             lambda n1, n2, n3: (n1 - n2) + (n3 * (n1 - n2))),
            ("A train travels {n1} miles at {n2} mph. How long does it take?", 
             lambda n1, n2, n3: n1 / n2)
        ]
        
        for i in range(count):
            temp, func = random.choice(templates)
            n1, n2, n3 = random.randint(20, 50), random.randint(1, 10), random.randint(2, 5)
            
            query = temp.format(n1=n1, n2=n2, n3=n3)
            expected = func(n1, n2, n3)
            
            problems.append({
                "id": f"math_hard_{i}",
                "difficulty": Difficulty.HARD,
                "query": query,
                "expected": float(expected),
                "trap": "Multi-step logic"
            })
        return problems

    def _generate_collapse(self, count: int) -> List[Dict[str, Any]]:
        """Ambiguous Notation & Unsolvable Problems."""
        collapse_cases = [
            {
                "query": "What is 6/2(1+2)?",
                "expected": "AMBIGUOUS", # 1 or 9 depending on convention
                "trap": "Ambiguous operator precedence"
            },
            {
                "query": "Calculate 5 divided by 0.",
                "expected": "ERROR", # Division by zero
                "trap": "Division by zero"
            },
            {
                "query": "Prove that 1 equals 2.",
                "expected": "FALSE", # Mathematical impossibility
                "trap": "False premise"
            },
            {
                "query": "What is the square root of -1 in real numbers?",
                "expected": "ERROR", # Complex number in real domain
                "trap": "Domain error"
            }
        ]
        
        problems = []
        for i in range(count):
            case = collapse_cases[i % len(collapse_cases)]
            problems.append({
                "id": f"math_collapse_{i}",
                "difficulty": Difficulty.COLLAPSE,
                "query": case["query"],
                "expected": case["expected"],
                "trap": case["trap"]
            })
        return problems
