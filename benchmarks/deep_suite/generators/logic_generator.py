"""
Logic Problem Generator for Deep Benchmark Suite.
Generates logic problems across 4 difficulty levels: Easy, Medium, Hard, Collapse.
Tests the Z3 solver's ability to handle formal logic.
"""

from typing import List, Dict, Any
from benchmarks.deep_suite.runner_base import Difficulty

class LogicGenerator:
    def generate_suite(self, count_per_level: int = 5) -> List[Dict[str, Any]]:
        suite = []
        suite.extend(self._generate_easy(count_per_level))
        suite.extend(self._generate_medium(count_per_level))
        suite.extend(self._generate_hard(count_per_level))
        suite.extend(self._generate_collapse(count_per_level))
        return suite

    def _generate_easy(self, count: int) -> List[Dict[str, Any]]:
        """Basic Syllogisms (Aristotelian Logic)."""
        problems = [
            {
                "query": "All humans are mortal. Socrates is human. Is Socrates mortal?",
                "expected": "SAT",  # Satisfiable - the conclusion follows
                "trap": "Basic syllogism"
            },
            {
                "query": "All A are B. Some B are C. Are all A necessarily C?",
                "expected": "UNSAT",  # Unsatisfiable - the conclusion doesn't follow
                "trap": "Invalid syllogism"
            },
            {
                "query": "If it rains, the ground is wet. The ground is wet. Did it rain?",
                "expected": "SAT",  # Could be true, but not necessarily (affirming consequent fallacy)
                "trap": "Affirming the consequent"
            }
        ]
        
        result = []
        for i in range(count):
            problem = problems[i % len(problems)]
            result.append({
                "id": f"logic_easy_{i}",
                "difficulty": Difficulty.EASY,
                "query": problem["query"],
                "expected_answer": problem["expected"],
                "trap": problem["trap"]
            })
        return result

    def _generate_medium(self, count: int) -> List[Dict[str, Any]]:
        """Propositional Logic & Truth Tables."""
        problems = [
            {
                "query": "If P implies Q, and Q implies R, does P imply R?",
                "expected": "SAT",  # Transitive property
                "trap": "Transitivity test"
            },
            {
                "query": "Either A or B is true. A is false. Is B true?",
                "expected": "SAT",  # Disjunctive syllogism
                "trap": "Disjunction"
            },
            {
                "query": "Not (A and B) is equivalent to (Not A) or (Not B)?",
                "expected": "SAT",  # De Morgan's Law
                "trap": "De Morgan"
            }
        ]
        
        result = []
        for i in range(count):
            problem = problems[i % len(problems)]
            result.append({
                "id": f"logic_med_{i}",
                "difficulty": Difficulty.MEDIUM,
                "query": problem["query"],
                "expected_answer": problem["expected"],
                "trap": problem["trap"]
            })
        return result

    def _generate_hard(self, count: int) -> List[Dict[str, Any]]:
        """Constraint Satisfaction Problems (Knights & Knaves, Einstein Puzzle)."""
        problems = [
            {
                "query": "On an island, knights always tell the truth and knaves always lie. Person A says 'I am a knave.' What is Person A?",
                "expected": "UNSAT",  # Paradox - A can't be either
                "trap": "Self-reference paradox"
            },
            {
                "query": "Three people: Alice, Bob, Carol. Alice says Bob is lying. Bob says Carol is lying. Carol says Alice is telling the truth. Can this be consistent?",
                "expected": "SAT",  # Yes, if Alice=Truth, Bob=Lie, Carol=Truth
                "trap": "Circular reference"
            },
            {
                "query": "In a 3x3 grid, place numbers 1-3 such that each row and column has unique numbers. Is this possible?",
                "expected": "SAT",  # Latin square
                "trap": "Constraint satisfaction"
            }
        ]
        
        result = []
        for i in range(count):
            problem = problems[i % len(problems)]
            result.append({
                "id": f"logic_hard_{i}",
                "difficulty": Difficulty.HARD,
                "query": problem["query"],
                "expected_answer": problem["expected"],
                "trap": problem["trap"]
            })
        return result

    def _generate_collapse(self, count: int) -> List[Dict[str, Any]]:
        """Paradoxes & Undecidable Statements."""
        collapse_cases = [
            {
                "query": "This statement is false.",
                "expected": "UNSAT",  # Liar's paradox - logically inconsistent
                "trap": "Liar's paradox"
            },
            {
                "query": "Does the set of all sets that do not contain themselves, contain itself?",
                "expected": "UNSAT",  # Russell's paradox
                "trap": "Russell's paradox"
            },
            {
                "query": "The next statement is true. The previous statement is false.",
                "expected": "UNSAT",  # Circular paradox
                "trap": "Circular contradiction"
            },
            {
                "query": "Can an omnipotent being create a rock so heavy it cannot lift it?",
                "expected": "UNSAT",  # Omnipotence paradox
                "trap": "Omnipotence paradox"
            }
        ]
        
        problems = []
        for i in range(count):
            case = collapse_cases[i % len(collapse_cases)]
            problems.append({
                "id": f"logic_collapse_{i}",
                "difficulty": Difficulty.COLLAPSE,
                "query": case["query"],
                "expected_answer": case["expected"],
                "trap": case["trap"]
            })
        return problems
