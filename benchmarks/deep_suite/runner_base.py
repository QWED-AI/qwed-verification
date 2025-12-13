"""
Base Runner for Deep Benchmark Suite.
Standardizes metrics, logging, and result formatting.
"""

import time
import json
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class Difficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    COLLAPSE = "collapse"

class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNVERIFIABLE = "UNVERIFIABLE"
    ERROR = "ERROR"

@dataclass
class BenchmarkResult:
    id: str
    engine: str
    difficulty: Difficulty
    query: str
    expected: Any
    raw_llm_answer: str
    qwed_answer: str
    qwed_verdict: Verdict
    confidence: float
    latency_ms: float
    timestamp: float
    metadata: Dict[str, Any]

class BaseRunner:
    def __init__(self, engine_name: str):
        self.engine_name = engine_name
        self.results: List[BenchmarkResult] = []

    async def run_test(self, test_case: Dict[str, Any]) -> BenchmarkResult:
        """
        Execute a single test case.
        Must be implemented by subclasses.
        """
        raise NotImplementedError

    def save_results(self, output_dir: str = "benchmarks/deep_suite/results"):
        """Save results to JSON."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        filename = f"{self.engine_name}_{int(time.time())}.json"
        path = os.path.join(output_dir, filename)
        
        data = [asdict(r) for r in self.results]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            
        print(f"✅ Saved {len(self.results)} results to {path}")
