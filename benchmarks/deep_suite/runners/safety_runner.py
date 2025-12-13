"""
Safety Runner for Deep Benchmark Suite.
Executes safety checks against QWED CodeVerifier.
"""

import time
import asyncio
from typing import Dict, Any
from benchmarks.deep_suite.runner_base import BaseRunner, BenchmarkResult, Verdict
from qwed_new.core.code_verifier import CodeVerifier

class SafetyRunner(BaseRunner):
    def __init__(self):
        super().__init__("SafetyEngine")
        self.verifier = CodeVerifier()

    async def run_test(self, test_case: Dict[str, Any]) -> BenchmarkResult:
        start_time = time.time()
        
        # 1. Raw LLM Call (Simulated)
        # Raw LLMs usually just generate the code requested, even if unsafe, 
        # unless they have RLHF refusals. We'll simulate "Raw" as just returning the code.
        raw_ans = test_case['query'] 

        # 2. QWED Safety Check
        try:
            # We are testing the verifier directly here
            result = self.verifier.verify_code(test_case['query'])
            
            is_safe = result["is_safe"]
            issues = result.get("issues", [])
            
            qwed_ans = "SAFE" if is_safe else f"UNSAFE: {', '.join(issues)}"
            confidence = 1.0 # Deterministic check
            
            # Determine Verdict
            verdict = self._evaluate_verdict(is_safe, test_case['expected'])
            
        except Exception as e:
            qwed_ans = f"Error: {str(e)}"
            confidence = 0.0
            verdict = Verdict.ERROR

        latency = (time.time() - start_time) * 1000
        
        result = BenchmarkResult(
            id=test_case['id'],
            engine="SafetyEngine",
            difficulty=test_case['difficulty'],
            query=test_case['query'][:50] + "..." if len(test_case['query']) > 50 else test_case['query'],
            expected=test_case['expected'],
            raw_llm_answer="Generated Code (Vulnerable)", # Assumption for raw LLM
            qwed_answer=qwed_ans,
            qwed_verdict=verdict,
            confidence=confidence,
            latency_ms=latency,
            timestamp=time.time(),
            metadata={"trap": test_case.get("trap")}
        )
        self.results.append(result)
        return result

    def _evaluate_verdict(self, is_safe: bool, expected: str) -> Verdict:
        if expected == "SAFE":
            return Verdict.PASS if is_safe else Verdict.FAIL # False Positive
        elif expected == "UNSAFE":
            return Verdict.PASS if not is_safe else Verdict.FAIL # False Negative (Dangerous!)
        return Verdict.ERROR
