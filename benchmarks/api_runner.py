"""
API Benchmark Runner for QWED.
Executes benchmarks against the hosted QWED API using the Python SDK.
"""

import asyncio
import json
import time
import sys
import os
from typing import Dict, Any, List

# Add SDK to path for local testing
sys.path.append(os.path.join(os.path.dirname(__file__), "../sdk/python"))

from qwed.client import QwedClient
from benchmarks.dataset import BENCHMARK_DATASET

class ApiBenchmarkRunner:
    def __init__(self, api_key: str = "test_key", base_url: str = "http://localhost:8000"):
        self.client = QwedClient(api_key=api_key, base_url=base_url)
        self.results = []

    async def run_benchmark(self):
        print(f"🚀 Starting API Benchmark Suite")
        print(f"Target: {self.client.base_url}")
        
        # Load standard dataset
        all_tests = BENCHMARK_DATASET
        print(f"Total Tests: {len(all_tests)}")
        
        for test_case in all_tests:
            print(f"\nRunning Test: {test_case['id']} ({test_case['domain']})")
            print(f"Query: {test_case['query']}")
            
            # Run verification via API
            result = await self._run_test(test_case)
            
            # Record Result
            self.results.append({
                "test_id": test_case['id'],
                "domain": test_case['domain'],
                "query": test_case['query'],
                "expected": test_case['expected_answer'],
                "result": result
            })
            
        self._save_results()
        print("\n✅ Benchmark Complete! Results saved to benchmarks/api_results.json")

    async def _run_test(self, test_case) -> Dict[str, Any]:
        start = time.time()
        try:
            # Determine which endpoint to use based on domain
            if test_case['domain'] == 'logic':
                response = self.client.verify_logic(test_case['query'])
                return {
                    "status": response.status,
                    "answer": str(response.model) if response.model else None,
                    "latency_ms": (time.time() - start) * 1000
                }
            elif test_case['domain'] == 'fact':
                # Simplified context for benchmark
                context = "Paris is the capital of France." 
                response = self.client.verify_fact(test_case['query'], context)
                return {
                    "status": response.verdict,
                    "reasoning": response.reasoning,
                    "latency_ms": (time.time() - start) * 1000
                }
            else:
                # Default to natural language
                response = self.client.verify_natural_language(test_case['query'])
                return {
                    "status": response.status,
                    "answer": response.final_answer,
                    "latency_ms": response.latency_ms
                }
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e),
                "latency_ms": (time.time() - start) * 1000
            }

    def _save_results(self):
        with open("benchmarks/api_results.json", "w") as f:
            json.dump(self.results, f, indent=2)

if __name__ == "__main__":
    runner = ApiBenchmarkRunner()
    asyncio.run(runner.run_benchmark())
