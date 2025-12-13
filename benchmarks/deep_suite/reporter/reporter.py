"""
Deep Benchmark Reporter.
Generates comprehensive reports from benchmark results.
"""

import json
import os
import glob
from typing import List, Dict
from benchmarks.deep_suite.runner_base import BenchmarkResult

class DeepReporter:
    def __init__(self, results_dir: str = "benchmarks/deep_suite/results"):
        self.results_dir = results_dir

    def generate_report(self):
        # Load all results
        all_results = []
        for f in glob.glob(os.path.join(self.results_dir, "*.json")):
            with open(f, "r") as file:
                all_results.extend(json.load(file))
        
        if not all_results:
            print("No results found.")
            return

        # Calculate Metrics
        stats = self._calculate_stats(all_results)
        
        # Generate Markdown
        report = self._generate_markdown(stats, all_results)
        
        with open("DEEP_BENCHMARK_REPORT.md", "w", encoding="utf-8") as f:
            f.write(report)
            
        print("✅ Deep Benchmark Report Generated: DEEP_BENCHMARK_REPORT.md")

    def _calculate_stats(self, results: List[Dict]) -> Dict:
        stats = {
            "total": len(results),
            "pass": 0,
            "fail": 0,
            "unverifiable": 0,
            "by_difficulty": {}
        }
        
        for r in results:
            verdict = r["qwed_verdict"]
            diff = r["difficulty"]
            
            if verdict == "PASS": stats["pass"] += 1
            elif verdict == "FAIL": stats["fail"] += 1
            elif verdict == "UNVERIFIABLE": stats["unverifiable"] += 1
            
            if diff not in stats["by_difficulty"]:
                stats["by_difficulty"][diff] = {"total": 0, "pass": 0}
            
            stats["by_difficulty"][diff]["total"] += 1
            if verdict == "PASS":
                stats["by_difficulty"][diff]["pass"] += 1
                
        return stats

    def _generate_markdown(self, stats: Dict, results: List[Dict]) -> str:
        md = "# 📉 QWED Deep Benchmark Report\n\n"
        
        # Executive Summary
        pass_rate = (stats["pass"] / stats["total"]) * 100
        md += f"## 📊 Executive Summary\n"
        md += f"- **Total Tests**: {stats['total']}\n"
        md += f"- **Overall Pass Rate**: {pass_rate:.1f}%\n"
        md += f"- **Failures**: {stats['fail']}\n\n"
        
        # Difficulty Breakdown
        md += "## 🏗️ Breakdown by Difficulty\n\n"
        md += "| Difficulty | Total | Pass Rate | Status |\n"
        md += "|------------|-------|-----------|--------|\n"
        
        for diff, data in stats["by_difficulty"].items():
            rate = (data["pass"] / data["total"]) * 100
            status = "✅" if rate > 90 else ("⚠️" if rate > 50 else "❌")
            md += f"| {diff.upper()} | {data['total']} | {rate:.1f}% | {status} |\n"
            
        # Failure Analysis (Collapse Cases)
        md += "\n## 💀 Collapse & Failure Analysis\n\n"
        md += "| ID | Query | Expected | QWED Answer | Verdict |\n"
        md += "|----|-------|----------|-------------|---------|\n"
        
        for r in results:
            if r["qwed_verdict"] != "PASS" or r["difficulty"] == "collapse":
                qwed_ans = str(r["qwed_answer"])[:50].replace("\n", " ")
                md += f"| {r['id']} | {r['query'][:30]}... | {r['expected']} | {qwed_ans} | {r['qwed_verdict']} |\n"
                
        return md

if __name__ == "__main__":
    reporter = DeepReporter()
    reporter.generate_report()
