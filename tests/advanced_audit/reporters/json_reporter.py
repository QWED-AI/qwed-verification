"""
JSON Reporter for QWED Test Results
Machine-readable output for CI/CD integration
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


class JSONReporter:
    """Generate JSON reports from test results"""
    
    def __init__(self, output_dir: str = "./test_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, summary: Dict[str, Any], results: List[Dict[str, Any]]) -> str:
        """
        Generate comprehensive JSON report
        
        Args:
            summary: Test summary statistics
            results: List of individual test results
        
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"qwed_test_report_{timestamp}.json"
        
        report = {
            "metadata": {
                "report_type": "QWED_COMPREHENSIVE_AUDIT",
                "generated_at": datetime.now().isoformat(),
                "version": "1.0"
            },
            "summary": summary,
            "results": results,
            "failures": [r for r in results if not r.get("passed", False)],
            "statistics": self._calculate_statistics(results)
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(output_file)
    
    def _calculate_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate detailed statistics"""
        if not results:
            return {}
        
        latencies = [r.get("latency_ms", 0) for r in results]
        
        return {
            "total_tests": len(results),
            "passed_count": sum(1 for r in results if r.get("passed", False)),
            "failed_count": sum(1 for r in results if not r.get("passed", False)),
            "latency": {
                "min_ms": min(latencies) if latencies else 0,
                "max_ms": max(latencies) if latencies else 0,
                "avg_ms": sum(latencies) / len(latencies) if latencies else 0
            },
            "engines_tested": list(set(r.get("engine", "unknown") for r in results)),
            "priorities_tested": list(set(r.get("priority", "unknown") for r in results))
        }
