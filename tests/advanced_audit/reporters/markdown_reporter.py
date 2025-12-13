"""
Markdown Reporter for QWED Test Results
Human-readable summary reports
"""

from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


class MarkdownReporter:
    """Generate Markdown reports from test results"""
    
    def __init__(self, output_dir: str = "./test_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, summary: Dict[str, Any], results: List[Dict[str, Any]]) -> str:
        """
        Generate comprehensive Markdown report
        
        Args:
            summary: Test summary statistics
            results: List of individual test results
        
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"qwed_test_report_{timestamp}.md"
        
        content = self._build_markdown(summary, results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(output_file)
    
    def _build_markdown(self, summary: Dict[str, Any], results: List[Dict[str, Any]]) -> str:
        """Build markdown content"""
        lines = []
        
        # Header
        lines.append("# QWED Comprehensive Test Audit Report")
        lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"\n**Duration:** {summary.get('duration_seconds', 0):.1f} seconds")
        lines.append("\n---\n")
        
        # Executive Summary
        lines.append("## Executive Summary\n")
        total = summary.get('total_tests', 0)
        passed = summary.get('passed', 0)
        failed = summary.get('failed', 0)
        pass_rate = summary.get('pass_rate', 0)
        
        lines.append(f"- **Total Tests:** {total}")
        lines.append(f"- **Passed:** {passed} ✅")
        lines.append(f"- **Failed:** {failed} ❌")
        lines.append(f"- **Pass Rate:** {pass_rate:.1f}%")
        
        # Emoji indicator
        if pass_rate >= 90:
            lines.append(f"\n**Status:** 🎉 EXCELLENT")
        elif pass_rate >= 75:
            lines.append(f"\n**Status:** ✅ GOOD")
        elif pass_rate >= 50:
            lines.append(f"\n**Status:** ⚠️ NEEDS IMPROVEMENT")
        else:
            lines.append(f"\n**Status:** ❌ CRITICAL ISSUES")
        
        lines.append("\n---\n")
        
        # By Priority
        lines.append("## Results by Priority\n")
        by_priority = summary.get('by_priority', {})
        
        lines.append("| Priority | Total | Passed | Failed | Pass Rate |")
        lines.append("|----------|-------|--------|--------|-----------|")
        
        for priority in ['critical', 'high', 'medium']:
            if priority in by_priority:
                stats = by_priority[priority]
                total = stats.get('total', 0)
                passed = stats.get('passed', 0)
                failed = total - passed
                rate = stats.get('pass_rate', 0)
                
                # Add emoji
                status = "✅" if rate >= 90 else "⚠️" if rate >= 75 else "❌"
                lines.append(f"| {status} {priority.upper()} | {total} | {passed} | {failed} | {rate:.1f}% |")
        
        lines.append("\n")
        
        # By Engine
        lines.append("## Results by Engine\n")
        by_engine = summary.get('by_engine', {})
        
        if by_engine:
            lines.append("| Engine | Total | Passed | Failed | Pass Rate |")
            lines.append("|--------|-------|--------|--------|-----------|")
            
            for engine, stats in sorted(by_engine.items()):
                total = stats.get('total', 0)
                passed = stats.get('passed', 0)
                failed = total - passed
                rate = stats.get('pass_rate', 0)
                
                status = "✅" if rate >= 80 else "⚠️" if rate >= 60 else "❌"
                lines.append(f"| {status} {engine} | {total} | {passed} | {failed} | {rate:.1f}% |")
            
            lines.append("\n")
        
        # Failed Tests Detail
        failures = [r for r in results if not r.get("passed", False)]
        if failures:
            lines.append(f"## ❌ Failed Tests ({len(failures)})\n")
            
            for fail in failures:
                lines.append(f"### {fail.get('test_name', 'Unknown Test')}")
                lines.append(f"- **Engine:** {fail.get('engine', 'N/A')}")
                lines.append(f"- **Priority:** {fail.get('priority', 'N/A')}")
                lines.append(f"- **Test ID:** `{fail.get('test_id', 'N/A')}`")
                
                if fail.get('error'):
                    lines.append(f"- **Error:** {fail.get('error')}")
                
                lines.append(f"- **Expected:** {fail.get('expected_result', 'N/A')}")
                lines.append(f"- **Timestamp:** {fail.get('timestamp', 'N/A')}")
                lines.append("")
        
        # Passed Tests Summary
        passed_tests = [r for r in results if r.get("passed", False)]
        if passed_tests:
            lines.append(f"## ✅ Passed Tests ({len(passed_tests)})\n")
            
            # Group by engine
            by_engine_passed = {}
            for test in passed_tests:
                engine = test.get('engine', 'unknown')
                if engine not in by_engine_passed:
                    by_engine_passed[engine] = []
                by_engine_passed[engine].append(test)
            
            for engine, tests in sorted(by_engine_passed.items()):
                lines.append(f"\n### {engine.upper()} Engine ({len(tests)} tests)")
                for test in tests:
                    lines.append(f"- ✅ {test.get('test_name')} ({test.get('latency_ms', 0):.0f}ms)")
        
        # Footer
        lines.append("\n---\n")
        lines.append("*Generated by QWED Advanced Testing Framework*")
        
        return "\n".join(lines)
