"""
Master Test Runner - Run All Adversarial Tests Against Claude Models
Generates comprehensive evidence for social media proof.

Run: python benchmarks/deep_suite/run_all_adversarial_tests.py
"""

import subprocess
import json
import os
from datetime import datetime
from pathlib import Path

class MasterTestRunner:
    """Coordinate all adversarial tests and generate combined report."""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.reports = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def run_math_tests(self):
        """Run adversarial math tests."""
        print("\n" + "="*80)
        print("RUNNING ADVERSARIAL MATH TESTS")
        print("="*80)
        
        result = subprocess.run(
            ["python", "adversarial_math_tests.py"],
            cwd=self.base_dir,
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        # Load the generated report
        report_path = self.base_dir / "adversarial_math_report.json"
        if report_path.exists():
            with open(report_path) as f:
                self.reports['math'] = json.load(f)
    
    def run_logic_tests(self):
        """Run adversarial logic tests."""
        print("\n" + "="*80)
        print("RUNNING ADVERSARIAL LOGIC TESTS")
        print("="*80)
        
        result = subprocess.run(
            ["python", "adversarial_logic_tests.py"],
            cwd=self.base_dir,
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        # Load the generated report
        report_path = self.base_dir / "adversarial_logic_report.json"
        if report_path.exists():
            with open(report_path) as f:
                self.reports['logic'] = json.load(f)
    
    def generate_master_report(self):
        """Generate combined report."""
        math_summary = self.reports.get('math', {}).get('summary', {})
        logic_summary = self.reports.get('logic', {}).get('summary', {})
        
        master_report = {
            "test_run_timestamp": self.timestamp,
            "overall_summary": {
                "total_math_tests": math_summary.get('total_tests', 0),
                "total_logic_tests": logic_summary.get('total_tests', 0),
                "total_tests": math_summary.get('total_tests', 0) + logic_summary.get('total_tests', 0),
                "math_errors_caught": math_summary.get('qwed_caught_errors', 0),
                "logic_issues_detected": logic_summary.get('issues_detected', 0),
                "total_issues_caught": math_summary.get('qwed_caught_errors', 0) + logic_summary.get('issues_detected', 0),
            },
            "math_results": self.reports.get('math', {}),
            "logic_results": self.reports.get('logic', {})
        }
        
        # Save master report
        filename = f"master_adversarial_report_{self.timestamp}.json"
        filepath = self.base_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(master_report, f, indent=2)
        
        print("\n" + "="*80)
        print("MASTER REPORT GENERATED")
        print("="*80)
        print(f"File: {filename}")
        print(f"\nOVERALL SUMMARY:")
        print(f"  Total Tests Run: {master_report['overall_summary']['total_tests']}")
        print(f"  Math Tests: {master_report['overall_summary']['total_math_tests']}")
        print(f"  Logic Tests: {master_report['overall_summary']['total_logic_tests']}")
        print(f"  Total Issues Caught by QWED: {master_report['overall_summary']['total_issues_caught']}")
        print(f"  Math Errors Caught: {master_report['overall_summary']['math_errors_caught']}")
        print(f"  Logic Issues Detected: {master_report['overall_summary']['logic_issues_detected']}")
        print("="*80)
        
        # Generate social media evidence
        self.generate_social_media_evidence(master_report)
        
        return master_report
    
    def generate_social_media_evidence(self, report):
        """Generate evidence snippets for social media."""
        evidence_file = self.base_dir / f"social_media_evidence_{self.timestamp}.txt"
        
        with open(evidence_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("QWED VERIFICATION ENGINE - TEST RESULTS\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"ðŸŽ¯ Tested Advanced LLMs (Claude Sonnet 4.5 & Opus 4.5) with adversarial problems\n\n")
            
            f.write(f"ðŸ“Š RESULTS:\n")
            f.write(f"   Total Tests: {report['overall_summary']['total_tests']}\n")
            f.write(f"   LLM Errors Detected: {report['overall_summary']['total_issues_caught']}\n\n")
            
            # Math evidence
            if report.get('math_results', {}).get('caught_errors'):
                f.write(f"ðŸ”¢ MATH ENGINE CATCHES:\n")
                for i, error in enumerate(report['math_results']['caught_errors'][:3], 1):
                    f.write(f"\n   Example {i}:\n")
                    f.write(f"   Query: {error['query']}\n")
                    f.write(f"   LLM Answer: {error['llm_answer']}\n")
                    f.write(f"   Correct Answer: {error['expected']}\n")
                    f.write(f"   âœ… QWED CAUGHT THE ERROR\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("This proves why verification layers are critical for AI safety.\n")
            f.write("="*80 + "\n")
        
        print(f"\nSocial media evidence saved to: {evidence_file.name}")
        print("Use this for Twitter/LinkedIn posts!\n")
    
    def run_all(self):
        """Run all tests and generate reports."""
        print("\n" + "#"*80)
        print("# QWED ADVERSARIAL TESTING SUITE")
        print("# Proving the Need for Verification Layers")
        print("#"*80 + "\n")
        
        self.run_math_tests()
        self.run_logic_tests()
        report = self.generate_master_report()
        
        print("\nâœ… All tests complete!")
        print(f"Check benchmarks/deep_suite/ for detailed reports.\n")
        
        return report


if __name__ == "__main__":
    runner = MasterTestRunner()
    runner.run_all()

