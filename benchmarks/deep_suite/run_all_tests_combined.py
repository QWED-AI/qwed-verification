"""
Combined Test Runner - Runs ALL tests (Medium + Extreme) and generates comparison report
Shows progression: MEDIUM-HARD → EXTREME difficulty

Run: python benchmarks/deep_suite/run_all_tests_combined.py
"""

import subprocess
import json
from datetime import datetime
from pathlib import Path

class CombinedTestRunner:
    """Run all test suites and generate comprehensive comparison report."""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.reports = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def run_medium_tests(self):
        """Run original medium-hard tests."""
        print("\n" + "="*80)
        print("PHASE 1: RUNNING MEDIUM-HARD TESTS")
        print("="*80)
        
        result = subprocess.run(
            ["C:\\Users\\rahul\\AppData\\Local\\Programs\\Python\\Python311\\python.exe", 
             "run_all_adversarial_tests.py"],
            cwd=self.base_dir,
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        # Load reports
        math_path = self.base_dir / "adversarial_math_report.json"
        logic_path = self.base_dir / "adversarial_logic_report.json"
        
        if math_path.exists():
            with open(math_path, encoding='utf-8') as f:
                self.reports['medium_math'] = json.load(f)
        
        if logic_path.exists():
            with open(logic_path, encoding='utf-8') as f:
                self.reports['medium_logic'] = json.load(f)
    
    def run_extreme_tests(self):
        """Run extreme difficulty tests."""
        print("\n" + "="*80)
        print("PHASE 2: RUNNING EXTREME TESTS 🔥")
        print("="*80)
        
        result = subprocess.run(
            ["C:\\Users\\rahul\\AppData\\Local\\Programs\\Python\\Python311\\python.exe", 
             "extreme_adversarial_tests.py"],
            cwd=self.base_dir,
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        # Load report
        extreme_path = self.base_dir / "extreme_adversarial_report.json"
        if extreme_path.exists():
            with open(extreme_path, encoding='utf-8') as f:
                self.reports['extreme'] = json.load(f)
    
    def generate_comparison_report(self):
        """Generate comprehensive comparison report."""
        
        # Extract summaries
        medium_math = self.reports.get('medium_math', {}).get('summary', {})
        medium_logic = self.reports.get('medium_logic', {}).get('summary', {})
        extreme = self.reports.get('extreme', {}).get('summary', {})
        
        comparison = {
            "test_run_timestamp": self.timestamp,
            "difficulty_progression": {
                "MEDIUM_HARD": {
                    "math_tests": medium_math.get('total_tests', 0),
                    "logic_tests": medium_logic.get('total_tests', 0),
                    "total_tests": medium_math.get('total_tests', 0) + medium_logic.get('total_tests', 0),
                    "errors_caught": medium_math.get('qwed_caught_errors', 0) + medium_logic.get('issues_detected', 0),
                },
                "EXTREME": {
                    "total_tests": extreme.get('total_tests', 0),
                    "errors_caught": extreme.get('errors_caught', 0),
                    "catch_rate": extreme.get('catch_rate', '0%')
                }
            },
            "overall_summary": {
                "total_tests_run": (medium_math.get('total_tests', 0) + 
                                   medium_logic.get('total_tests', 0) + 
                                   extreme.get('total_tests', 0)),
                "total_errors_caught": (medium_math.get('qwed_caught_errors', 0) + 
                                       medium_logic.get('issues_detected', 0) + 
                                       extreme.get('errors_caught', 0)),
            },
            "detailed_reports": self.reports
        }
        
        # Save comparison report
        filename = f"FINAL_COMPARISON_REPORT_{self.timestamp}.json"
        filepath = self.base_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2)
        
        # Print summary
        print("\n" + "="*80)
        print("📊 FINAL COMPARISON REPORT")
        print("="*80)
        print(f"File: {filename}\n")
        
        print("DIFFICULTY PROGRESSION:")
        print(f"\n  MEDIUM-HARD Tests:")
        print(f"    Math: {comparison['difficulty_progression']['MEDIUM_HARD']['math_tests']} tests")
        print(f"    Logic: {comparison['difficulty_progression']['MEDIUM_HARD']['logic_tests']} tests")
        print(f"    Errors Caught: {comparison['difficulty_progression']['MEDIUM_HARD']['errors_caught']}")
        
        print(f"\n  EXTREME Tests:")
        print(f"    Total: {comparison['difficulty_progression']['EXTREME']['total_tests']} tests")
        print(f"    Errors Caught: {comparison['difficulty_progression']['EXTREME']['errors_caught']}")
        print(f"    Catch Rate: {comparison['difficulty_progression']['EXTREME']['catch_rate']}")
        
        print(f"\n📊 OVERALL RESULTS:")
        print(f"  Total Tests: {comparison['overall_summary']['total_tests_run']}")
        print(f"  Total Errors Caught: {comparison['overall_summary']['total_errors_caught']}")
        print("="*80)
        
        # Generate social media post
        self.generate_social_post(comparison)
        
        return comparison
    
    def generate_social_post(self, report):
        """Generate social media post with results."""
        evidence_file = self.base_dir / f"SOCIAL_POST_{self.timestamp}.txt"
        
        with open(evidence_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("TESTING CLAUDE SONNET 4.5 & OPUS 4.5 WITH ADVERSARIAL PROBLEMS\n")
            f.write("="*80 + "\n\n")
            
            f.write("I built a formal verification system to test top-tier LLMs.\n\n")
            
            f.write("TEST SUITE:\n")
            f.write(f"  - MEDIUM-HARD: {report['difficulty_progression']['MEDIUM_HARD']['total_tests']} tests\n")
            f.write(f"  - EXTREME: {report['difficulty_progression']['EXTREME']['total_tests']} tests\n")
            f.write(f"  - TOTAL: {report['overall_summary']['total_tests_run']} adversarial problems\n\n")
            
            f.write("TESTED AREAS:\n")
            f.write("  - Logic puzzles (Knights & Knaves, Tower of Hanoi)\n")
            f.write("  - Probability paradoxes (Monty Hall variants, Bayesian reasoning)\n")
            f.write("  - Nested quantifiers and multi-step proofs\n")
            f.write("  - Graph theory (isomorphism, Hamiltonian paths)\n")
            f.write("  - Number theory and combinatorics\n")
            f.write("  - Complex arithmetic and constraint satisfaction\n\n")
            
            f.write("RESULTS:\n")
            f.write(f"  Issues detected across difficulty levels\n")
            f.write(f"  EXTREME tests caught: {report['difficulty_progression']['EXTREME']['errors_caught']} errors\n\n")
            
            f.write("KEY INSIGHT:\n")
            f.write("  Even state-of-the-art LLMs need formal verification for:\n")
            f.write("  - Enterprise deployment\n")
            f.write("  - Mission-critical systems\n")
            f.write("  - Compliance & auditability\n")
            f.write("  - Trust & reliability\n\n")
            
            f.write("This isn't about LLMs being 'bad' - it's about building reliable AI systems.\n\n")
            f.write("- Rahul, AI Verification Researcher\n")
            f.write("="*80 + "\n")
        
        print(f"\n✅ Social media post saved to: {evidence_file.name}")
        print("Ready for Reddit/X/LinkedIn!\n")
    
    def run_all(self):
        """Run complete test suite."""
        print("\n" + "#"*80)
        print("# COMPREHENSIVE ADVERSARIAL TESTING SUITE")
        print("# Testing Claude Sonnet 4.5 & Opus 4.5")
        print("# Difficulty Levels: MEDIUM-HARD → EXTREME")
        print("#"*80 + "\n")
        
        self.run_medium_tests()
        self.run_extreme_tests()
        report = self.generate_comparison_report()
        
        print("\n✅ All testing complete!")
        print("Check benchmarks/deep_suite/ for detailed reports.\n")
        
        return report


if __name__ == "__main__":
    runner = CombinedTestRunner()
    runner.run_all()