"""
QWED Complete Audit Test Runner
Main orchestrator for running all 7 engine tests with priority-based execution

Usage:
    python run_complete_audit.py --all
    python run_complete_audit.py --priority CRITICAL
    python run_complete_audit.py --engine code
    python run_complete_audit.py --report json markdown html
"""

import argparse
import yaml
import sys
import os
from pathlib import Path
from typing import List, Dict, Any
import logging
from datetime import datetime

# Add parent directory to path to import modules
sys.path.insert(0, str(Path(__file__).parent))

from api_client import QWEDAPIClient, APIResponse
from base_test import BaseTest, TestResult
from reporters.json_reporter import JSONReporter
from reporters.markdown_reporter import MarkdownReporter
from reporters.html_reporter import HTMLReporter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class QWEDTestRunner:
    """Main test orchestrator for QWED comprehensive auditing"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize test runner with configuration"""
        self.config = self._load_config(config_path)
        self.client = self._create_api_client()
        self.results: List[TestResult] = []
        self.start_time = None
        self.end_time = None
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load YAML configuration"""
        # noqa: PT - config_path is hardcoded at call site, not user input
        config_file = Path(__file__).parent / config_path
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        
        with open(config_file, 'r') as f:  # noqa: PTH123
            return yaml.safe_load(f)
    
    def _create_api_client(self) -> QWEDAPIClient:
        """Create configured API client"""
        api_config = self.config['api']
        return QWEDAPIClient(
            base_url=api_config['url'],
            api_key=api_config['key'],
            timeout=api_config.get('timeout', 30),
            max_retries=api_config.get('max_retries', 3)
        )
    
    def run_health_check(self) -> bool:
        """Verify QWED API is accessible"""
        logger.info("="*80)
        logger.info("QWED API Health Check")
        logger.info("="*80)
        
        response = self.client.health_check()
        
        if response.success:
            logger.info(f"✅ API is healthy: {self.client.base_url}")
            return True
        else:
            logger.error(f"❌ API health check failed: {response.error}")
            logger.error(f"   URL: {self.client.base_url}")
            logger.error(f"   Please verify the API is running and accessible")
            return False
    
    def load_test_suites(self, priority: str = None, engine: str = None) -> List[BaseTest]:
        """Load test suites based on filters"""
        tests = []
        test_suite_dir = Path(__file__).parent / "test_suites"
        
        logger.info(f"Loading test suites from: {test_suite_dir}")
        logger.info(f"Filters: priority={priority}, engine={engine}")
        
        # Import available test modules
        for test_file in test_suite_dir.glob("*.py"):
            if test_file.name.startswith("_") or test_file.name == "example_test.py":
                continue
            
            try:
                module_name = test_file.stem
                spec = __import__(f"test_suites.{module_name}", fromlist=['AVAILABLE_TESTS'])
                
                if hasattr(spec, 'AVAILABLE_TESTS'):
                    for test in spec.AVAILABLE_TESTS:
                        # Apply filters
                        if priority and test.priority != priority:
                            continue
                        if engine and test.engine != engine:
                            continue
                        
                        tests.append(test)
                        logger.info(f"  Loaded: [{test.engine}] {test.test_name}")
            
            except Exception as e:
                logger.error(f"  Failed to load {test_file.name}: {e}")
        
        logger.info(f"\nTotal tests loaded: {len(tests)}")
        return tests
    
    def run_tests(self, tests: List[BaseTest]) -> List[TestResult]:
        """Execute all tests and collect results"""
        logger.info("="*80)
        logger.info(f"Running {len(tests)} tests")
        logger.info("="*80)
        
        self.start_time = datetime.now()
        results = []
        
        for i, test in enumerate(tests, 1):
            logger.info(f"\n[{i}/{len(tests)}] Running: {test.test_name}")
            logger.info(f"  Engine: {test.engine} | Priority: {test.priority}")
            
            try:
                result = test.execute(self.client)
                results.append(result)
                
                status = "✅ PASS" if result.passed else "❌ FAIL"
                logger.info(f"  {status} ({result.latency_ms:.0f}ms)")
                
                if not result.passed and result.error:
                    logger.error(f"  Error: {result.error}")
            
            except Exception as e:
                logger.error(f"  ❌ Test crashed: {str(e)}")
                results.append(TestResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    engine=test.engine,
                    priority=test.priority,
                    passed=False,
                    expected_result="N/A",
                    actual_result={},
                    error=str(e)
                ))
        
        self.end_time = datetime.now()
        self.results = results
        return results
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate test summary statistics"""
        if not self.results:
            return {}
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        
        # By priority
        critical_results = [r for r in self.results if r.priority == "CRITICAL"]
        high_results = [r for r in self.results if r.priority == "HIGH"]
        medium_results = [r for r in self.results if r.priority == "MEDIUM"]
        
        # By engine
        engines = {}
        for result in self.results:
            engine = result.engine
            if engine not in engines:
                engines[engine] = {"total": 0, "passed": 0}
            engines[engine]["total"] += 1
            if result.passed:
                engines[engine]["passed"] += 1
        
        # Calculate pass rates
        for engine in engines:
            total_e = engines[engine]["total"]
            passed_e = engines[engine]["passed"]
            engines[engine]["pass_rate"] = (passed_e / total_e * 100) if total_e > 0 else 0
        
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        
        return {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": (passed / total * 100) if total > 0 else 0,
            "by_priority": {
                "critical": {
                    "total": len(critical_results),
                    "passed": sum(1 for r in critical_results if r.passed),
                    "pass_rate": (sum(1 for r in critical_results if r.passed) / len(critical_results) * 100) if critical_results else 0
                },
                "high": {
                    "total": len(high_results),
                    "passed": sum(1 for r in high_results if r.passed),
                    "pass_rate": (sum(1 for r in high_results if r.passed) / len(high_results) * 100) if high_results else 0
                },
                "medium": {
                    "total": len(medium_results),
                    "passed": sum(1 for r in medium_results if r.passed),
                    "pass_rate": (sum(1 for r in medium_results if r.passed) / len(medium_results) * 100) if medium_results else 0
                }
            },
            "by_engine": engines
        }
    
    def print_summary(self):
        """Print summary to console"""
        summary = self.generate_summary()
        
        if not summary:
            logger.info("\nNo tests were run.")
            return
        
        logger.info("\n" + "="*80)
        logger.info("TEST SUMMARY")
        logger.info("="*80)
        logger.info(f"Total Tests: {summary['total_tests']}")
        logger.info(f"Passed: {summary['passed']} ({summary['pass_rate']:.1f}%)")
        logger.info(f"Failed: {summary['failed']}")
        logger.info(f"Duration: {summary['duration_seconds']:.1f}s")
        
        logger.info("\nBy Priority:")
        for priority, stats in summary['by_priority'].items():
            logger.info(f"  {priority.upper()}: {stats['passed']}/{stats['total']} ({stats['pass_rate']:.1f}%)")
        
        logger.info("\nBy Engine:")
        for engine, stats in summary['by_engine'].items():
            logger.info(f"  {engine}: {stats['passed']}/{stats['total']} ({stats['pass_rate']:.1f}%)")
        
        logger.info("="*80)
        
        # List failures
        failures = [r for r in self.results if not r.passed]
        if failures:
            logger.info(f"\n❌ Failed Tests ({len(failures)}):")
            for fail in failures:
                logger.info(f"  - [{fail.engine}] {fail.test_name}")
                if fail.error:
                    logger.info(f"    Error: {fail.error}")
    
    def save_results(self, formats: List[str] = None):
        """Save results in multiple formats"""
        if formats is None:
            formats = self.config['reporting'].get('formats', ['json'])
        
        output_dir = self.config['reporting']['output_dir']
        summary = self.generate_summary()
        results_dict = [r.to_dict() for r in self.results]
        
        saved_files = []
        
        for format in formats:
            logger.info(f"\nGenerating {format.upper()} report...")
            
            if format == "json":
                reporter = JSONReporter(output_dir)
                file_path = reporter.generate_report(summary, results_dict)
                saved_files.append(file_path)
                logger.info(f"  ✅ JSON report: {file_path}")
            
            elif format == "markdown":
                reporter = MarkdownReporter(output_dir)
                file_path = reporter.generate_report(summary, results_dict)
                saved_files.append(file_path)
                logger.info(f"  ✅ Markdown report: {file_path}")
            
            elif format == "html":
                reporter = HTMLReporter(output_dir)
                file_path = reporter.generate_report(summary, results_dict)
                saved_files.append(file_path)
                logger.info(f"  ✅ HTML dashboard: {file_path}")
        
        return saved_files


def main():
    parser = argparse.ArgumentParser(description="QWED Complete Audit Test Runner")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--priority", choices=["CRITICAL", "HIGH", "MEDIUM"], help="Run tests by priority")
    parser.add_argument("--engine", choices=["code", "math", "logic", "stats", "sql", "fact", "image"], help="Run tests for specific engine")
    parser.add_argument("--report", nargs='+', choices=["json", "html", "markdown"], help="Report formats (can specify multiple)")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    
    args = parser.parse_args()
    
    try:
        runner = QWEDTestRunner(config_path=args.config)
        
        # Health check first
        if not runner.run_health_check():
            logger.error("\n❌ QWED API is not accessible. Aborting.")
            sys.exit(1)
        
        # Load tests
        priority = args.priority if not args.all else None
        engine = args.engine if not args.all else None
        tests = runner.load_test_suites(priority=priority, engine=engine)
        
        if not tests:
            logger.warning("\n⚠️  No tests loaded.")
            logger.info("Add test files to test_suites/ directory")
            return
        
        # Run tests
        runner.run_tests(tests)
        
        # Print summary
        runner.print_summary()
        
        # Save results in requested formats
        formats = args.report if args.report else runner.config['reporting'].get('formats', ['json'])
        runner.save_results(formats=formats)
    
    except KeyboardInterrupt:
        logger.info("\n\nTest run interrupted by user.")
        sys.exit(1)
    
    except Exception as e:
        logger.error(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
