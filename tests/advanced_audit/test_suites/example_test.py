"""
Simple test to verify the framework works
This demonstrates how to write a real test
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class SimpleCodeTest(BaseTest):
    """Example: Test eval() detection"""
    
    def __init__(self):
        super().__init__(
            test_id="code_001",
            test_name="Detect eval() usage",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        """Run the test"""
        code = '''
user_input = input("Code: ")
eval(user_input)  # Should be detected as CRITICAL
'''
        
        self.log_info("Testing eval() detection...")
        response = api_client.verify_code(code)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="CRITICAL",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Check if eval was detected as CRITICAL
        passed = self._check_result("CRITICAL", response.data)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Add test to registry (will be automated later)
AVAILABLE_TESTS = [
    SimpleCodeTest()
]
