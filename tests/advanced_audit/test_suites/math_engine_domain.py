"""
Math Engine Test Suite - Domain Restrictions
Tests for detecting invalid domain operations
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_SquareRoot_NegativeNumber(BaseTest):
    """Test: Square root of negative (real domain)"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_DOM_001",
            test_name="Detect sqrt of negative in real domain",
            engine="math",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        expression = "sqrt(-4)"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression, context={"domain": "real"})
        
        if not response.success:
            # Error is expected for negative sqrt in real domain
            passed = "domain" in str(response.error).lower() or "negative" in str(response.error).lower()
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=passed,
                expected_result="Error - undefined in real domain",
                actual_result={"error": response.error},
                latency_ms=response.latency_ms
            )
        
        # If not error, should flag as undefined/complex
        passed = "complex" in str(response.data).lower() or "undefined" in str(response.data).lower()
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="Undefined in real domain",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Logarithm_ZeroOrNegative(BaseTest):
    """Test: Log of non-positive number"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_DOM_002",
            test_name="Detect log(0) undefined",
            engine="math",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        expression = "log(0)"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression)
        
        if not response.success:
            # Error is expected
            passed = "undefined" in str(response.error).lower() or "domain" in str(response.error).lower()
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=passed,
                expected_result="Error - log(0) undefined",
                actual_result={"error": response.error},
                latency_ms=response.latency_ms
            )
        
        # Should flag as undefined
        passed = "undefined" in str(response.data).lower()
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="Undefined - log(0)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_SquareRoot_NegativeNumber(),
    Test_Logarithm_ZeroOrNegative()
]
