"""
Math Engine Test Suite - Expression Ambiguity
Tests for detecting ambiguous mathematical expressions
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_OrderOfOperations_Ambiguity(BaseTest):
    """Test 4A: Famous 8/2(2+2) ambiguity"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_AMB_001",
            test_name="Detect order of operations ambiguity",
            engine="math",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        expression = "8/2(2+2)"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="WARNING - Ambiguous expression",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should detect ambiguity (could be 16 or 1)
        passed = (self._check_result("WARNING", response.data) or 
                 "ambiguous" in str(response.data).lower())
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="WARNING - Ambiguous (16 vs 1)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_ImplicitMultiplication(BaseTest):
    """Test 4B: Implicit multiplication handling"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_AMB_002",
            test_name="Handle implicit multiplication (2x vs 2*x)",
            engine="math",
            priority="MEDIUM"
        )
    
    def execute(self, api_client) -> TestResult:
        # These should be treated as equivalent
        expr1 = "2x + 3"
        expr2 = "2*x + 3"
        
        self.log_info(f"Testing {self.test_name}...")
        response1 = api_client.verify_math(expr1)
        response2 = api_client.verify_math(expr2)
        
        if not response1.success or not response2.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="Both parse successfully",
                actual_result={},
                error=response1.error or response2.error,
                latency_ms=response1.latency_ms + response2.latency_ms
            )
        
        # Both should be valid and ideally equivalent
        passed = response1.success and response2.success
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="Both expressions parse successfully",
            actual_result={"expr1": response1.data, "expr2": response2.data},
            latency_ms=response1.latency_ms + response2.latency_ms
        )


class Test_DivisionByZero(BaseTest):
    """Test: Division by zero detection"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_AMB_003",
            test_name="Detect division by zero",
            engine="math",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        expression = "5/0"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression)
        
        if not response.success:
            # Error is expected - division by zero should fail
            passed = "division by zero" in str(response.error).lower() or "divide" in str(response.error).lower()
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=passed,
                expected_result="Error or warning about division by zero",
                actual_result={"error": response.error},
                latency_ms=response.latency_ms
            )
        
        # If it doesn't error, check if it flags it
        passed = "undefined" in str(response.data).lower() or "error" in str(response.data).lower()
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="Division by zero flagged",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_OrderOfOperations_Ambiguity(),
    Test_ImplicitMultiplication(),
    Test_DivisionByZero()
]
