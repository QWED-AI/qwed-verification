"""
Math Engine Test Suite - Symbolic Simplification
Tests for algebraic identity verification
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_AlgebraicIdentity_True(BaseTest):
    """Test 5A: Valid algebraic identity (x²-y² = (x-y)(x+y))"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_SYM_001",
            test_name="Verify true algebraic identity",
            engine="math",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # This is a TRUE identity
        expression = "(x**2 - y**2) = (x-y)*(x+y)"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="VERIFIED - Identity is true",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should verify as TRUE
        passed = (response.data.get("is_valid") == True or 
                 response.data.get("result") == True or
                 "true" in str(response.data).lower())
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="TRUE - Difference of squares identity",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_AlgebraicIdentity_False1(BaseTest):
    """Test 5B: False identity (x+y)² ≠ x²+y²"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_SYM_002",
            test_name="Detect false algebraic identity (missing 2xy)",
            engine="math",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # This is FALSE - missing 2xy term
        expression = "(x+y)**2 = x**2 + y**2"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="FALSE - Missing 2xy term",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should verify as FALSE
        passed = (response.data.get("is_valid") == False or 
                 response.data.get("result") == False or
                 "false" in str(response.data).lower())
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="FALSE - Should be x²+2xy+y²",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_SquareRoot_AbsoluteValue(BaseTest):
    """Test 5C: sqrt(x²) = |x|, not x"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_SYM_003",
            test_name="Detect sqrt(x²) ≠ x (should be |x|)",
            engine="math",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        # This is FALSE - should be |x|
        expression = "sqrt(x**2) = x"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="FALSE - Should be |x|",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should verify as FALSE (correct is |x|)
        passed = (response.data.get("is_valid") == False or 
                 response.data.get("result") == False or
                 "false" in str(response.data).lower())
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="FALSE - sqrt(x²) = |x|, not x",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_SimpleArithmetic(BaseTest):
    """Test: Basic arithmetic verification"""
    
    def __init__(self):
        super().__init__(
            test_id="MATH_SYM_004",
            test_name="Verify simple arithmetic (2+2=4)",
            engine="math",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        expression = "2+2=4"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_math(expression)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="TRUE",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be TRUE
        passed = (response.data.get("is_valid") == True or 
                 response.data.get("result") == True or
                 "true" in str(response.data).lower() or
                 response.data.get("value") == 4)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="TRUE - Basic arithmetic",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_AlgebraicIdentity_True(),
    Test_AlgebraicIdentity_False1(),
    Test_SquareRoot_AbsoluteValue(),
    Test_SimpleArithmetic()
]
