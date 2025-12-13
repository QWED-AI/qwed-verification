"""
Logic Engine Test Suite - Complex Constraints
Tests for more complex logical scenarios
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_Inequality_Chain_SAT(BaseTest):
    """Test: Chain of inequalities (SAT)"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_SAT_003",
            test_name="Verify inequality chain (x < y < z)",
            engine="logic",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        # x < y AND y < z (should be SAT)
        query = "x < y AND y < z"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="SAT",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be SAT
        passed = response.data.get("status") == "SAT"
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="SAT (e.g., x=0, y=1, z=2)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Divisibility_Constraint(BaseTest):
    """Test: Divisibility constraint"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_SAT_004",
            test_name="Verify divisibility constraint (x % 5 == 0)",
            engine="logic",
            priority="MEDIUM"
        )
    
    def execute(self, api_client) -> TestResult:
        # x % 5 == 0 AND x > 0 AND x < 20
        query = "x % 5 == 0 AND x > 0 AND x < 20"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="SAT",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be SAT (x=5,10,15)
        passed = response.data.get("status") == "SAT"
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="SAT (x=5, 10, or 15)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Implication_Logic(BaseTest):
    """Test: Logical implication"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_SAT_005",
            test_name="Verify implication (P implies Q)",
            engine="logic",
            priority="MEDIUM"
        )
    
    def execute(self, api_client) -> TestResult:
        # P AND (P implies Q) should mean Q is true
        query = "P and (not P or Q)"  # P → Q is equivalent to ¬P ∨ Q
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="SAT",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be SAT (P=True, Q=True)
        passed = response.data.get("status") == "SAT"
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="SAT (P=True, Q=True)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_Inequality_Chain_SAT(),
    Test_Divisibility_Constraint(),
    Test_Implication_Logic()
]
