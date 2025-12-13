"""
Logic Engine Test Suite - Contradictions
Tests for detecting various types of contradictions (UNSAT cases)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_Circular_Dependency(BaseTest):
    """Test: Circular dependency contradiction"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_UNSAT_002",
            test_name="Detect circular dependency (x=y+1 AND y=x+1)",
            engine="logic",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        # x = y + 1 AND y = x + 1 (circular, impossible)
        query = "x == y + 1 AND y == x + 1"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="UNSAT (circular)",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be UNSAT
        passed = response.data.get("status") == "UNSAT"
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="UNSAT (circular dependency)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Boolean_Contradiction(BaseTest):
    """Test: Boolean contradiction (P AND NOT P)"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_UNSAT_003",
            test_name="Detect boolean contradiction (P AND NOT P)",
            engine="logic",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # P AND NOT P (always false)
        query = "P and not P"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="UNSAT",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be UNSAT
        passed = response.data.get("status") == "UNSAT"
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="UNSAT (logical contradiction)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Multiple_Constraints_UNSAT(BaseTest):
    """Test: Multiple conflicting constraints"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_UNSAT_004",
            test_name="Detect conflict in multiple constraints",
            engine="logic",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        # x > 5, x < 10, x == 15 (conflict)
        query = "x > 5 AND x < 10 AND x == 15"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="UNSAT",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be UNSAT (15 is not between 5 and 10)
        passed = response.data.get("status") == "UNSAT"
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="UNSAT (conflicting constraints)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_Circular_Dependency(),
    Test_Boolean_Contradiction(),
    Test_Multiple_Constraints_UNSAT()
]
