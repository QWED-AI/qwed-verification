"""
Logic Engine Test Suite - Satisfiability Tests
Tests for basic SAT/UNSAT logic constraint verification
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_Simple_SAT(BaseTest):
    """Test: Simple satisfiable constraints"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_SAT_001",
            test_name="Verify simple SAT constraints",
            engine="logic",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # x > 5 AND x < 10 (should be SAT with x=6,7,8,9)
        query = "x > 5 AND x < 10"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="SAT with solution",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be SAT
        passed = response.data.get("status") == "SAT" and response.data.get("model") is not None
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="SAT with solution (x=6,7,8,or 9)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Simple_UNSAT(BaseTest):
    """Test: Simple contradiction (UNSAT)"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_UNSAT_001",
            test_name="Detect simple contradiction (UNSAT)",
            engine="logic",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # x > 10 AND x < 5 (impossible)
        query = "x > 10 AND x < 5"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="UNSAT (contradictory)",
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
            expected_result="UNSAT (contradiction)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Boolean_Logic_SAT(BaseTest):
    """Test: Boolean logic satisfiability"""
    
    def __init__(self):
        super().__init__(
            test_id="LOGIC_SAT_002",
            test_name="Verify boolean logic constraints",
            engine="logic",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # P OR Q (should be SAT)
        query = "P or Q"
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_logic(query)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="SAT with boolean solution",
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
            expected_result="SAT (P=True or Q=True)",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_Simple_SAT(),
    Test_Simple_UNSAT(),
    Test_Boolean_Logic_SAT()
]
