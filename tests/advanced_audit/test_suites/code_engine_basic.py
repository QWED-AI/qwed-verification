# First real test for Code Engine
# Tests eval() detection with CRITICAL severity

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_Code_Eval_Detection(BaseTest):
    """Test 1: Detect eval() with user input"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_001",
            test_name="Detect eval() with user input",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        """Execute the test against real QWED API"""
        code = '''
user_code = input("Enter code: ")
eval(user_code)  # RCE vulnerability
'''
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_code(code, language="python")
        
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
        
        # Check if CRITICAL severity was detected
        passed = self._check_result("CRITICAL", response.data)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - eval() with user input",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Code_Pickle_Detection(BaseTest):
    """Test 2: Detect pickle.loads() vulnerability"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_002",
            test_name="Detect pickle.loads() RCE",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        """Execute the test against real QWED API"""
        code = '''
import pickle
data = input("Data: ")
obj = pickle.loads(data)  # Deserialization RCE
'''
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_code(code, language="python")
        
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
        
        passed = self._check_result("CRITICAL", response.data)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - pickle.loads()",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export available tests
AVAILABLE_TESTS = [
    Test_Code_Eval_Detection(),
    Test_Code_Pickle_Detection()
]
