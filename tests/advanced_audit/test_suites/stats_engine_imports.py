"""
Stats Engine Test Suite - Import Security
Tests for dangerous import patterns in statistical code
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_OS_Import_In_Stats(BaseTest):
    """Test: Detect os module import in stats code"""
    
    def __init__(self):
        super().__init__(
            test_id="STATS_IMP_001",
            test_name="Detect os module in statistical code",
            engine="stats",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        # Stats code that imports os (suspicious)
        code = """
import pandas as pd
import os

df = pd.read_csv("data.csv")
os.system("rm data.csv")  # Suspicious!
"""
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_code(code)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="WARNING/CRITICAL - os.system detected",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be flagged
        passed = not response.data.get("is_safe", True)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - os.system() detected",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Subprocess_In_Stats(BaseTest):
    """Test: Detect subprocess in statistical code"""
    
    def __init__(self):
        super().__init__(
            test_id="STATS_IMP_002",
            test_name="Detect subprocess in stats code",
            engine="stats",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # Stats code that uses subprocess
        code = """
import subprocess
import pandas as pd

data = subprocess.check_output(["cat", "/etc/passwd"])
df = pd.DataFrame({"data": [data]})
"""
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_code(code)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="CRITICAL - subprocess detected",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be flagged as critical
        passed = not response.data.get("is_safe", True)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - subprocess usage",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Pickle_In_Stats(BaseTest):
    """Test: Detect pickle.loads() in stats code (RCE risk)"""
    
    def __init__(self):
        super().__init__(
            test_id="STATS_IMP_003",
            test_name="Detect pickle.loads() RCE risk",
            engine="stats",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # Stats code using pickle (dangerous)
        code = """
import pickle
import pandas as pd

with open("model.pkl", "rb") as f:
    user_data = input("Data: ").encode()
    model = pickle.loads(user_data)  # RCE!
"""
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_code(code)
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="CRITICAL - pickle.loads with user input",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be flagged
        passed = not response.data.get("is_safe", True)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - pickle.loads() detected",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_OS_Import_In_Stats(),
    Test_Subprocess_In_Stats(),
    Test_Pickle_In_Stats()
]
