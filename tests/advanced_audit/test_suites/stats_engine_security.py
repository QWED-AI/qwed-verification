"""
Stats Engine Test Suite - Security Tests
Tests for detecting code execution vulnerabilities in statistical analysis code
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_DataFrame_Eval_Injection(BaseTest):
    """Test: Detect DataFrame.eval() with user input (RCE)"""
    
    def __init__(self):
        super().__init__(
            test_id="STATS_SEC_001",
            test_name="Detect DataFrame.eval() injection risk",
            engine="stats",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # Code that uses df.eval() with user input - dangerous!
        code = """
import pandas as pd
user_formula = input("Formula: ")
df = pd.DataFrame({"x": [1,2,3]})
result = df.eval(user_formula)  # RCE via eval!
"""
        
        self.log_info(f"Testing {self.test_name}...")
        response = api_client.verify_code(code)  # Using verify_code since stats needs file upload
        
        if not response.success:
            return TestResult(
                test_id=self.test_id,
                test_name=self.test_name,
                engine=self.engine,
                priority=self.priority,
                passed=False,
                expected_result="CRITICAL - DataFrame.eval with user input",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should detect as unsafe - eval is dangerous
        issues = response.data.get("issues", [])
        has_eval_warning = any("eval" in issue.get("description", "").lower() for issue in issues)
        is_unsafe = not response.data.get("is_safe", True)
        
        passed = is_unsafe or has_eval_warning
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - eval() with user input detected",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Exec_In_Analysis(BaseTest):
    """Test: Detect exec() in statistical analysis code"""
    
    def __init__(self):
        super().__init__(
            test_id="STATS_SEC_002",
            test_name="Detect exec() in analysis code",
            engine="stats",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        # Code that uses exec() with user input
        code = """
analysis_code = input("Enter analysis: ")
exec(analysis_code)  # Direct RCE
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
                expected_result="CRITICAL - exec() detected",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be flagged as unsafe
        passed = not response.data.get("is_safe", True)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - exec() with user input",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Safe_Pandas_Operations(BaseTest):
    """Test: Verify safe pandas operations are not flagged"""
    
    def __init__(self):
        super().__init__(
            test_id="STATS_SAFE_001",
            test_name="Allow safe pandas operations",
            engine="stats",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        # Safe statistical code - should NOT be flagged
        code = """
import pandas as pd
import numpy as np

df = pd.DataFrame({"x": [1,2,3,4,5], "y": [2,4,6,8,10]})
mean_x = df["x"].mean()
std_y = df["y"].std()
correlation = df["x"].corr(df["y"])
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
                expected_result="SAFE - No security issues",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be safe
        passed = response.data.get("is_safe", False)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="SAFE - Standard pandas operations",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_DataFrame_Eval_Injection(),
    Test_Exec_In_Analysis(),
    Test_Safe_Pandas_Operations()
]
