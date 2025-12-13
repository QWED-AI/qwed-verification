"""
Code Engine Test Suite - Context-Aware Detection
Tests for tracking tainted data across function boundaries
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_UserInput_FlowThrough_Functions(BaseTest):
    """Test 1A: User Input Flow Through Function Boundaries"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_CTX_001",
            test_name="Track user input through function boundaries",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
def get_user_input():
    return input("Enter path: ")

def sanitize(data):
    # Pretends to sanitize but doesn't
    return data

def process_file(path):
    import subprocess
    subprocess.run(["ls", path])

# The flow
user_path = get_user_input()
clean_path = sanitize(user_path)
process_file(clean_path)
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
                expected_result="CRITICAL - subprocess with user input",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should detect subprocess with user-controlled argument
        passed = self._check_result("CRITICAL", response.data)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - Command injection via tainted input",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Variable_Aliasing(BaseTest):
    """Test 1B: Variable Aliasing Detection"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_CTX_002",
            test_name="Detect taint through variable aliasing",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
user_data = input("Enter command: ")
safe_looking_var = user_data
another_name = safe_looking_var
totally_safe = another_name
import subprocess
subprocess.run(["sh", "-c", totally_safe])
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
            expected_result="CRITICAL - shell=True with tainted input",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Open_WithHardcodedPath(BaseTest):
    """Test 1C: Safe open() with hardcoded path"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_CTX_003",
            test_name="Safe open() with hardcoded path",
            engine="code",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
with open("config.json", "r") as f:
    data = f.read()
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
                expected_result="SAFE",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be SAFE - hardcoded path
        passed = self._check_result("SAFE", response.data)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="SAFE - Hardcoded path is safe",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Open_WithVariablePath(BaseTest):
    """Test 1D: open() with variable path (needs review)"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_CTX_004",
            test_name="open() with variable path",
            engine="code",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
filename = get_config_path()  # Variable, not user input
with open(filename, "r") as f:
    data = f.read()
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
                expected_result="WARNING or REQUIRES_REVIEW",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be WARNING - needs manual review
        passed = (self._check_result("WARNING", response.data) or 
                 self._check_result("REQUIRES_REVIEW", response.data))
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="WARNING - Variable path needs review",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_UserInput_FlowThrough_Functions(),
    Test_Variable_Aliasing(),
    Test_Open_WithHardcodedPath(),
    Test_Open_WithVariablePath()
]
