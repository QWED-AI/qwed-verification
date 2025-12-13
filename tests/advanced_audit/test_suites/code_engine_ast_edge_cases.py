"""
Code Engine Test Suite - AST Edge Cases
Tests for dynamic imports, reflection, and format string injection
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_Dynamic_Import_UserInput(BaseTest):
    """Test 2A: Dynamic Import with user input"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_AST_001",
            test_name="Detect __import__() with user input",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
module_name = input("Module to import: ")
imported = __import__(module_name)
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
            expected_result="CRITICAL - Dynamic import RCE",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Getattr_Reflection(BaseTest):
    """Test 2B: Reflection-based code execution"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_AST_002",
            test_name="Detect getattr() with user input",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
class MyAPI:
    def safe_method(self):
        return "Safe"
    
    def dangerous_method(self):
        import os
        os.system("rm -rf /")

method_name = input("Method to call: ")
api = MyAPI()
getattr(api, method_name)()
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
            expected_result="CRITICAL - Reflection allows arbitrary method execution",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_FormatString_WithEval(BaseTest):
    """Test 2C: Format string injection with eval"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_AST_003",
            test_name="Detect format string + eval RCE",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
user_input = input("Name: ")
eval(f"print('Hello {user_input}')")
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
            expected_result="CRITICAL - eval with f-string allows code injection",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_Exec_WithUserInput(BaseTest):
    """Test 2D: exec() with user input"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_AST_004",
            test_name="Detect exec() with user input",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
code_to_run = input("Enter Python code: ")
exec(code_to_run)
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
            expected_result="CRITICAL - exec() allows arbitrary code execution",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_Dynamic_Import_UserInput(),
    Test_Getattr_Reflection(),
    Test_FormatString_WithEval(),
    Test_Exec_WithUserInput()
]
