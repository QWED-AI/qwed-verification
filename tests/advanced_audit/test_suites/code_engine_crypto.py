"""
Code Engine Test Suite - Cryptography Misuse
Tests for weak hashing, hardcoded keys, and crypto vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_test import BaseTest, TestResult


class Test_MD5_ForPasswords(BaseTest):
    """Test 3A: MD5 used for password hashing"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_CRYPTO_001",
            test_name="Detect MD5 for password hashing",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
import hashlib

password = input("Password: ")
hashed = hashlib.md5(password.encode()).hexdigest()
store_in_database(hashed)
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
        
        # MD5 for passwords should be CRITICAL
        passed = self._check_result("CRITICAL", response.data)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL - MD5 is cryptographically broken for passwords",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_HardcodedEncryptionKey(BaseTest):
    """Test 3B: Hardcoded encryption key"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_CRYPTO_002",
            test_name="Detect hardcoded encryption keys",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
from cryptography.fernet import Fernet

# Hardcoded key
key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
cipher = Fernet(key)

message = "secret data"
encrypted = cipher.encrypt(message.encode())
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
            expected_result="CRITICAL - Hardcoded encryption key",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


class Test_SHA256_WithoutSalt(BaseTest):
    """Test 3C: SHA-256 without salt for passwords"""
    
    def __init__(self):
        super().__init__(
            test_id="CODE_CRYPTO_003",
            test_name="Detect SHA-256 without salt",
            engine="code",
            priority="HIGH"
        )
    
    def execute(self, api_client) -> TestResult:
        code = '''
import hashlib

password = input("Password: ")
hashed = hashlib.sha256(password.encode()).hexdigest()
store_in_database(hashed)
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
                expected_result="WARNING or CRITICAL",
                actual_result={},
                error=response.error,
                latency_ms=response.latency_ms
            )
        
        # Should be WARNING or CRITICAL - no salt/key stretching
        passed = (self._check_result("WARNING", response.data) or 
                 self._check_result("CRITICAL", response.data))
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="WARNING - SHA-256 needs salt and key stretching",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )


# Export tests
AVAILABLE_TESTS = [
    Test_MD5_ForPasswords(),
    Test_HardcodedEncryptionKey(),
    Test_SHA256_WithoutSalt()
]
