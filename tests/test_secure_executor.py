"""
Test suite for SecureCodeExecutor.
Tests Docker isolation, resource limits, and security validation.
Note: Requires Docker to be running for these tests to pass.
"""

import pytest
import pandas as pd
from qwed_new.core.secure_code_executor import SecureCodeExecutor, ExecutionError


class TestSecureCodeExecutor:
    def setup_method(self):
        self.executor = SecureCodeExecutor()
    
    @pytest.mark.skipif(not SecureCodeExecutor().is_available(), reason="Docker not available")
    def test_safe_code_execution(self):
        """Test that safe code executes successfully."""
        code = """
result = 2 + 2
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert success
        assert error is None
        assert result == 4
    
    def test_dangerous_import_blocked(self):
        """Test that dangerous imports are blocked before execution."""
        code = """
import os
result = os.system('ls')
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert not success
        assert "security" in error.lower() or "dangerous" in error.lower()
    
    def test_eval_blocked(self):
        """Test that eval() is blocked."""
        code = """
result = eval('2+2')
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert not success
        assert "eval" in error.lower() or "dangerous" in error.lower()
    
    def test_exec_blocked(self):
        """Test that exec() is blocked."""
        code = """
exec('result = 5')
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert not success
    
    def test_subprocess_blocked(self):
        """Test that subprocess is blocked."""
        code = """
import subprocess
result = subprocess.run(['ls'], capture_output=True)
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert not success
    
    @pytest.mark.skipif(not SecureCodeExecutor().is_available(), reason="Docker not available")
    def test_timeout_enforced(self):
        """Test that execution times out after configured limit."""
        code = """
import time
time.sleep(20)  # Exceeds 10 second limit
result = 'done'
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert not success
        # Should timeout
        assert error is not None
    
    @pytest.mark.skipif(not SecureCodeExecutor().is_available(), reason="Docker not available")
    def test_dataframe_context_passed(self):
        """Test that DataFrame context is correctly passed."""
        code = """
import pandas as pd
# The DataFrame should be reconstructed from context
result = df['value'].sum()
"""
        df = pd.DataFrame({"value": [10, 20, 30]})
        context = {"df": df}
        
        success, error, result = self.executor.execute(code, context)
        assert success
        assert result == 60
    
    @pytest.mark.skipif(True, reason="Network test - requires Docker")
    def test_network_isolation(self):
        """Test that network access is blocked."""
        code = """
import urllib.request
result = urllib.request.urlopen('https://google.com').read()
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert not success
        # Should fail due to network isolation
    
    def test_is_available_check(self):
        """Test that Docker availability check works."""
        is_available = self.executor.is_available()
        assert isinstance(is_available, bool)
    
    def test_execution_counter(self):
        """Test that execution attempts are counted."""
        if not self.executor.is_available():
            pytest.skip("Docker not available")
        
        initial_count = self.executor.get_execution_count()
        code = "result = 1 + 1"
        self.executor.execute(code, {})
        assert self.executor.get_execution_count() > initial_count
    
    def test_file_operations_blocked(self):
        """Test that file operations are blocked."""
        code = """
with open('/etc/passwd', 'r') as f:
    result = f.read()
"""
        context = {}
        success, error, result = self.executor.execute(code, context)
        assert not success
        assert "open" in error.lower() or "file" in error.lower()
    
    @pytest.mark.skipif(not SecureCodeExecutor().is_available(), reason="Docker not available")
    def test_context_serialization(self):
        """Test that complex context is properly serialized."""
        code = """
result = data['numbers'][0] + data['numbers'][1]
"""
        context = {
            "data": {
                "numbers": [5, 10],
                "text": "hello"
            }
        }
        success, error, result = self.executor.execute(code, context)
        assert success
        assert result == 15


class TestSecureExecutorFallback:
    """Test behavior when Docker is not available."""
    
    def test_docker_unavailable_returns_error(self):
        """Test that unavailable Docker returns proper error."""
        # Create executor and force docker_available to False
        executor = SecureCodeExecutor()
        if executor.is_available():
            pytest.skip("Docker is available, cannot test fallback")
        
        code = "result = 2 + 2"
        success, error, result = executor.execute(code, {})
        assert not success
        assert "Docker" in error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
