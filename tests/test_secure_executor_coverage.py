
import unittest
import docker
from unittest.mock import MagicMock, patch
from src.qwed_new.core.secure_code_executor import (
    SECURE_RUNTIME_UNAVAILABLE,
    SecureCodeExecutor,
    ExecutionError,
)

class TestSecureExecutorCoverage(unittest.TestCase):
    """Targeted tests to improve coverage of secure_code_executor.py"""

    def test_init_docker_failure(self):
        """Test initialization when Docker client fails."""
        with patch("docker.from_env", side_effect=Exception("Docker down")):
            executor = SecureCodeExecutor()
            self.assertFalse(executor.docker_available)

    def test_execute_docker_unavailable(self):
        """Test execute when Docker is not available."""
        with patch("docker.from_env", side_effect=Exception("Docker down")):
            executor = SecureCodeExecutor()
            success, error, _ = executor.execute("print(1)", {})
            self.assertFalse(success)
            self.assertEqual(SECURE_RUNTIME_UNAVAILABLE, error)

    def test_is_available_rechecks_docker_health(self):
        """Test live Docker health check instead of relying on cached startup state."""
        executor = SecureCodeExecutor()
        executor.docker_available = True
        executor.client = MagicMock()
        executor.client.ping.side_effect = Exception("Docker daemon unavailable")

        self.assertFalse(executor.is_available())
        self.assertTrue(executor.docker_available)

    def test_is_available_recovers_after_transient_ping_failure(self):
        """Test Docker availability check recovers once ping succeeds again."""
        executor = SecureCodeExecutor()
        executor.docker_available = True
        executor.client = MagicMock()
        executor.client.ping.side_effect = [Exception("Temporary Docker issue"), None]

        self.assertFalse(executor.is_available())
        self.assertTrue(executor.is_available())

    def test_execute_os_error_tempdir(self):
        """Test execute when tempfile creation fails."""
        with patch("tempfile.TemporaryDirectory", side_effect=OSError("Disk full")):
            executor = SecureCodeExecutor()
            # Force docker available even if mock fails real init (though we mocked class)
            executor.docker_available = True 
            executor.client = MagicMock()
            
            success, error, _ = executor.execute("print(1)", {})
            self.assertFalse(success)
            self.assertIn("Setup error", error)

    def test_execute_image_not_found(self):
        """Test execute when Docker image is missing."""
        executor = SecureCodeExecutor()
        executor.docker_available = True
        executor.client = MagicMock()
        # Mock container run to raise ImageNotFound
        executor.client.containers.run.side_effect = docker.errors.ImageNotFound("Missing image")
        
        # We need to bypass the tempdir context manager for the run call to happen
        # or just let it run normally since we only mock the docker call
        success, error, _ = executor.execute("print(1)", {})
        self.assertFalse(success)
        self.assertIn("not found", error)

    def test_execute_container_error(self):
        """Test execute when container crashes."""
        executor = SecureCodeExecutor()
        executor.docker_available = True
        executor.client = MagicMock()
        executor.client.containers.run.side_effect = docker.errors.ContainerError(
            "container", 1, "cmd", "image", b"stderr"
        )
        
        success, error, _ = executor.execute("print(1)", {})
        self.assertFalse(success)
        self.assertIn("Container execution failed", error)

    def test_execute_generic_exception(self):
        """Test execute when unexpected error occurs."""
        executor = SecureCodeExecutor()
        executor.docker_available = True
        executor.client = MagicMock()
        executor.client.containers.run.side_effect = Exception("Chaos")
        
        success, error, _ = executor.execute("print(1)", {})
        self.assertFalse(success)
        self.assertIn("Execution error", error)
        

    def test_container_timeout_kill_fails(self):
        """Test timeout where container kill also fails."""
        executor = SecureCodeExecutor()
        executor.docker_available = True
        executor.client = MagicMock()
        
        mock_container = MagicMock()
        # wait raises generic exception (interpreted as timeout/error)
        mock_container.wait.side_effect = Exception("Timeout")
        # kill raises exception
        mock_container.kill.side_effect = Exception("Zombie container")
        
        executor.client.containers.run.return_value = mock_container
        
        # Should raise ExecutionError but also catch kill exception
        with self.assertRaises(ExecutionError):
            executor._run_in_container("/tmp", "exec_1")

    def test_code_verifier_import_error_fails_closed(self):
        """CodeVerifier import failures must block execution safety checks."""
        with patch.dict("sys.modules", {"qwed_new.core.code_verifier": None}):
            executor = SecureCodeExecutor()

            is_safe, reason = executor._is_safe_code("print('hello')")
            self.assertFalse(is_safe)
            self.assertIn("CodeVerifier unavailable", reason)

    def test_execute_fails_closed_when_code_verifier_missing(self):
        """Execution must not proceed when CodeVerifier cannot be imported."""
        with patch.dict("sys.modules", {"qwed_new.core.code_verifier": None}):
            executor = SecureCodeExecutor()
            executor.client = MagicMock()
            executor.client.ping.return_value = None

            success, error, result = executor.execute("print('hello')", {})

            self.assertFalse(success)
            self.assertIn("Code safety validation failed", error)
            self.assertIn("CodeVerifier unavailable", error)
            self.assertIsNone(result)
            executor.client.containers.run.assert_not_called()

    def test_execute_import_error_returns_advisory_reason_without_authorizing(self):
        """Heuristic fallback may inform the error but must never authorize execution."""
        with patch.dict("sys.modules", {"qwed_new.core.code_verifier": None}):
            executor = SecureCodeExecutor()
            executor.client = MagicMock()
            executor.client.ping.return_value = None

            success, error, result = executor.execute("import os; result = os.name", {})

            self.assertFalse(success)
            self.assertIn("CodeVerifier unavailable", error)
            self.assertIn("Advisory-only fallback also flagged", error)
            self.assertIn("dangerous operation", error)
            self.assertIsNone(result)
            executor.client.containers.run.assert_not_called()

    def test_code_verifier_runtime_failure_fails_closed(self):
        """Runtime failures inside CodeVerifier must block execution deterministically."""
        executor = SecureCodeExecutor()
        with patch("qwed_new.core.code_verifier.CodeVerifier.verify_code", side_effect=RuntimeError("engine down")):
            is_safe, reason = executor._is_safe_code("print('hello')")

        self.assertFalse(is_safe)
        self.assertIn("CodeVerifier unavailable", reason)

if __name__ == '__main__':
    unittest.main()
