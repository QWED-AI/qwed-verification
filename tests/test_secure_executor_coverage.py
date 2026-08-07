
import unittest
import docker
from unittest.mock import MagicMock, patch
from src.qwed_new.core.secure_code_executor import (
    SECURE_RUNTIME_UNAVAILABLE,
    SecureCodeExecutor,
    ExecutionError,
    _find_dangerous_pattern,
    _find_dangerous_pattern_fallback,
)

class TestDangerousPatternScanner(unittest.TestCase):
    """AST-aware dangerous-pattern scanner: only executable operations count."""

    def test_blocks_real_dangerous_operations(self):
        for code, expected in [
            ("eval(x)", "eval"),
            ("exec(c)", "exec"),
            ("compile(x)", "compile"),
            ("with open(1): pass", "open"),
            ("import os\nos.system('ls')", "os"),
            ("import subprocess\nsubprocess.run(x)", "subprocess"),
            ("import requests\nrequests.get(u)", "requests"),
            ("builtins.__import__('os')", "__import__"),
            ("os.name", "os.name"),
            ("import os.path\nprint(os.path.join('a', 'b'))", "os.path"),
            ("from urllib.request import urlopen", "urllib.request"),
        ]:
            with self.subTest(code=code):
                self.assertIsNotNone(_find_dangerous_pattern(code), code)
                self.assertIn(expected, _find_dangerous_pattern(code) or "")

    def test_allows_keywords_in_comments_docstrings_and_strings(self):
        for code in [
            "# naughty http here\nprint(1)",
            'print("http://example.com")',
            '"""Fetches over https and prints os.environ for debugging."""\nprint(1)',
            "x = 'eval is not called'",
            "# import os would be bad\nprint(1)",
        ]:
            with self.subTest(code=code):
                self.assertIsNone(_find_dangerous_pattern(code), code)

    def test_allows_safe_code(self):
        for code in [
            "x = 2 + 2",
            "print(1)",
            "result = data['numbers'][0]",
            "def f(a, b):\n    return a + b",
            "import pandas as pd\nresult = df['value'].sum()",
        ]:
            with self.subTest(code=code):
                self.assertIsNone(_find_dangerous_pattern(code), code)

    def test_fallback_scanner_strips_comments_and_strings(self):
        # Comment/string mentions must not trigger; executable use still does.
        self.assertIsNone(_find_dangerous_pattern_fallback("# http only in comment\nprint(1)"))
        self.assertIsNone(_find_dangerous_pattern_fallback('print("http://x.com")'))
        self.assertIsNotNone(_find_dangerous_pattern_fallback("import os\nos.name"))

    def test_syntax_error_falls_back_closed(self):
        # Unparseable code still scans executable tokens conservatively.
        self.assertIsNotNone(_find_dangerous_pattern("os.system('ls' (broken"))
        self.assertIsNone(_find_dangerous_pattern("# just a comment, no newline"))
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

            safety = executor._is_safe_code("print('hello')")
            self.assertTrue(safety.is_fail_closed)
            self.assertEqual(
                safety.developer_fields.get("constraint_id"),
                "secure_code_executor.verifier_unavailable",
            )
            self.assertEqual(safety.status.value, "UNVERIFIABLE")

    def test_execute_fails_closed_when_code_verifier_missing(self):
        """Execution must not proceed when CodeVerifier cannot be imported."""
        with patch.dict("sys.modules", {"qwed_new.core.code_verifier": None}):
            executor = SecureCodeExecutor()
            executor.client = MagicMock()
            executor.client.ping.return_value = None

            success, error, result = executor.execute("print('hello')", {})

            self.assertFalse(success)
            self.assertIn("Code safety validation failed", error)
            self.assertIn("Code safety verification unavailable", error)
            self.assertIsNone(result)
            executor.client.containers.run.assert_not_called()

    def test_execute_import_error_never_authorizes_execution(self):
        """The heuristic fallback is advisory only and must never authorize execution."""
        with patch.dict("sys.modules", {"qwed_new.core.code_verifier": None}):
            executor = SecureCodeExecutor()
            executor.client = MagicMock()
            executor.client.ping.return_value = None

            success, error, result = executor.execute("import os; result = os.name", {})

            self.assertFalse(success)
            self.assertIn("Code safety verification unavailable", error)
            self.assertIsNone(result)
            executor.client.containers.run.assert_not_called()

            safety = executor._is_safe_code("import os; result = os.name")
            advisory = safety.advisory_checks[0]
            self.assertTrue(advisory.advisory_only)
            self.assertFalse(advisory.details["is_safe"])

    def test_code_verifier_runtime_failure_fails_closed(self):
        """Runtime failures inside CodeVerifier must block execution deterministically."""
        executor = SecureCodeExecutor()
        with patch("qwed_new.core.code_verifier.CodeVerifier.verify_code", side_effect=RuntimeError("engine down")):
            safety = executor._is_safe_code("print('hello')")

        self.assertTrue(safety.is_fail_closed)
        self.assertIn("Code safety verification unavailable", safety.agent_message)

if __name__ == '__main__':
    unittest.main()
