"""
Environment Integrity Guard — Startup Hook Detection.

Defends against supply chain attacks that inject malicious .pth files
into Python site-packages directories (e.g., the LiteLLM/TeamPCP backdoor
that exfiltrated AWS credentials, SSH keys, and crypto wallets via
litellm_init.pth).

.pth files execute automatically on Python startup (before any application
code runs), making them an ideal persistence mechanism for attackers
(MITRE ATT&CK T1546.018).

This guard scans all site-packages directories for unauthorized .pth files
and inspects their contents for known malicious patterns.
"""

import os
import re
import site
from typing import Any, Dict, FrozenSet, List, Optional, Set


# Patterns that indicate malicious intent inside .pth files
_SUSPICIOUS_PATTERNS = [
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bbase64\b", re.IGNORECASE),
    re.compile(r"\bimport\s+socket\b"),
    re.compile(r"\bimport\s+subprocess\b"),
    re.compile(r"\bimport\s+urllib\b"),
    re.compile(r"\bimport\s+requests\b"),
    re.compile(r"\bimport\s+http\.client\b"),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bos\.popen\s*\("),
    re.compile(r"\b__import__\s*\("),
    re.compile(r"\bcompile\s*\(.*exec", re.IGNORECASE),
    re.compile(r"\\x[0-9a-fA-F]{2}"),            # hex-encoded bytes
    re.compile(r"\bcryptowallet|\.aws/credentials", re.IGNORECASE),
]


class StartupHookGuard:
    """
    Deterministic environment integrity verification.

    Scans Python site-packages for unauthorized .pth startup hooks
    that could execute malicious code before application startup.

    Usage:
        guard = StartupHookGuard()
        result = guard.verify_environment_integrity()
        if not result["verified"]:
            print("BLOCKED:", result["message"])
    """

    # Known safe .pth files shipped with standard Python tooling
    DEFAULT_ALLOWED: FrozenSet[str] = frozenset({
        "distutils-precedence.pth",
        "setuptools.pth",
        "easy-install.pth",
        "pip.pth",
        "virtualenv.pth",
        "_virtualenv.pth",
        "hatchling.pth",
        "coverage.pth",
        "pytest.pth",
        "site-packages.pth",
        "README.txt",
    })

    def __init__(
        self,
        allowed_pth_files: Optional[Set[str]] = None,
        scan_contents: bool = True,
    ):
        """
        Args:
            allowed_pth_files: Additional .pth filenames to whitelist.
            scan_contents: If True, also scans file contents for malicious patterns.
        """
        self.allowed = set(self.DEFAULT_ALLOWED)
        if allowed_pth_files:
            self.allowed |= allowed_pth_files
        self.scan_contents = scan_contents

    def _get_site_dirs(self) -> List[str]:
        """Return all site-packages directories to scan (sorted for determinism)."""
        dirs: List[str] = []
        try:
            dirs.extend(site.getsitepackages())
        except AttributeError:
            pass  # Some embedded interpreters lack this
        user_site = getattr(site, "getusersitepackages", lambda: None)()
        if user_site:
            dirs.append(user_site)
        return sorted(d for d in dirs if os.path.isdir(d))

    def _scan_file_contents(self, filepath: str) -> List[str]:
        """Scan a .pth file for suspicious code patterns."""
        findings: List[str] = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for pattern in _SUSPICIOUS_PATTERNS:
                if pattern.search(content):
                    findings.append(
                        f"Suspicious pattern '{pattern.pattern}' in {filepath}"
                    )
        except OSError as exc:
            findings.append(
                f"Unable to read {filepath} ({type(exc).__name__}: {exc})"
            )
        return findings

    def _scan_directory(
        self,
        site_dir: str,
        suspicious_hooks: List[str],
        content_findings: List[str],
    ) -> None:
        """Scan a single site-packages directory for suspicious .pth files."""
        try:
            entries = sorted(os.listdir(site_dir))
        except OSError:
            return

        for filename in entries:
            if not filename.endswith(".pth"):
                continue

            filepath = os.path.join(site_dir, filename)
            is_allowlisted = filename in self.allowed

            # Always scan allowlisted files for tampering;
            # scan non-allowlisted files only when scan_contents is enabled
            file_findings: List[str] = []
            if is_allowlisted or self.scan_contents:
                file_findings = self._scan_file_contents(filepath)
                content_findings.extend(file_findings)

            # Flag if: not allowlisted, OR allowlisted but tampered
            if not is_allowlisted or file_findings:
                suspicious_hooks.append(filepath)

    def verify_environment_integrity(self) -> Dict[str, Any]:
        """
        Scan all site-packages directories for unauthorized .pth files.

        Returns:
            Dict with keys:
                - verified (bool): True if environment is clean.
                - status (str): "CLEAN_ENVIRONMENT" or "COMPROMISED".
                - suspicious_hooks (list): Paths to suspicious .pth files.
                - content_findings (list): Malicious patterns found.
                - message (str): Human-readable summary.
        """
        suspicious_hooks: List[str] = []
        content_findings: List[str] = []
        scanned_dirs: List[str] = []

        for site_dir in self._get_site_dirs():
            scanned_dirs.append(site_dir)
            self._scan_directory(site_dir, suspicious_hooks, content_findings)

        if not suspicious_hooks:
            return {
                "verified": True,
                "status": "CLEAN_ENVIRONMENT",
                "message": "No unauthorized startup hooks detected.",
                "suspicious_hooks": [],
                "content_findings": [],
                "scanned_directories": scanned_dirs,
            }

        # Build accurate message based on evidence
        if content_findings:
            detail = "with malicious patterns detected"
        else:
            detail = "not on the verified allowlist"

        return {
            "verified": False,
            "status": "COMPROMISED",
            "risk": "COMPROMISED_ENVIRONMENT_STARTUP_HOOK",
            "message": (
                f"CRITICAL: Detected {len(suspicious_hooks)} suspicious Python "
                f"startup hook(s) (.pth files) {detail}. "
                f"This is a known supply chain attack vector. Execution blocked."
            ),
            "suspicious_hooks": suspicious_hooks,
            "content_findings": content_findings,
            "scanned_directories": scanned_dirs,
        }
