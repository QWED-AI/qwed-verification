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

# Suspicious path entries in .pth files — directories an attacker would inject
# to hijack imports via sys.path manipulation (no exec/eval needed)
_SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"^/tmp\b"),
    re.compile(r"^/dev/shm\b"),
    re.compile(r"^/var/tmp\b"),
    re.compile(r"\.\./"),                         # relative path traversal
    re.compile(r"^~"),                            # home directory expansion
    re.compile(r"^https?://"),                    # URL-based path injection
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
    })

    def __init__(
        self,
        allowed_pth_files: Optional[Set[str]] = None,
        scan_contents: bool = True,
    ):
        """
        Args:
            allowed_pth_files: Additional .pth filenames to whitelist.
            scan_contents: When True, scans file contents for malicious
                patterns. Note: allowlisted files are always scanned for
                tampering regardless of this flag (fail-closed design).
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
        if getattr(site, "ENABLE_USER_SITE", False):
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

    def _scan_path_entries(self, filepath: str) -> List[str]:
        """Detect suspicious sys.path entries in allowlisted .pth files.

        In Python's site module, non-comment, non-import lines in .pth files
        are added to sys.path. An attacker can inject a path like /tmp/evil
        to hijack imports without using exec/eval.
        """
        findings: List[str] = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped.startswith("import "):
                        continue  # Handled by _scan_file_contents
                    # This is a path entry — check for suspicious locations
                    for pattern in _SUSPICIOUS_PATH_PATTERNS:
                        if pattern.search(stripped):
                            findings.append(
                                f"Suspicious path entry line {line_num}: "
                                f"'{stripped}' in {filepath}"
                            )
                            break
        except OSError:
            pass  # Read errors handled by _scan_file_contents
        return findings

    def _classify_file(
        self,
        filepath: str,
        is_allowlisted: bool,
        counts: Dict[str, int],
        content_findings: List[str],
    ) -> bool:
        """Classify a .pth file and return True if suspicious."""
        file_findings: List[str] = []

        # Always scan allowlisted files for tampering (fail-closed)
        if is_allowlisted or self.scan_contents:
            file_findings = self._scan_file_contents(filepath)
            content_findings.extend(file_findings)

        # For allowlisted files, also check for path injection
        if is_allowlisted:
            path_findings = self._scan_path_entries(filepath)
            if path_findings:
                content_findings.extend(path_findings)
                file_findings.extend(path_findings)

        # Classify the finding
        has_patterns = any("Suspicious pattern" in f for f in file_findings)
        has_path_inject = any("Suspicious path entry" in f for f in file_findings)
        has_read_error = any("Unable to read" in f for f in file_findings)

        if has_patterns or has_path_inject:
            counts["malicious"] += 1
            return True
        if has_read_error:
            counts["unreadable"] += 1
            return True
        if not is_allowlisted:
            counts["unauthorized"] += 1
            return True
        return False

    def _scan_directory(
        self,
        site_dir: str,
        suspicious_hooks: List[str],
        content_findings: List[str],
        scan_errors: List[str],
        counts: Dict[str, int],
    ) -> None:
        """Scan a single site-packages directory for suspicious .pth files."""
        try:
            entries = sorted(os.listdir(site_dir))
        except OSError as exc:
            scan_errors.append(
                f"Unable to list {site_dir} ({type(exc).__name__}: {exc})"
            )
            return

        for filename in entries:
            if not filename.endswith(".pth"):
                continue
            filepath = os.path.join(site_dir, filename)
            is_allowlisted = filename in self.allowed
            if self._classify_file(
                filepath, is_allowlisted, counts, content_findings
            ):
                suspicious_hooks.append(filepath)

    @staticmethod
    def _build_message(counts: Dict[str, int], scan_errors: List[str]) -> str:
        """Build an accurate summary message from structured classification."""
        total = sum(counts.values())
        parts: List[str] = []

        if counts.get("malicious"):
            parts.append(f"{counts['malicious']} with malicious patterns")
        if counts.get("unreadable"):
            parts.append(f"{counts['unreadable']} unreadable (possible tampering)")
        if counts.get("unauthorized"):
            parts.append(f"{counts['unauthorized']} unauthorized (not on allowlist)")
        if scan_errors:
            parts.append(f"{len(scan_errors)} directory scan failure(s)")

        detail = "; ".join(parts) if parts else "suspicious activity"

        if total == 0 and scan_errors:
            return (
                f"CRITICAL: {len(scan_errors)} directory scan failure(s) — "
                f"environment could not be fully verified. "
                f"Execution blocked as a precaution."
            )

        return (
            f"CRITICAL: Detected {total} suspicious Python "
            f"startup hook(s) — {detail}. "
            f"This is a known supply chain attack vector. Execution blocked."
        )

    def verify_environment_integrity(self) -> Dict[str, Any]:
        """
        Scan all site-packages directories for unauthorized .pth files.

        Returns:
            Dict with keys:
                - verified (bool): True if environment is clean.
                - status (str): "CLEAN_ENVIRONMENT" or "COMPROMISED".
                - suspicious_hooks (list): Paths to suspicious .pth files.
                - content_findings (list): Malicious patterns found.
                - scan_errors (list): Directory enumeration failures.
                - counts (dict): Per-category classification counts.
                - message (str): Human-readable summary.
        """
        suspicious_hooks: List[str] = []
        content_findings: List[str] = []
        scan_errors: List[str] = []
        scanned_dirs: List[str] = []
        counts: Dict[str, int] = {
            "malicious": 0,
            "unreadable": 0,
            "unauthorized": 0,
        }

        for site_dir in self._get_site_dirs():
            scanned_dirs.append(site_dir)
            self._scan_directory(
                site_dir, suspicious_hooks, content_findings,
                scan_errors, counts,
            )

        if suspicious_hooks or scan_errors:
            return {
                "verified": False,
                "status": "COMPROMISED",
                "risk": "COMPROMISED_ENVIRONMENT_STARTUP_HOOK",
                "message": self._build_message(counts, scan_errors),
                "suspicious_hooks": suspicious_hooks,
                "content_findings": content_findings,
                "scan_errors": scan_errors,
                "counts": counts,
                "scanned_directories": scanned_dirs,
            }

        return {
            "verified": True,
            "status": "CLEAN_ENVIRONMENT",
            "message": "No unauthorized startup hooks detected.",
            "suspicious_hooks": [],
            "content_findings": [],
            "scan_errors": [],
            "counts": counts,
            "scanned_directories": scanned_dirs,
        }
