"""
ConfigGuard: Deterministic Secrets Scanner.
Detects plaintext secrets in configuration data.
"""
import bisect
import re
from typing import Dict, Any, Iterator, List, Optional

from qwed_new.guards.canonical_text import decoded_json, reading_copies
from qwed_new.guards.run_search import RunSearch

# Default patterns re would retry at every position of a long run, in
# quadratic time: searched without repeating a failed attempt along the run
# (GHSA-v3m4). Each starts with a run character ([MN], eyJ) and needs a
# "." after the run, which the run cannot hold.
_RUN_SEARCHES = {
    "DISCORD_TOKEN": (r"[MN]", r"[A-Za-z\d]*"),
    "JWT_TOKEN": (r"eyJ", r"[a-zA-Z0-9_-]*"),
}

# The AWS secret key pattern takes any 40 base64 characters, so it also
# matched values that are public by their shape: the commit of a pinned
# GitHub Action, a digest named by its algorithm, an npm integrity hash, a
# line of "=" and an alphabet written out. A match is dropped only when the
# whole run of base64 characters around it is one of these shapes, read
# exactly; every other run keeps all the matches the pattern finds. A
# 40-character hex value is kept anywhere else: some services issue tokens of
# that shape.
_BASE64_RUN = re.compile(r"[a-zA-Z0-9/+=]{40,}", re.IGNORECASE)
_HEX = re.compile(r"[0-9a-fA-F]+")
_HEX_DIGEST_LENGTHS = {"sha1:": 40, "sha256:": 64, "sha384:": 96, "sha512:": 128}
# Base64 of a 32-, 48- or 64-byte digest, with the padding it has.
_SRI_DIGESTS = {
    "sha256-": re.compile(r"[A-Za-z0-9+/]{43}="),
    "sha384-": re.compile(r"[A-Za-z0-9+/]{64}"),
    "sha512-": re.compile(r"[A-Za-z0-9+/]{86}=="),
}
# An integrity value: "integrity": "sha512-..." (npm) or integrity="sha384-..."
# (HTML), the hash first in the value.
_INTEGRITY_BEFORE = re.compile(r"integrity[\"']?[ \t]*[:=][ \t]*[\"']?\Z", re.IGNORECASE)
# A step that pins an action or a reusable workflow to a commit, alone on its
# line apart from quotes and a comment.
_PINNED_ACTION_LINE = re.compile(
    r"[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*(['\"]?)"
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]*@([0-9a-fA-F]{40})\1[ \t]*(?:#[^\n]*)?\r?"
)


def _labelled(text: str, start: int, labels) -> Optional[str]:
    """The label from *labels* that ends at *start* and does not continue a
    word, or None."""
    for label in labels:
        begin = start - len(label)
        if begin >= 0 and text[begin:start].lower() == label and (begin == 0 or not text[begin - 1].isalnum()):
            return label
    return None


class _PublicShapes:
    """The default AWS_SECRET_KEY *pattern*, without its matches in a run of
    base64 characters that is public by its shape. ``search``, ``finditer``
    and ``findall`` give the pattern's own matches, in order, minus those."""

    def __init__(self, pattern: "re.Pattern[str]"):
        self.pattern = pattern

    def finditer(self, text: str) -> Iterator["re.Match[str]"]:
        newlines: Optional[List[int]] = None
        # The commit each line pins, by the line's start: each line is read
        # once, however many candidates it holds.
        pinned: Dict[int, int] = {}
        for run in _BASE64_RUN.finditer(text):
            start, end = run.span()
            value = run.group(0)
            if value.isascii() and len(value) == 40 and text[start - 1:start] == "@" and _HEX.fullmatch(value):
                if newlines is None:
                    newlines = [found.start() for found in re.finditer("\n", text)]
                if self._pinned_commit(text, start, newlines, pinned) == start:
                    continue
            if self._public(text, start, value):
                continue
            yield from self.pattern.finditer(text, start, end)

    @staticmethod
    def _pinned_commit(text: str, start: int, newlines: List[int], pinned: Dict[int, int]) -> int:
        """Where the commit starts on the line around *start*, if the line
        pins an action to one; otherwise -1."""
        at = bisect.bisect_left(newlines, start)
        line_start = newlines[at - 1] + 1 if at else 0
        if line_start not in pinned:
            line_end = newlines[at] if at < len(newlines) else len(text)
            line = _PINNED_ACTION_LINE.fullmatch(text, line_start, line_end)
            pinned[line_start] = line.start(2) if line else -1
        return pinned[line_start]

    @staticmethod
    def _public(text: str, start: int, value: str) -> bool:
        if not value.isascii():
            return False
        # Padding and rules: fewer than 40 characters that are not "=".
        if len(value) - value.count("=") < 40:
            return True
        # An alphabet or another listing in strictly ascending order.
        if all(a < b for a, b in zip(value, value[1:])):
            return True
        label = _labelled(text, start, _HEX_DIGEST_LENGTHS)
        if label and len(value) == _HEX_DIGEST_LENGTHS[label] and _HEX.fullmatch(value):
            return True
        label = _labelled(text, start, _SRI_DIGESTS)
        if label and _INTEGRITY_BEFORE.search(text[max(0, start - len(label) - 40):start - len(label)]):
            return _SRI_DIGESTS[label].fullmatch(value) is not None
        return False

    def search(self, text: str) -> Optional["re.Match[str]"]:
        return next(self.finditer(text), None)

    def findall(self, text: str) -> List[str]:
        return [found.group(0) for found in self.finditer(text)]


class ConfigGuard:
    """
    Deterministic guard for configuration security.
    Scans for plaintext secrets and credentials.
    """
    
    # Regex patterns for common secret types
    DEFAULT_SECRET_PATTERNS = {
        # Project, service-account and admin keys (sk-proj-, sk-svcacct-,
        # sk-admin-) contain "-" and "_"; legacy keys are plain alphanumerics.
        # sk-ant- (Anthropic) matches neither branch.
        "OPENAI_API_KEY": r"sk-(?:(?:proj|svcacct|admin)-[a-zA-Z0-9_-]{20,}|[a-zA-Z0-9]{20,})",
        "ANTHROPIC_API_KEY": r"sk-ant-[a-zA-Z0-9-]+",
        "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
        # Any 40 base64 characters; public shapes are read out (_PublicShapes).
        "AWS_SECRET_KEY": r"[a-zA-Z0-9/+=]{40}",
        "GITHUB_TOKEN": r"gh[pousr]_[a-zA-Z0-9]{36,}",
        "PRIVATE_KEY_PEM": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "PRIVATE_KEY_END": r"-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "JWT_TOKEN": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "GOOGLE_API_KEY": r"AIza[0-9A-Za-z_-]{35}",
        "STRIPE_API_KEY": r"sk_live_[a-zA-Z0-9]{24,}",
        "STRIPE_RESTRICTED_KEY": r"rk_live_[a-zA-Z0-9]{24,}",
        "SLACK_TOKEN": r"xox[baprs]-[0-9a-zA-Z-]+",
        "DISCORD_TOKEN": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        "DATABASE_URL": r"(postgres|mysql|mongodb)://[^:]+:[^@]+@",
        "BASIC_AUTH": r"Basic [A-Za-z0-9+/=]{10,}",
        "BEARER_TOKEN": r"Bearer [a-zA-Z0-9_.-]{20,}",
    }
    
    def __init__(
        self,
        custom_patterns: Optional[Dict[str, str]] = None,
        sensitivity: str = "high"
    ):
        """
        Args:
            custom_patterns: Additional regex patterns to check.
            sensitivity: "high" (strict) or "low" (only obvious secrets).
        """
        self.patterns = {**self.DEFAULT_SECRET_PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        
        self.sensitivity = sensitivity
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.patterns.items()
        }
        for name, (start, run) in _RUN_SEARCHES.items():
            if self.patterns.get(name) == self.DEFAULT_SECRET_PATTERNS[name]:
                self.compiled_patterns[name] = RunSearch(self.compiled_patterns[name], start, run)
        if self.patterns.get("AWS_SECRET_KEY") == self.DEFAULT_SECRET_PATTERNS["AWS_SECRET_KEY"]:
            self.compiled_patterns["AWS_SECRET_KEY"] = _PublicShapes(self.compiled_patterns["AWS_SECRET_KEY"])
    
    def verify_config_safety(
        self, 
        config_data: Any, 
        path: str = ""
    ) -> Dict[str, Any]:
        """
        Recursively scan configuration data for plaintext secrets.
        
        Args:
            config_data: Dict, list, or string to scan.
            path: Current path in the config tree (for error reporting).
        
        Returns:
            {"verified": True/False, "violations": [...]}
        """
        violations = []
        
        def scan(data: Any, current_path: str):
            if isinstance(data, dict):
                for key, value in data.items():
                    new_path = f"{current_path}.{key}" if current_path else key
                    scan(value, new_path)
            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    scan(item, f"{current_path}[{idx}]")
            elif isinstance(data, str):
                # Check the string, as written and as a reader sees it
                # (GHSA-v3m4), against all patterns
                copies = reading_copies(data)
                for secret_type, pattern in self.compiled_patterns.items():
                    if any(pattern.search(copy) for copy in copies):
                        violations.append({
                            "type": secret_type,
                            "path": current_path,
                            "message": f"Possible {secret_type} detected at '{current_path}'."
                        })
        
        scan(config_data, path)
        
        if violations:
            return {
                "verified": False,
                "risk": "PLAINTEXT_SECRET",
                "violations": violations,
                "message": f"Found {len(violations)} potential secret(s) in configuration."
            }
        
        return {"verified": True, "message": "No secrets detected in configuration."}
    
    def scan_string(self, text: str) -> Dict[str, Any]:
        """
        Scan a raw string for secrets (e.g., log output, API response).
        
        Returns:
            {"verified": True/False, "secrets_found": [...]}
        """
        secrets_found = []
        # The text as written and as a reader sees it, and the strings of
        # JSON, which may write characters as escapes (GHSA-v3m4).
        copies = reading_copies(text)
        decoded = decoded_json(text)
        if decoded is not None:
            copies = tuple(dict.fromkeys(copies + reading_copies(decoded)))
        
        for secret_type, pattern in self.compiled_patterns.items():
            # The copy with the most matches: as written, or as a reader
            # sees it (GHSA-v3m4).
            matches = max((pattern.findall(copy) for copy in copies), key=len)
            if matches:
                secrets_found.append({
                    "type": secret_type,
                    "count": len(matches),
                    "message": f"Found {len(matches)} instance(s) of {secret_type}."
                })
        
        if secrets_found:
            return {
                "verified": False,
                "risk": "SECRET_EXPOSURE",
                "secrets_found": secrets_found,
                "message": f"Detected {len(secrets_found)} secret type(s) in text."
            }
        
        return {"verified": True, "message": "No secrets detected."}
