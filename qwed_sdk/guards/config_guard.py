"""
ConfigGuard: Deterministic Secrets Scanner.
Detects plaintext secrets in configuration data.
"""
import re
from itertools import pairwise
from typing import Dict, Any, Iterator, List, Optional, Tuple

from qwed_new.guards.canonical_text import json_readings, reading_copies
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
# GitHub Action, a digest named by its algorithm, an integrity hash, a line
# of "=" and an alphabet written out. A match is dropped only when the whole
# run of base64 characters around it is one of these shapes, read exactly;
# every other run keeps all the matches the pattern finds. A 40-character hex
# value is kept anywhere else: some services issue tokens of that shape.
# The same characters as the pattern, with its flags, so a run holds every
# match the pattern finds.
_BASE64_RUN = re.compile(r"[a-z0-9/+=]{40,}", re.IGNORECASE)
_HEX = re.compile(r"[0-9a-fA-F]+")
_HEX_DIGEST_LENGTHS = {"sha1:": 40, "sha256:": 64, "sha384:": 96, "sha512:": 128}
# Base64 of a 32-, 48- or 64-byte digest, with the padding it has.
_SRI_DIGESTS = {
    "sha256-": re.compile(r"[A-Za-z0-9+/]{43}="),
    "sha384-": re.compile(r"[A-Za-z0-9+/]{64}"),
    "sha512-": re.compile(r"[A-Za-z0-9+/]{86}=="),
}
# An integrity value: "integrity": "sha512-..." (npm), integrity="sha384-..."
# (HTML) or integrity: sha256-... (YAML, and a JSON key with its value), the
# hash first in the value. ASCII only, so no other script's letter (a dotless
# i) reads as the key's.
_INTEGRITY_BEFORE = re.compile(r"integrity[\"']?[ \t]*[:=][ \t]*[\"']?\Z", re.IGNORECASE | re.ASCII)
# A step that pins an action or a reusable workflow to a commit, alone on its
# line apart from quotes and a comment, which YAML starts after whitespace.
_PINNED_ACTION_LINE = re.compile(
    r"[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*(['\"]?)"
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]*)?@([0-9a-fA-F]{40})\1"
    r"(?:[ \t]+#[^\n]*)?[ \t]*\r?"
)
# The keys whose name makes a value public by its shape. In a parsed tree the
# built-in AWS secret key pattern reads a value under one of them with its
# key, as in the file.
_SHAPE_KEYS = ("uses", "integrity")


def _continues_name(text: str, begin: int) -> bool:
    """Whether the character before *begin* continues a name, so a label or
    key at *begin* is part of a longer name (my_sha1:, notintegrity,
    data-integrity, an accented letter before sha1:): an ASCII letter or
    digit, "_", "-", or any character outside ASCII, a letter or mark of
    another script among them."""
    if begin <= 0:
        return False
    char = text[begin - 1]
    return not char.isascii() or char.isalnum() or char in "_-"


def _labelled(text: str, start: int, labels) -> Optional[str]:
    """The label from *labels*, written in ASCII, that ends at *start* and
    does not continue a longer name, or None."""
    for label in labels:
        begin = start - len(label)
        written = text[max(0, begin):start]
        if written.isascii() and written.lower() == label and not _continues_name(text, begin):
            return label
    return None


def _hex_digest(text: str, start: int, value: str) -> bool:
    """Whether *value* is a hex digest of its algorithm's exact length, after
    that algorithm's label (sha256:...)."""
    label = _labelled(text, start, _HEX_DIGEST_LENGTHS)
    return label is not None and len(value) == _HEX_DIGEST_LENGTHS[label] and _HEX.fullmatch(value) is not None


def _integrity_hash(text: str, start: int, value: str) -> bool:
    """Whether *value* is a whole integrity hash of its exact length, the
    value of an integrity key or attribute (integrity="sha384-...")."""
    label = _labelled(text, start, _SRI_DIGESTS)
    if label is None:
        return False
    label_start = start - len(label)
    key = _INTEGRITY_BEFORE.search(text, max(0, label_start - 40), label_start)
    if key is None or _continues_name(text, key.start()):
        return False
    return _SRI_DIGESTS[label].fullmatch(value) is not None


class _PinnedCommits:
    """Which runs of *text* are the commit of a pinned step, asked for runs
    in order: one cursor walks the line ends, and each line is read once
    however many candidates it holds."""

    def __init__(self, text: str):
        self.text = text
        self.newlines: Optional[List[int]] = None
        self.cursor = 0
        self.line_read = -1
        self.commit_at = -1

    def pinned(self, start: int, value: str) -> bool:
        """Whether the run *value* at *start* is the commit of a pinned step."""
        if len(value) != 40 or self.text[start - 1:start] != "@" or not _HEX.fullmatch(value):
            return False
        line_start, line_end = self._line(start)
        if line_start != self.line_read:
            line = _PINNED_ACTION_LINE.fullmatch(self.text, line_start, line_end)
            self.line_read, self.commit_at = line_start, (line.start(2) if line else -1)
        return self.commit_at == start

    def _line(self, start: int) -> Tuple[int, int]:
        """The start and end of the line *start* is on."""
        if self.newlines is None:
            self.newlines = [found.start() for found in re.finditer("\n", self.text)]
        newlines = self.newlines
        while self.cursor < len(newlines) and newlines[self.cursor] < start:
            self.cursor += 1
        line_start = newlines[self.cursor - 1] + 1 if self.cursor else 0
        line_end = newlines[self.cursor] if self.cursor < len(newlines) else len(self.text)
        return line_start, line_end


class _PublicShapes:
    """The default AWS_SECRET_KEY *pattern*, without its matches in a run of
    base64 characters that is public by its shape. ``search``, ``finditer``
    and ``findall`` give the pattern's own matches, in order, minus those."""

    def __init__(self, pattern: "re.Pattern[str]"):
        self.pattern = pattern

    def finditer(self, text: str) -> Iterator["re.Match[str]"]:
        pinned = _PinnedCommits(text)
        for run in _BASE64_RUN.finditer(text):
            start, end = run.span()
            value = run.group(0)
            if not self._public(text, start, value, pinned):
                yield from self.pattern.finditer(text, start, end)

    @staticmethod
    def _public(text: str, start: int, value: str, pinned: _PinnedCommits) -> bool:
        if not value.isascii():
            return False
        return (
            # A rule: nothing but "=", which no key is made of.
            value.count("=") == len(value)
            # An alphabet or another listing in strictly ascending order.
            or all(a < b for a, b in pairwise(value))
            or pinned.pinned(start, value)
            or _hex_digest(text, start, value)
            or _integrity_hash(text, start, value)
        )

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
        # A pattern the caller gives, even the default one, is searched as
        # written.
        if "AWS_SECRET_KEY" not in (custom_patterns or {}):
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
        
        def scan(data: Any, current_path: str, name: Any = None):
            if isinstance(data, dict):
                for key, value in data.items():
                    new_path = f"{current_path}.{key}" if current_path else key
                    scan(value, new_path, key)
            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    scan(item, f"{current_path}[{idx}]")
            elif isinstance(data, str):
                for secret_type in self._types_in_value(data, name):
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
    
    def _types_in_value(self, value: str, name: Any) -> List[str]:
        """The secret types found in a string *value* under the key *name*,
        as written and as a reader sees it (GHSA-v3m4). The built-in AWS
        secret key pattern reads a value under "uses" or "integrity" with its
        key, as "uses: value", so a pinned step or an integrity hash keeps the
        name that makes it public; every other pattern, a caller's among
        them, reads the value alone, and no other key is read."""
        alone = reading_copies(value)
        keyed = reading_copies(f"{name}: {value}") if name in _SHAPE_KEYS else alone
        return [
            secret_type
            for secret_type, pattern in self.compiled_patterns.items()
            if any(pattern.search(copy) for copy in self._readings_for(pattern, alone, keyed))
        ]

    @staticmethod
    def _readings_for(pattern: Any, alone: Tuple[str, ...], keyed: Tuple[str, ...]) -> Tuple[str, ...]:
        """*keyed* for the built-in AWS secret key pattern, which reads a value
        with its key; *alone* for every other pattern."""
        return keyed if isinstance(pattern, _PublicShapes) else alone

    def scan_string(self, text: str) -> Dict[str, Any]:
        """
        Scan a raw string for secrets (e.g., log output, API response).
        
        Returns:
            {"verified": True/False, "secrets_found": [...]}
        """
        secrets_found = []
        # The text as written and as a reader sees it, and the strings of
        # JSON, which may write characters as escapes (GHSA-v3m4): one per
        # line for every pattern, and each string value on its key's line
        # for the built-in AWS secret key pattern.
        alone = keyed = reading_copies(text)
        decoded = json_readings(text)
        if decoded is not None:
            alone = tuple(dict.fromkeys(alone + reading_copies(decoded[0])))
            keyed = tuple(dict.fromkeys(keyed + reading_copies(decoded[1])))
        
        for secret_type, pattern in self.compiled_patterns.items():
            # The copy with the most matches: as written, or as a reader
            # sees it (GHSA-v3m4).
            copies = self._readings_for(pattern, alone, keyed)
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
