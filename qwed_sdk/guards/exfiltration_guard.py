"""
ExfiltrationGuard: Runtime Data Exfiltration Protection.

Prevents compromised agents from sending sensitive data (PII, credentials,
internal documents) to unauthorized endpoints. Acts as a runtime control
policy layer between the agent's tool calls and external APIs.

Addresses the "if the agent does get tricked" scenario — even if an MCP
tool or prompt injection succeeds, the data cannot leave your infrastructure.
"""
import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# --- Audit Constants ---
AUDIT_ISSUE = "irac.issue"
AUDIT_RULE = "irac.rule"
AUDIT_APP = "irac.application"
AUDIT_CONCL = "irac.conclusion"


# --- PII Detection Patterns ---

_PII_PATTERNS: Dict[str, re.Pattern] = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    # Credit card: contiguous digits only — formatted numbers are
    # caught by normalising the payload in _scan_payload_for_pii
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"           # Visa
        r"5[1-5][0-9]{14}|"                         # MasterCard
        r"3[47][0-9]{13}|"                          # Amex
        r"6(?:011|5[0-9]{2})[0-9]{12})\b"           # Discover
    ),
    "EMAIL": re.compile(
        # [A-Za-z]{2,} — no pipe inside char class
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "PHONE_US": re.compile(
        r"\b(?:\+1\s?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}\b"
    ),
    # PASSPORT: opt-in only — too broad by default (matches version strings etc.)
    # Enable via pii_checks=[..., 'PASSPORT'] in ExfiltrationGuard.__init__
    "PASSPORT": re.compile(
        # Refactored for ReDoS safety: avoid overlapping quantifiers.
        # Requires at least one separator char ([:\s]) before the number.
        r"\bpassport(?:[\s#]+(?:no|number|#))?[:\s]+[a-z]{1,2}\d{6,9}\b",
        re.IGNORECASE,
    ),
    # (?:[A-Z0-9]{1}){0,16} avoids matching the empty string
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{1}){0,16}\b"),
    # AKIA = long-term, ASIA = temporary/session credentials
    "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[A-Z\d]{16}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    # \- is a literal hyphen; use - at end of class. a-z covers A-Z with IGNORECASE.
    "JWT": re.compile(r"\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+\b", re.IGNORECASE),
    "BEARER_TOKEN": re.compile(r"Bearer\s+[a-z0-9_.-]{20,}", re.IGNORECASE),
}

_DEFAULT_PII_CHECKS = frozenset(k for k in _PII_PATTERNS if k != "PASSPORT")


class ExfiltrationGuard:
    """
    Deterministic guard for runtime data exfiltration prevention.

    Verifies outbound agent API calls against:
    1. An endpoint allowlist (blocks calls to unauthorized destinations)
    2. A PII scanner (blocks payloads containing sensitive data)

    Example::

        guard = ExfiltrationGuard(
            allowed_endpoints=["https://api.openai.com", "https://api.anthropic.com"]
        )
        result = guard.verify_outbound_call(
            destination_url="https://evil-server.com/collect",
            payload="User SSN: 123-45-6789"
        )
        # result["verified"] == False, result["risk"] == "DATA_EXFILTRATION"
    """

    def __init__(
        self,
        allowed_endpoints: Optional[List[str]] = None,
        pii_checks: Optional[List[str]] = None,
        custom_pii_patterns: Optional[Dict[str, str]] = None,
    ):
        """
        Args:
            allowed_endpoints: URL prefixes or hostnames that agents are
                permitted to call. Pass an **explicit empty list** ``[]``
                to block all outbound calls. If ``None`` (default), a safe
                set of well-known AI API endpoints is used.
            pii_checks: Subset of PII type names to enable. Defaults to all
                built-in types except ``PASSPORT`` (opt-in).
            custom_pii_patterns: Additional ``{name: regex_string}`` patterns.
        """
        # Distinguish None (use defaults) from [] (block all)
        if allowed_endpoints is not None:
            self.allowed_endpoints: List[str] = allowed_endpoints
        else:
            self.allowed_endpoints = [
                "https://api.openai.com",
                "https://api.anthropic.com",
                "https://generativelanguage.googleapis.com",
                "http://localhost",
                "http://127.0.0.1",
            ]

        # Build active PII patterns
        if pii_checks is not None:
            active_pii = {k: v for k, v in _PII_PATTERNS.items() if k in pii_checks}
        else:
            active_pii = {k: v for k, v in _PII_PATTERNS.items() if k in _DEFAULT_PII_CHECKS}
        if custom_pii_patterns:
            for name, pattern_str in custom_pii_patterns.items():
                active_pii[name] = re.compile(pattern_str)
        self._pii_patterns = active_pii

    def _is_allowed_endpoint(self, url: str) -> bool:
        """Check if URL matches any allowed endpoint prefix or hostname."""
        url_clean = url.strip()
        url_lower = url_clean.lower()
        try:
            _parsed_url = urlparse(url_clean)
            parsed_host = _parsed_url.hostname or ""
            url_scheme = _parsed_url.scheme
        except ValueError:
            return False

        for allowed in self.allowed_endpoints:
            if self._matches_allowed_entry(url_lower, parsed_host, url_scheme, allowed):
                return True
        return False

    def _matches_allowed_entry(
        self, url_lower: str, parsed_host: str, url_scheme: str, allowed: str
    ) -> bool:
        """
        Check if URL matches one specific allowlist entry.

        Refactored to reduce complexity of _is_allowed_endpoint.
        """
        allowed_lower = allowed.lower()
        # Prefix match — require path boundary to prevent
        # 'https://api.openai.com.evil.com' bypassing the allowlist
        if url_lower.startswith(allowed_lower):
            rest = url_lower[len(allowed_lower) :]
            if not rest or rest[0] in ("/", "?", "#", ":"):
                return True

        # Hostname-only / exact match
        try:
            _allowed_parsed = urlparse(allowed)
            allowed_host = _allowed_parsed.hostname or allowed_lower
            allowed_scheme = _allowed_parsed.scheme
        except ValueError:
            allowed_host = allowed_lower
            allowed_scheme = ""

        # Exact match only — no implicit subdomain matching.
        # Require scheme compatibility if the allowlist entry specifies one.
        if parsed_host == allowed_host:
            if allowed_scheme:
                if url_scheme == allowed_scheme:
                    return True
            elif url_scheme in ("http", "https"):
                # Schemeless allowlist entry: default to safe web protocols only
                return True
        return False

    def verify_outbound_call(
        self,
        destination_url: str,
        payload: str = "",
        method: str = "POST",
    ) -> Dict[str, Any]:
        """
        Verify an outbound API call before execution.

        Args:
            destination_url: The full URL the agent is attempting to call.
            payload: The request body / payload (string or JSON-encoded).
            method: HTTP method (for logging). Default: ``"POST"``.

        Returns:
            Dict with ``verified`` bool plus IRAC audit fields.
        """
        _rule_endpoint = "Destination URL must appear in the configured endpoint allowlist."
        _rule_pii = "Outbound payloads must not contain unmasked PII or secrets."

        if not destination_url:
            return {
                "verified": False,
                "risk": "EMPTY_DESTINATION",
                "message": "Outbound call has no destination URL.",
                AUDIT_ISSUE: "EMPTY_DESTINATION",
                AUDIT_RULE: "Outbound calls must have a non-empty destination URL.",
                AUDIT_APP: "Destination URL is empty or None.",
                AUDIT_CONCL: "Blocked: invalid destination.",
            }

        # 1. Endpoint allowlist check
        if not self._is_allowed_endpoint(destination_url):
            verdict = {
                "verified": False,
                "risk": "DATA_EXFILTRATION",
                "destination": destination_url,
                "message": (
                    f"Agent attempted to send data to unauthorized endpoint: "
                    f"{destination_url}. Call blocked by ExfiltrationGuard."
                ),
                AUDIT_ISSUE: "DATA_EXFILTRATION",
                AUDIT_RULE: _rule_endpoint,
                AUDIT_APP: f"'{destination_url}' is not in the allowlist.",
                AUDIT_CONCL: "Blocked: unauthorized destination.",
            }
            logger.warning(
                "ExfiltrationGuard blocked outbound call",
                extra={"risk": "DATA_EXFILTRATION", "destination": destination_url, "method": method},
            )
            return verdict

        # 2. PII scan on payload
        if payload:
            pii_hits = self._scan_payload_for_pii(payload)
            if pii_hits:
                pii_types = ", ".join(hit["type"] for hit in pii_hits)
                verdict = {
                    "verified": False,
                    "risk": "PII_LEAK",
                    "destination": destination_url,
                    "pii_detected": pii_hits,
                    "message": (
                        f"Blocked: Payload destined for '{destination_url}' "
                        f"contains unmasked PII: {pii_types}. "
                        "Mask or redact before sending."
                    ),
                    AUDIT_ISSUE: "PII_LEAK",
                    AUDIT_RULE: _rule_pii,
                    AUDIT_APP: f"Detected PII types in payload: {pii_types}.",
                    AUDIT_CONCL: "Blocked: payload contains sensitive data.",
                }
                logger.warning(
                    "ExfiltrationGuard blocked PII in payload",
                    extra={
                        "risk": "PII_LEAK",
                        "destination": destination_url,
                        "method": method,
                        "pii_detected": [h["type"] for h in pii_hits],
                    },
                )
                return verdict

        return {
            "verified": True,
            "destination": destination_url,
            "method": method,
            "message": f"Outbound {method} to '{destination_url}' approved.",
            AUDIT_ISSUE: "OK",
            AUDIT_RULE: f"{_rule_endpoint} AND {_rule_pii}",
            AUDIT_APP: f"Destination verified AND payload is clean for '{destination_url}'.",
            AUDIT_CONCL: "Verified: call is compliant.",
        }

    def _scan_payload_for_pii(self, payload: str) -> List[Dict[str, Any]]:
        """Scan payload string for PII matches. Returns list of findings."""
        findings: List[Dict[str, Any]] = []
        # Normalise: also scan a copy with spaces/hyphens removed to
        # catch formatted card numbers like "4111 1111 1111 1111"
        normalised = re.sub(r"[\s\-]", "", payload)

        for pii_type, pattern in self._pii_patterns.items():
            text_to_scan = normalised if pii_type == "CREDIT_CARD" else payload
            matches = pattern.findall(text_to_scan)
            if matches:
                findings.append({
                    "type": pii_type,
                    "count": len(matches),
                    "message": f"Found {len(matches)} instance(s) of {pii_type}.",
                })
        return findings

    def scan_payload(self, payload: str) -> Dict[str, Any]:
        """
        Standalone PII scan without endpoint check.

        Useful for scanning LLM outputs before storing or forwarding them.

        Args:
            payload: String content to scan.

        Returns:
            Dict with ``verified`` bool plus IRAC audit fields.
        """
        _rule = "Payloads must not contain unmasked PII or secrets."
        findings = self._scan_payload_for_pii(payload)
        if findings:
            pii_types = ", ".join(f["type"] for f in findings)
            return {
                "verified": False,
                "risk": "PII_DETECTED",
                "pii_detected": findings,
                "message": f"Payload contains unmasked PII: {pii_types}.",
                AUDIT_ISSUE: "PII_DETECTED",
                AUDIT_RULE: _rule,
                AUDIT_APP: f"Scan detected {len(findings)} PII type(s): {pii_types}.",
                AUDIT_CONCL: "Violates: PII detected in content.",
            }
        return {
            "verified": True,
            "message": "No PII detected in payload.",
            AUDIT_ISSUE: "OK",
            AUDIT_RULE: _rule,
            AUDIT_APP: "PII scan returned zero matches.",
            AUDIT_CONCL: "Compliant: content is clean.",
        }
