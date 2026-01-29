import re
from typing import Dict, Any, List

class PIIGuard:
    """
    Local-first PII and Secret detection using regex heuristics.
    Lightweight, offline-capable scanner for sensitive data.
    """
    
    def __init__(self):
        # Pre-compiled regex patterns for performance
        self.patterns = {
            "openai_api_key": re.compile(r"sk-(proj-)?[\w-]{20,}"),
            "anthropic_api_key": re.compile(r"sk-ant-[\w-]{20,}"),
            "aws_access_key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            "ssh_private_key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
            # Identifying common password declarations (heuristic)
            "password_assignment": re.compile(r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"]?(\S{6,})['\"]?"),
            # Generic high-entropy strings usually associated with secrets (checking later if needed)
            
            # Additional PII
            "phone_number": re.compile(r"(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}"),
        }

    def scan(self, content: str) -> Dict[str, Any]:
        """
        Scans the provided content for secrets and PII.
        Returns a dictionary with detection results.
        """
        detected_types = []
        violations = []
        
        for name, pattern in self.patterns.items():
            matches = pattern.findall(content)
            if matches:
                # Special handling for password heuristic
                if name == "password_assignment":
                    valid_matches = [m for m in matches if len(m[1]) > 5]
                    if not valid_matches:
                        continue
                        
                # Special handling for public emails
                if name == "email":
                    public_prefixes = ('support@', 'contact@', 'info@', 'sales@', 'help@', 'hello@', 'marketing@', 'jobs@', 'careers@')
                    matches = [m for m in matches if not m.lower().startswith(public_prefixes)]
                    if not matches:
                        continue

                detected_types.append(name)
                # Redact content for safe logging
                for m in matches:
                    snippet = str(m)[:10] + "..." 
                    violations.append(f"Potential {name} detected: {snippet}")

        if detected_types:
            return {
                "verified": False,
                "risk": "PII_LEAK",
                "types": detected_types,
                "violations": violations,
                "message": f"Secrets detected: {', '.join(detected_types)}"
            }
        
        return {
            "verified": True,
            "scan_method": "REGEX_HEURISTICS",
            "message": "No obvious secrets found."
        }
