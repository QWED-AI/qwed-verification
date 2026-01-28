"""
ConfigGuard: Deterministic Secrets Scanner.
Detects plaintext secrets in configuration data.
"""
import re
from typing import Dict, Any, List, Optional

class ConfigGuard:
    """
    Deterministic guard for configuration security.
    Scans for plaintext secrets and credentials.
    """
    
    # Regex patterns for common secret types
    DEFAULT_SECRET_PATTERNS = {
        "OPENAI_API_KEY": r"sk-[a-zA-Z0-9]{20,}",
        "ANTHROPIC_API_KEY": r"sk-ant-[a-zA-Z0-9-]+",
        "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
        "AWS_SECRET_KEY": r"[a-zA-Z0-9/+=]{40}",  # Needs context
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
                # Check string against all patterns
                for secret_type, pattern in self.compiled_patterns.items():
                    if pattern.search(data):
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
        
        for secret_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
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
