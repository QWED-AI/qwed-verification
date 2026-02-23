import re

class SovereigntyGuard:
    """
    Enforces Data Residency and Sovereignty.
    Source: Alignment with privacy-sensitive legal deployments [Source 60, 61].
    """
    def __init__(self, required_local_providers=None):
        if required_local_providers is None:
            required_local_providers = ["ollama", "vllm_local"]
        self.local_providers = list(required_local_providers)
        self._local_providers_casefold = {p.casefold() for p in self.local_providers}
        
        # Regex for SSN variants and Confidentiality markers
        self.sensitive_patterns = [
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),      # SSN: dash-separated
            re.compile(r"\b\d{3}\s\d{2}\s\d{4}\b"),     # SSN: space-separated
            re.compile(r"\b\d{9}\b"),                    # SSN: contiguous (use with care — broad)
            re.compile(r"CONFIDENTIAL", re.IGNORECASE),
        ]

    def verify_routing(self, prompt: str, target_provider: str) -> dict:
        if not prompt:
            raise ValueError("prompt must be a non-empty string.")
        if not target_provider:
            raise ValueError("target_provider must be a non-empty string.")

        # ISSUE: Does this prompt contain sensitive data destined for an external provider?
        is_sensitive = any(p.search(prompt) for p in self.sensitive_patterns)
        
        # RULE: Sensitive data must never be routed to non-local infrastructure.
        # [Source: MSLR, data residency compliance]
        
        # APPLICATION: Evaluate whether target_provider is an approved local provider.
        if is_sensitive and target_provider.casefold() not in self._local_providers_casefold:
            # CONCLUSION: Violation — block routing.
            return {
                "verified": False,
                "risk": "DATA_SOVEREIGNTY_VIOLATION",
                "message": f"Sensitive data detected. Routing to external provider '{target_provider}' is blocked. Must use local infrastructure."
            }
            
        # CONCLUSION: No violation detected — permit routing.
        return {"verified": True, "risk": None, "message": "Routing permitted."}
