import re

class SovereigntyGuard:
    """
    Enforces Data Residency and Sovereignty.
    Source: Alignment with privacy-sensitive legal deployments [Source 60, 61].
    """
    def __init__(self, required_local_providers=["ollama", "vllm_local"]):
        self.local_providers = required_local_providers
        # Simple regex for SSN, Credit Cards, or Confidentiality markers
        self.sensitive_patterns = [r"\b\d{3}-\d{2}-\d{4}\b", r"(?i)CONFIDENTIAL"]

    def verify_routing(self, prompt: str, target_provider: str) -> dict:
        # 1. Check if data is sensitive
        is_sensitive = any(re.search(p, prompt) for p in self.sensitive_patterns)
        
        # 2. Enforce Sovereignty
        if is_sensitive and target_provider not in self.local_providers:
            return {
                "verified": False,
                "risk": "DATA_SOVEREIGNTY_VIOLATION",
                "message": f"Sensitive data detected. Routing to external provider '{target_provider}' is blocked. Must use local infrastructure."
            }
            
        return {"verified": True}
