"""
Policy Engine: The Enforcer.

This module handles security policies, rate limiting, and compliance rules.
It implements the "Security & Policy" layer of the QWED OS.
"""

import time
from typing import Dict, Tuple, Optional
from qwed_new.core.security import SecurityGateway

class RateLimiter:
    """
    Simple Token Bucket Rate Limiter (In-Memory).
    """
    def __init__(self, rate: int = 60, per: int = 60):
        self.rate = rate
        self.per = per
        self.tokens = rate
        self.last_update = time.time()
        
    def allow(self) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        
        # Refill tokens
        self.tokens += elapsed * (self.rate / self.per)
        if self.tokens > self.rate:
            self.tokens = self.rate
        self.last_update = now
        
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

class PolicyEngine:
    """
    Central policy enforcement point.
    Now supports per-tenant isolation.
    """
    def __init__(self):
        self.security_gateway = SecurityGateway()
        # Per-tenant rate limiters (keyed by organization_id)
        self.tenant_limiters: Dict[int, RateLimiter] = {}
        
    def _get_tenant_limiter(self, organization_id: int, max_per_minute: int = 60) -> RateLimiter:
        """
        Get or create a rate limiter for a specific tenant.
        """
        if organization_id not in self.tenant_limiters:
            self.tenant_limiters[organization_id] = RateLimiter(rate=max_per_minute, per=60)
        return self.tenant_limiters[organization_id]
        
    def check_policy(
        self, 
        query: str, 
        organization_id: Optional[int] = None,
        context: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if the request complies with all policies.
        Returns (allowed, reason).
        """
        # 1. Rate Limiting (Per-Tenant)
        if organization_id:
            limiter = self._get_tenant_limiter(organization_id)
            if not limiter.allow():
                return False, "Rate limit exceeded for your organization. Please try again later."
        
        # 2. Security / Prompt Injection
        is_safe, reason = self.security_gateway.detect_injection(query)
        if not is_safe:
            return False, f"Security Policy Violation: {reason}"
            
        # 3. PII Check (Informational for now, redaction happens later)
        # We could block PII here if strict mode is enabled
        
        return True, None

    def sanitize_output(self, text: str) -> str:
        """
        Enforce data leakage policy (Redact PII).
        """
        return self.security_gateway.redact_pii(text)
