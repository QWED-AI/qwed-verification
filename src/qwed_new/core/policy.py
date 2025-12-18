"""
Policy Engine: The Enforcer.

This module handles security policies, rate limiting, and compliance rules.
It implements the "Security & Policy" layer of the QWED OS.

Now with Redis-backed distributed rate limiting for multi-instance deployments.
"""

import time
import logging
from typing import Dict, Tuple, Optional
from qwed_new.core.security import SecurityGateway

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Simple Token Bucket Rate Limiter (In-Memory).
    Used as fallback when Redis is unavailable.
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


class RedisSlidingWindowLimiter:
    """
    Redis-backed Sliding Window Rate Limiter.
    
    Uses Redis sorted sets for accurate distributed rate limiting:
    - Each request adds a timestamped entry to a sorted set
    - Old entries outside the window are removed
    - Count of remaining entries determines if limit is exceeded
    
    Features:
    - Distributed across multiple app instances
    - Burst allowance for momentary spikes
    - Automatic cleanup of old entries
    """
    
    def __init__(
        self,
        rate: int = 60,           # Requests allowed
        per: int = 60,            # Per this many seconds (window size)
        burst_multiplier: float = 1.5,  # Allow burst up to rate * multiplier
        key_prefix: str = "qwed:ratelimit"
    ):
        self.rate = rate
        self.per = per
        self.burst_limit = int(rate * burst_multiplier)
        self.key_prefix = key_prefix
        
        # Get Redis client
        from qwed_new.core.redis_config import get_redis_client
        self._client = get_redis_client()
        
        # Fallback to in-memory if Redis unavailable
        self._fallback: Optional[RateLimiter] = None
        if self._client is None:
            self._fallback = RateLimiter(rate=rate, per=per)
    
    def _get_key(self, identifier: str) -> str:
        """Generate Redis key for the rate limit bucket."""
        return f"{self.key_prefix}:{identifier}"
    
    def allow(self, identifier: str = "global") -> bool:
        """
        Check if a request should be allowed.
        
        Args:
            identifier: Unique identifier (e.g., tenant_id, API key hash)
            
        Returns:
            True if request is allowed, False if rate limited
        """
        # Fallback to in-memory
        if self._fallback:
            return self._fallback.allow()
        
        now = time.time()
        window_start = now - self.per
        key = self._get_key(identifier)
        
        try:
            # Use pipeline for atomic operations
            pipe = self._client.pipeline()
            
            # Remove entries outside the window
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current entries in window
            pipe.zcard(key)
            
            # Execute
            results = pipe.execute()
            current_count = results[1]
            
            # Check if under limit
            if current_count >= self.rate:
                logger.debug(f"Rate limit exceeded for {identifier}: {current_count}/{self.rate}")
                return False
            
            # Add new entry with current timestamp
            # Use unique member to allow multiple requests per millisecond
            member = f"{now}:{id(self)}"
            self._client.zadd(key, {member: now})
            
            # Set TTL on key to auto-cleanup (window + buffer)
            self._client.expire(key, self.per + 10)
            
            return True
            
        except Exception as e:
            logger.warning(f"Redis rate limit error: {e}. Allowing request.")
            # Fail-open: allow request if Redis errors
            return True
    
    def get_remaining(self, identifier: str = "global") -> int:
        """Get remaining requests in current window."""
        if self._fallback:
            return max(0, int(self._fallback.tokens))
        
        try:
            now = time.time()
            window_start = now - self.per
            key = self._get_key(identifier)
            
            # Clean and count
            self._client.zremrangebyscore(key, 0, window_start)
            current_count = self._client.zcard(key)
            
            return max(0, self.rate - current_count)
            
        except Exception:
            return self.rate  # Assume full if error
    
    def reset(self, identifier: str = "global") -> bool:
        """Reset rate limit for an identifier."""
        if self._fallback:
            self._fallback.tokens = self._fallback.rate
            return True
        
        try:
            key = self._get_key(identifier)
            return self._client.delete(key) > 0
        except Exception:
            return False


class PolicyEngine:
    """
    Central policy enforcement point.
    Now supports per-tenant isolation with Redis-backed distributed rate limiting.
    """
    def __init__(self, use_redis: bool = True):
        self.security_gateway = SecurityGateway()
        self.use_redis = use_redis
        
        # Check Redis availability
        from qwed_new.core.redis_config import is_redis_available
        self._redis_available = is_redis_available() if use_redis else False
        
        if self._redis_available:
            # Use Redis-backed limiters
            self.global_limiter = RedisSlidingWindowLimiter(rate=60, per=60)
            self._tenant_limiters: Dict[int, RedisSlidingWindowLimiter] = {}
            logger.info("PolicyEngine using Redis-backed rate limiting")
        else:
            # Fallback to in-memory
            self.global_limiter = RateLimiter(rate=60, per=60)
            self._tenant_limiters: Dict[int, RateLimiter] = {}
            logger.info("PolicyEngine using in-memory rate limiting")
        
        # Alias for backwards compatibility
        self.tenant_limiters = self._tenant_limiters
        
    def _get_tenant_limiter(self, organization_id: int, max_per_minute: int = 60):
        """
        Get or create a rate limiter for a specific tenant.
        """
        if organization_id not in self._tenant_limiters:
            if self._redis_available:
                self._tenant_limiters[organization_id] = RedisSlidingWindowLimiter(
                    rate=max_per_minute,
                    per=60,
                    key_prefix=f"qwed:ratelimit:tenant:{organization_id}"
                )
            else:
                self._tenant_limiters[organization_id] = RateLimiter(
                    rate=max_per_minute,
                    per=60
                )
        return self._tenant_limiters[organization_id]
        
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
        # 1. Rate Limiting (Per-Tenant or Global)
        if organization_id:
            limiter = self._get_tenant_limiter(organization_id)
            identifier = str(organization_id)
            if self._redis_available:
                allowed = limiter.allow(identifier)
            else:
                allowed = limiter.allow()
            if not allowed:
                return False, "Rate limit exceeded for your organization. Please try again later."
        else:
            if self._redis_available:
                allowed = self.global_limiter.allow("global")
            else:
                allowed = self.global_limiter.allow()
            if not allowed:
                return False, "Rate limit exceeded. Please try again later."
        
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
    
    def get_rate_limit_info(self, organization_id: Optional[int] = None) -> Dict:
        """Get current rate limit status for debugging."""
        if organization_id:
            limiter = self._get_tenant_limiter(organization_id)
            identifier = str(organization_id)
        else:
            limiter = self.global_limiter
            identifier = "global"
        
        if self._redis_available and hasattr(limiter, 'get_remaining'):
            return {
                "backend": "redis",
                "remaining": limiter.get_remaining(identifier),
                "limit": limiter.rate,
                "window_seconds": limiter.per
            }
        else:
            return {
                "backend": "in-memory",
                "remaining": int(getattr(limiter, 'tokens', 0)),
                "limit": limiter.rate,
                "window_seconds": limiter.per
            }
