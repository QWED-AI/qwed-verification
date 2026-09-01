"""
Rate limiting for QWED API endpoints.

Implements:
- Per-API-key rate limits
- Global endpoint rate limits
- Returns 429 Too Many Requests when exceeded
"""

from typing import Dict, Optional
from collections import defaultdict
from fastapi import HTTPException
import time
import os
import threading

class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window algorithm.
    
    For production with multiple servers, consider using Redis instead.
    
    Environment Variables:
        QWED_RATE_LIMIT_PER_KEY: Requests per minute per API key (default: 100)
        QWED_RATE_LIMIT_GLOBAL: Requests per minute globally (default: 1000)
        QWED_RATE_LIMIT_PER_IP: Requests per minute per client IP on
            anonymous /auth/* routes (default: 10) — these routes have no
            API key to key a bucket on, so without a per-IP bucket they are
            an unthrottled bcrypt/DoS surface (issues #226, #334).
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Per-API-key request timestamps: {api_key: [timestamp1, timestamp2, ...]}
        self.api_key_requests: Dict[str, list] = defaultdict(list)

        # Per-client-IP request timestamps for anonymous auth routes:
        # {ip: [timestamp1, timestamp2, ...]}
        self.ip_requests: Dict[str, list] = defaultdict(list)

        # Global request timestamps: [timestamp1, timestamp2, ...]
        self.global_requests: list = []

        # Rate limit configurations - configurable via env vars
        self.PER_KEY_LIMIT = int(os.environ.get("QWED_RATE_LIMIT_PER_KEY", "100"))
        self.PER_KEY_WINDOW = 60  # seconds

        self.GLOBAL_LIMIT = int(os.environ.get("QWED_RATE_LIMIT_GLOBAL", "1000"))
        self.GLOBAL_WINDOW = 60  # seconds

        self.PER_IP_LIMIT = int(os.environ.get("QWED_RATE_LIMIT_PER_IP", "10"))
        self.PER_IP_WINDOW = 60  # seconds

        # Bound the per-IP table: floods from spoofed/varied IPs must not
        # grow memory unboundedly. Above the cap, drop IPs whose windows
        # have fully expired.
        self.MAX_TRACKED_IPS = 50_000
    
    def _clean_old_requests(self, requests: list, window_seconds: int) -> list:
        """Remove timestamps older than the window."""
        cutoff = time.time() - window_seconds
        return [ts for ts in requests if ts > cutoff]
    
    def check_api_key_limit(self, api_key: str) -> bool:
        """
        Check if API key has exceeded its rate limit.
        
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self._lock:
            # Clean old requests
            self.api_key_requests[api_key] = self._clean_old_requests(
                self.api_key_requests[api_key], 
                self.PER_KEY_WINDOW
            )
            
            # Check limit
            if len(self.api_key_requests[api_key]) >= self.PER_KEY_LIMIT:
                return False
            
            # Record this request
            self.api_key_requests[api_key].append(time.time())
            return True
    
    def check_global_limit(self) -> bool:
        """
        Check if global endpoint has exceeded its rate limit.
        
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self._lock:
            # Clean old requests
            self.global_requests = self._clean_old_requests(
                self.global_requests, 
                self.GLOBAL_WINDOW
            )
            
            # Check limit
            if len(self.global_requests) >= self.GLOBAL_LIMIT:
                return False
            
            # Record this request
            self.global_requests.append(time.time())
            return True
    
    def check_ip_limit(self, client_ip: str) -> bool:
        """
        Check if a client IP has exceeded the anonymous-route rate limit.

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self._lock:
            if len(self.ip_requests) > self.MAX_TRACKED_IPS:
                cutoff = time.time() - self.PER_IP_WINDOW
                self.ip_requests = defaultdict(
                    list,
                    {
                        ip: stamps
                        for ip, stamps in self.ip_requests.items()
                        if stamps and stamps[-1] > cutoff
                    },
                )

            self.ip_requests[client_ip] = self._clean_old_requests(
                self.ip_requests[client_ip],
                self.PER_IP_WINDOW,
            )

            if len(self.ip_requests[client_ip]) >= self.PER_IP_LIMIT:
                return False

            self.ip_requests[client_ip].append(time.time())
            return True

    def get_ip_reset_time(self, client_ip: str) -> int:
        """Seconds until this IP's auth-route window resets."""
        with self._lock:
            requests = list(self.ip_requests.get(client_ip, []))
            if not requests:
                return 0
            oldest = min(requests)
            return max(0, int(oldest + self.PER_IP_WINDOW - time.time()))

    def get_reset_time(self, api_key: Optional[str] = None) -> int:
        """
        Get seconds until rate limit resets.
        
        Args:
            api_key: If provided, get per-key reset time. Otherwise, global reset time.
        
        Returns:
            Seconds until oldest request expires from the window
        """
        with self._lock:
            if api_key:
                # Copy list to prevent mutation during calculation
                requests = list(self.api_key_requests.get(api_key, []))
                window = self.PER_KEY_WINDOW
            else:
                requests = list(self.global_requests)
                window = self.GLOBAL_WINDOW
            
            if not requests:
                return 0
            
            oldest = min(requests)
            reset_time = oldest + window
            return max(0, int(reset_time - time.time()))


# Global rate limiter instance
rate_limiter = RateLimiter()


def check_rate_limit(api_key: Optional[str] = None):
    """
    FastAPI dependency to check rate limits.
    
    Args:
        api_key: Optional API key for per-key limiting
    
    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    # Check global limit first
    if not rate_limiter.check_global_limit():
        reset_after = rate_limiter.get_reset_time()
        raise HTTPException(
            status_code=429,
            detail=f"Global rate limit exceeded. Try again in {reset_after} seconds.",
            headers={"Retry-After": str(reset_after)}
        )
    
    # Check per-API-key limit if key provided
    if api_key:
        if not rate_limiter.check_api_key_limit(api_key):
            reset_after = rate_limiter.get_reset_time(api_key)
            raise HTTPException(
                status_code=429,
                detail=f"API key rate limit exceeded. Try again in {reset_after} seconds.",
                headers={"Retry-After": str(reset_after)}
            )


def client_ip_of(request) -> str:
    """
    Best-effort client IP for anonymous-route rate limiting.

    Prefers the first X-Forwarded-For hop (set by the ingress/replica proxy);
    falls back to the direct peer address. X-Forwarded-For is client-spoofable
    where no trusted proxy strips it — this is a DoS-mitigation bucket, not an
    identity boundary, and false attribution only widens or narrows one bucket.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    first_hop = forwarded.split(",")[0].strip() if forwarded else ""
    if first_hop:
        return first_hop
    return request.client.host if request.client else "unknown"


def check_auth_rate_limit(request):
    """
    FastAPI dependency for anonymous /auth/* routes: per-IP bucket only.

    These routes have no API key, so the per-key limiter cannot apply; an
    unthrottled bcrypt signup/signin is a ~4 req/s whole-service DoS plus a
    password-guessing oracle (issues #226, #334).
    """
    ip = client_ip_of(request)
    if not rate_limiter.check_ip_limit(ip):
        reset_after = rate_limiter.get_ip_reset_time(ip)
        raise HTTPException(
            status_code=429,
            detail=f"Too many authentication attempts. Try again in {reset_after} seconds.",
            headers={"Retry-After": str(reset_after)},
        )
