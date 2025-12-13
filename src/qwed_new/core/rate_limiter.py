"""
Rate limiting for QWED API endpoints.

Implements:
- Per-API-key rate limits
- Global endpoint rate limits
- Returns 429 Too Many Requests when exceeded
"""

from datetime import datetime, timedelta
from typing import Dict, Optional
from collections import defaultdict
from fastapi import HTTPException, Request
import time

class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window algorithm.
    
    For production with multiple servers, consider using Redis instead.
    """
    
    def __init__(self):
        # Per-API-key request timestamps: {api_key: [timestamp1, timestamp2, ...]}
        self.api_key_requests: Dict[str, list] = defaultdict(list)
        
        # Global request timestamps: [timestamp1, timestamp2, ...]
        self.global_requests: list = []
        
        # Rate limit configurations
        self.PER_KEY_LIMIT = 100  # requests per minute per API key
        self.PER_KEY_WINDOW = 60  # seconds
        
        self.GLOBAL_LIMIT = 1000  # requests per minute total
        self.GLOBAL_WINDOW = 60  # seconds
    
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
    
    def get_reset_time(self, api_key: Optional[str] = None) -> int:
        """
        Get seconds until rate limit resets.
        
        Args:
            api_key: If provided, get per-key reset time. Otherwise, global reset time.
        
        Returns:
            Seconds until oldest request expires from the window
        """
        if api_key:
            requests = self.api_key_requests.get(api_key, [])
            window = self.PER_KEY_WINDOW
        else:
            requests = self.global_requests
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
