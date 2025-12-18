"""
QWED Verification Cache.

Caches verification results to reduce latency for repeated queries.
Logic is universal - same problem = same answer.

Addresses Gemini's feedback on latency:
- Monty Hall: 12,115ms → ~1ms (cached)
- Hamiltonian Path: 21,163ms → ~1ms (cached)
"""

import hashlib
import json
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from threading import Lock
from collections import OrderedDict


@dataclass
class CacheEntry:
    """A cached verification result."""
    key: str
    dsl_code: str
    result: Dict[str, Any]
    created_at: float
    hit_count: int = 0
    last_accessed: float = field(default_factory=time.time)


class VerificationCache:
    """
    LRU Cache for verification results.
    
    Features:
    - Thread-safe
    - LRU eviction
    - TTL (time-to-live) support
    - Hit rate tracking
    """
    
    def __init__(
        self, 
        max_size: int = 1000,
        ttl_seconds: int = 3600,  # 1 hour default
        enabled: bool = True
    ):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled
        
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = Lock()
        
        # Metrics
        self._hits = 0
        self._misses = 0
    
    def _generate_key(self, dsl_code: str, variables: Optional[list] = None) -> str:
        """Generate a cache key from DSL code and variables."""
        # Normalize the DSL (remove extra whitespace)
        normalized = ' '.join(dsl_code.split())
        
        # Include variables in key if provided
        if variables:
            normalized += json.dumps(variables, sort_keys=True)
        
        # Hash for fixed-length key
        return hashlib.sha256(normalized.encode()).hexdigest()[:32]
    
    def get(self, dsl_code: str, variables: Optional[list] = None) -> Optional[Dict[str, Any]]:
        """
        Get cached result for DSL code.
        
        Returns:
            Cached result dict or None if not found/expired
        """
        if not self.enabled:
            return None
        
        key = self._generate_key(dsl_code, variables)
        
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            entry = self._cache[key]
            
            # Check TTL
            if time.time() - entry.created_at > self.ttl_seconds:
                # Expired - remove and return None
                del self._cache[key]
                self._misses += 1
                return None
            
            # Hit! Update stats and move to end (LRU)
            entry.hit_count += 1
            entry.last_accessed = time.time()
            self._cache.move_to_end(key)
            self._hits += 1
            
            return entry.result
    
    def set(
        self, 
        dsl_code: str, 
        result: Dict[str, Any],
        variables: Optional[list] = None
    ) -> None:
        """Cache a verification result."""
        if not self.enabled:
            return
        
        key = self._generate_key(dsl_code, variables)
        
        with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
            
            self._cache[key] = CacheEntry(
                key=key,
                dsl_code=dsl_code,
                result=result,
                created_at=time.time()
            )
    
    def invalidate(self, dsl_code: str, variables: Optional[list] = None) -> bool:
        """Remove a specific entry from cache."""
        key = self._generate_key(dsl_code, variables)
        
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> int:
        """Clear all cached entries. Returns count of cleared entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            return count
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "ttl_seconds": self.ttl_seconds,
                "enabled": self.enabled
            }
    
    def __len__(self) -> int:
        return len(self._cache)
    
    def __contains__(self, dsl_code: str) -> bool:
        key = self._generate_key(dsl_code)
        return key in self._cache


class RedisCache:
    """
    Redis-backed verification cache for distributed deployments.
    
    Features:
    - Distributed cache across multiple instances
    - Automatic TTL expiration
    - Graceful fallback to in-memory if Redis unavailable
    - Same interface as VerificationCache
    """
    
    def __init__(
        self,
        ttl_math: int = 3600,      # 1 hour for deterministic math
        ttl_logic: int = 300,       # 5 minutes for logic
        ttl_default: int = 600,     # 10 minutes default
        tenant_id: Optional[int] = None,
        enabled: bool = True
    ):
        self.ttl_math = ttl_math
        self.ttl_logic = ttl_logic
        self.ttl_default = ttl_default
        self.tenant_id = tenant_id
        self.enabled = enabled
        
        # Import here to avoid circular imports
        from qwed_new.core.redis_config import get_redis_client, CacheKeys
        
        self._client = get_redis_client()
        self._cache_keys = CacheKeys
        
        # Metrics (stored in Redis for distributed tracking)
        self._hits = 0
        self._misses = 0
        
        # Fallback to in-memory if Redis unavailable
        self._fallback_cache: Optional[VerificationCache] = None
        if self._client is None:
            self._fallback_cache = VerificationCache()
    
    def _get_ttl(self, result_type: str = "default") -> int:
        """Get TTL based on result type."""
        if result_type == "math":
            return self.ttl_math
        elif result_type == "logic":
            return self.ttl_logic
        return self.ttl_default
    
    def _generate_key(self, dsl_code: str, variables: Optional[list] = None) -> str:
        """Generate a cache key from DSL code and variables."""
        normalized = ' '.join(dsl_code.split())
        if variables:
            normalized += json.dumps(variables, sort_keys=True)
        query_hash = hashlib.sha256(normalized.encode()).hexdigest()[:32]
        return self._cache_keys.verification_key(self.tenant_id, query_hash)
    
    def get(self, dsl_code: str, variables: Optional[list] = None) -> Optional[Dict[str, Any]]:
        """Get cached result for DSL code."""
        if not self.enabled:
            return None
        
        # Fallback to in-memory
        if self._fallback_cache:
            return self._fallback_cache.get(dsl_code, variables)
        
        key = self._generate_key(dsl_code, variables)
        
        try:
            cached = self._client.get(key)
            if cached is None:
                self._misses += 1
                return None
            
            self._hits += 1
            return json.loads(cached)
            
        except Exception as e:
            # Redis error - log and return None
            import logging
            logging.warning(f"Redis get error: {e}")
            self._misses += 1
            return None
    
    def set(
        self,
        dsl_code: str,
        result: Dict[str, Any],
        variables: Optional[list] = None,
        result_type: str = "default"
    ) -> None:
        """Cache a verification result."""
        if not self.enabled:
            return
        
        # Fallback to in-memory
        if self._fallback_cache:
            self._fallback_cache.set(dsl_code, result, variables)
            return
        
        key = self._generate_key(dsl_code, variables)
        ttl = self._get_ttl(result_type)
        
        try:
            self._client.setex(key, ttl, json.dumps(result))
        except Exception as e:
            import logging
            logging.warning(f"Redis set error: {e}")
    
    def invalidate(self, dsl_code: str, variables: Optional[list] = None) -> bool:
        """Remove a specific entry from cache."""
        if self._fallback_cache:
            return self._fallback_cache.invalidate(dsl_code, variables)
        
        key = self._generate_key(dsl_code, variables)
        
        try:
            return self._client.delete(key) > 0
        except Exception:
            return False
    
    def clear(self, pattern: str = None) -> int:
        """
        Clear cached entries.
        
        Args:
            pattern: Optional pattern to match (e.g., "qwed:verify:*")
                    If None, clears all QWED verification cache
        """
        if self._fallback_cache:
            return self._fallback_cache.clear()
        
        try:
            if pattern is None:
                pattern = f"{self._cache_keys.VERIFICATION}:*"
            
            # Use SCAN to avoid blocking
            cursor = 0
            deleted = 0
            while True:
                cursor, keys = self._client.scan(cursor, match=pattern, count=100)
                if keys:
                    deleted += self._client.delete(*keys)
                if cursor == 0:
                    break
            
            self._hits = 0
            self._misses = 0
            return deleted
            
        except Exception as e:
            import logging
            logging.warning(f"Redis clear error: {e}")
            return 0
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self._fallback_cache:
            stats = self._fallback_cache.stats
            stats["backend"] = "in-memory (fallback)"
            return stats
        
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        
        try:
            info = self._client.info("memory")
            return {
                "backend": "redis",
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "redis_used_memory": info.get("used_memory_human"),
                "enabled": self.enabled,
                "tenant_id": self.tenant_id
            }
        except Exception:
            return {
                "backend": "redis",
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "enabled": self.enabled
            }


# Global cache singleton
_verification_cache: Optional[VerificationCache] = None
_redis_cache: Optional[RedisCache] = None


def get_cache(use_redis: bool = True, tenant_id: Optional[int] = None) -> VerificationCache:
    """
    Get the appropriate verification cache.
    
    Args:
        use_redis: Whether to prefer Redis cache (falls back to in-memory if unavailable)
        tenant_id: Optional tenant ID for multi-tenant isolation
        
    Returns:
        Cache instance (RedisCache or VerificationCache)
    """
    global _verification_cache, _redis_cache
    
    if use_redis:
        # Try Redis first
        from qwed_new.core.redis_config import is_redis_available
        
        if is_redis_available():
            if _redis_cache is None or _redis_cache.tenant_id != tenant_id:
                _redis_cache = RedisCache(tenant_id=tenant_id)
            return _redis_cache
    
    # Fallback to in-memory
    if _verification_cache is None:
        _verification_cache = VerificationCache()
    return _verification_cache


def cached_verify(
    dsl_code: str,
    variables: Optional[list] = None,
    verify_fn: callable = None
) -> Dict[str, Any]:
    """
    Verify with caching.
    
    Args:
        dsl_code: The QWED-DSL expression
        variables: Variable declarations
        verify_fn: Function to call on cache miss (should return result dict)
        
    Returns:
        Verification result (from cache or fresh)
    """
    cache = get_cache()
    
    # Check cache first
    cached_result = cache.get(dsl_code, variables)
    if cached_result is not None:
        cached_result['_cached'] = True
        return cached_result
    
    # Cache miss - compute result
    if verify_fn is None:
        raise ValueError("verify_fn required on cache miss")
    
    result = verify_fn()
    result['_cached'] = False
    
    # Only cache successful results
    if result.get('status') in ['SAT', 'UNSAT', 'SUCCESS']:
        cache.set(dsl_code, result, variables)
    
    return result


# --- DEMO ---
if __name__ == "__main__":
    import time
    
    print("=" * 60)
    print("QWED Verification Cache Demo")
    print("=" * 60)
    
    cache = VerificationCache()
    
    # Test DSL
    test_dsl = "(AND (GT x 5) (LT y 10))"
    test_result = {"status": "SAT", "model": {"x": "6", "y": "9"}}
    
    # First access - cache miss
    print("\n1. First access (cache miss):")
    result = cache.get(test_dsl)
    print(f"   Result: {result}")
    print(f"   Stats: {cache.stats}")
    
    # Set cache
    print("\n2. Caching result...")
    cache.set(test_dsl, test_result)
    
    # Second access - cache hit
    print("\n3. Second access (cache hit):")
    result = cache.get(test_dsl)
    print(f"   Result: {result}")
    print(f"   Stats: {cache.stats}")
    
    # Simulate latency savings
    print("\n4. Latency simulation:")
    print("   Without cache: ~12,000ms (Monty Hall benchmark)")
    print("   With cache:    ~0.01ms")
    
    start = time.perf_counter()
    for _ in range(1000):
        cache.get(test_dsl)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"   1000 cache lookups: {elapsed:.2f}ms ({elapsed/1000:.4f}ms per lookup)")
    
    print(f"\n5. Final Stats: {cache.stats}")
    print("\n" + "=" * 60)
