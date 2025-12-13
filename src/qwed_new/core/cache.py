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


# Global cache singleton
_verification_cache: Optional[VerificationCache] = None


def get_cache() -> VerificationCache:
    """Get the global verification cache."""
    global _verification_cache
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
