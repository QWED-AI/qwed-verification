"""
Tests for Redis-backed caching and rate limiting.

These are REAL integration tests - they require Redis to be running.
In CI, Redis is provided as a service container.
Locally, run: docker-compose up -d redis
"""

import pytest
import time
import os


# Skip all tests in this file if Redis is not available
def redis_available():
    """Check if Redis is actually available."""
    try:
        import redis
        r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r.ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not redis_available(),
    reason="Redis not available - run 'docker-compose up -d redis' for local tests"
)


class TestVerificationCache:
    """Test the in-memory VerificationCache (no Redis needed)."""
    
    def test_cache_set_and_get(self):
        from qwed_new.core.cache import VerificationCache
        
        cache = VerificationCache()
        dsl = "(AND (GT x 5) (LT y 10))"
        result = {"status": "SAT", "model": {"x": 6, "y": 9}}
        
        cache.set(dsl, result)
        cached = cache.get(dsl)
        
        assert cached is not None
        assert cached["status"] == "SAT"
    
    def test_cache_miss(self):
        from qwed_new.core.cache import VerificationCache
        
        cache = VerificationCache()
        assert cache.get("nonexistent") is None
    
    def test_cache_ttl_expiration(self):
        from qwed_new.core.cache import VerificationCache
        
        # Very short TTL for testing
        cache = VerificationCache(ttl_seconds=1)
        dsl = "(EQ x 1)"
        cache.set(dsl, {"status": "SAT"})
        
        # Should be cached
        assert cache.get(dsl) is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        assert cache.get(dsl) is None
    
    def test_cache_invalidation(self):
        from qwed_new.core.cache import VerificationCache
        
        cache = VerificationCache()
        dsl = "(EQ a b)"
        cache.set(dsl, {"status": "UNSAT"})
        
        assert cache.get(dsl) is not None
        assert cache.invalidate(dsl) is True
        assert cache.get(dsl) is None
    
    def test_cache_stats(self):
        from qwed_new.core.cache import VerificationCache
        
        cache = VerificationCache()
        
        # Generate some hits and misses
        cache.set("query1", {"status": "SAT"})
        cache.get("query1")  # hit
        cache.get("query1")  # hit
        cache.get("query2")  # miss
        
        stats = cache.stats
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_rate_percent"] == pytest.approx(66.67, rel=0.1)


class TestRedisCache:
    """Test the RedisCache with REAL Redis connection."""
    
    def test_redis_cache_set_and_get(self):
        """Test basic set/get with real Redis."""
        from qwed_new.core.cache import RedisCache
        
        cache = RedisCache(tenant_id=999)  # Use test tenant
        
        # Clear any previous test data
        cache.clear()
        
        dsl = "(TEST redis cache)"
        result = {"status": "SAT", "test": True}
        
        cache.set(dsl, result, result_type="math")
        cached = cache.get(dsl)
        
        assert cached is not None
        assert cached["status"] == "SAT"
        assert cached["test"] is True
    
    def test_redis_cache_ttl(self):
        """Test that TTL works with real Redis."""
        from qwed_new.core.cache import RedisCache
        
        # Create cache with 1 second TTL for testing
        cache = RedisCache(ttl_default=1, tenant_id=998)
        cache.clear()
        
        dsl = "(TTL test)"
        cache.set(dsl, {"status": "SAT"})
        
        # Should be cached
        assert cache.get(dsl) is not None
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Should be expired
        assert cache.get(dsl) is None
    
    def test_redis_cache_stats(self):
        """Test stats tracking with real Redis."""
        from qwed_new.core.cache import RedisCache
        
        cache = RedisCache(tenant_id=997)
        cache.clear()
        
        cache.set("q1", {"status": "SAT"})
        cache.get("q1")  # hit
        cache.get("q1")  # hit
        cache.get("q2")  # miss
        
        stats = cache.stats
        assert stats["backend"] == "redis"
        assert stats["hits"] >= 2


class TestRateLimiter:
    """Test the in-memory RateLimiter (no Redis needed)."""
    
    def test_rate_limiter_allows(self):
        from qwed_new.core.policy import RateLimiter
        
        limiter = RateLimiter(rate=5, per=60)
        
        # Should allow first 5 requests
        for _ in range(5):
            assert limiter.allow() is True
        
        # 6th should be denied
        assert limiter.allow() is False
    
    def test_rate_limiter_refills(self):
        from qwed_new.core.policy import RateLimiter
        
        limiter = RateLimiter(rate=1, per=1)  # 1 request per second
        
        assert limiter.allow() is True
        assert limiter.allow() is False
        
        time.sleep(1.1)
        
        assert limiter.allow() is True


class TestRedisSlidingWindowLimiter:
    """Test Redis-backed sliding window rate limiter with REAL Redis."""
    
    def test_redis_rate_limiter_allows(self):
        """Test that rate limiter allows requests under limit."""
        from qwed_new.core.policy import RedisSlidingWindowLimiter
        
        limiter = RedisSlidingWindowLimiter(rate=5, per=60, key_prefix="qwed:test:ratelimit")
        
        # Reset first
        limiter.reset("test_allows")
        
        # Should allow first 5 requests
        for i in range(5):
            assert limiter.allow("test_allows") is True, f"Request {i+1} should be allowed"
        
        # 6th should be denied
        assert limiter.allow("test_allows") is False
    
    def test_redis_rate_limiter_remaining(self):
        """Test get_remaining returns accurate count."""
        from qwed_new.core.policy import RedisSlidingWindowLimiter
        
        limiter = RedisSlidingWindowLimiter(rate=10, per=60, key_prefix="qwed:test:ratelimit")
        limiter.reset("test_remaining")
        
        assert limiter.get_remaining("test_remaining") == 10
        
        limiter.allow("test_remaining")
        limiter.allow("test_remaining")
        
        assert limiter.get_remaining("test_remaining") == 8


class TestPolicyEngine:
    """Test PolicyEngine with REAL Redis."""
    
    def test_policy_engine_uses_redis(self):
        """Test that PolicyEngine detects and uses Redis."""
        from qwed_new.core.policy import PolicyEngine
        
        engine = PolicyEngine(use_redis=True)
        
        # Should be using Redis since it's available
        assert engine._redis_available is True
    
    def test_policy_rate_limit_info(self):
        """Test rate limit info endpoint."""
        from qwed_new.core.policy import PolicyEngine
        
        engine = PolicyEngine(use_redis=True)
        info = engine.get_rate_limit_info()
        
        assert info["backend"] == "redis"
        assert "remaining" in info
        assert "limit" in info
