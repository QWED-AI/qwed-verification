"""
Redis Configuration for QWED.

Provides centralized Redis connection management with:
- Connection pooling
- Health checks
- Graceful fallback when Redis is unavailable
"""

import os
import logging
from typing import Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

# Redis connection settings from environment
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
REDIS_SOCKET_TIMEOUT = float(os.getenv("REDIS_SOCKET_TIMEOUT", "5.0"))

# Lazy import to avoid ImportError if redis not installed
_redis_client = None
_redis_available = None


def get_redis_client():
    """
    Get the Redis client singleton with connection pooling.
    
    Returns:
        redis.Redis instance or None if Redis is unavailable
    """
    global _redis_client, _redis_available
    
    if _redis_available is False:
        return None
    
    if _redis_client is not None:
        return _redis_client
    
    try:
        import redis
        
        _redis_client = redis.from_url(
            REDIS_URL,
            max_connections=REDIS_MAX_CONNECTIONS,
            socket_timeout=REDIS_SOCKET_TIMEOUT,
            socket_connect_timeout=REDIS_SOCKET_TIMEOUT,
            decode_responses=True  # Return strings instead of bytes
        )
        
        # Test connection
        _redis_client.ping()
        _redis_available = True
        logger.info(f"Redis connection established: {REDIS_URL}")
        return _redis_client
        
    except ImportError:
        logger.warning("redis-py not installed. Falling back to in-memory cache.")
        _redis_available = False
        return None
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}. Falling back to in-memory cache.")
        _redis_available = False
        return None


def is_redis_available() -> bool:
    """Check if Redis is available and connected."""
    global _redis_available
    
    if _redis_available is not None:
        return _redis_available
    
    # Try to connect
    client = get_redis_client()
    return client is not None


def redis_health_check() -> dict:
    """
    Perform health check on Redis connection.
    
    Returns:
        Dict with health status
    """
    try:
        client = get_redis_client()
        if client is None:
            return {
                "status": "unavailable",
                "message": "Redis client not connected"
            }
        
        # Ping and get info
        client.ping()
        info = client.info("server")
        
        return {
            "status": "healthy",
            "redis_version": info.get("redis_version"),
            "connected_clients": client.info("clients").get("connected_clients"),
            "used_memory_human": client.info("memory").get("used_memory_human")
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# Cache key prefixes
class CacheKeys:
    """Standard key prefixes for Redis cache."""
    VERIFICATION = "qwed:verify"
    RATE_LIMIT = "qwed:ratelimit"
    SESSION = "qwed:session"
    
    @staticmethod
    def verification_key(tenant_id: Optional[int], query_hash: str) -> str:
        """Generate verification cache key."""
        if tenant_id:
            return f"{CacheKeys.VERIFICATION}:{tenant_id}:{query_hash}"
        return f"{CacheKeys.VERIFICATION}:global:{query_hash}"
    
    @staticmethod
    def rate_limit_key(tenant_id: int, window: str) -> str:
        """Generate rate limit key for sliding window."""
        return f"{CacheKeys.RATE_LIMIT}:{tenant_id}:{window}"


# TTL configurations (in seconds)
class CacheTTL:
    """Standard TTL values for different cache types."""
    MATH_RESULT = 3600      # 1 hour - deterministic, safe to cache longer
    LOGIC_RESULT = 300      # 5 minutes - context-dependent
    SQL_RESULT = 600        # 10 minutes
    CODE_RESULT = 600       # 10 minutes
    RATE_LIMIT_WINDOW = 60  # 1 minute sliding window
