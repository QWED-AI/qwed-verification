"""
QWED Verification Cache.

Caches verification results to reduce latency for repeated queries.
Logic is universal - same problem = same answer.

Addresses Gemini's feedback on latency:
- Monty Hall: 12,115ms -> ~1ms (cached)
- Hamiltonian Path: 21,163ms -> ~1ms (cached)

Issue #189: Redis fallback is now fail-closed by default.
RedisCache in STRICT_DISTRIBUTED mode raises CacheBackendUnavailableError
when Redis is unavailable instead of silently degrading to node-local state.
"""

import hashlib
import copy
import json
import time
from enum import Enum
from typing import Callable, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from threading import Event, Lock
from collections import OrderedDict

import logging

_security_logger = logging.getLogger("qwed.cache.security")

_STRICT_UNAVAILABLE_MSG = "RedisCache(mode=STRICT_DISTRIBUTED): Redis backend is unavailable. "
_STRICT_COOLDOWN_MSG = "Fail-closed -- client in cooldown, not falling back to node-local cache."
MSG_BACKEND_RECOVERED = "Redis connection restored; exiting node-local fallback mode."


# ---------------------------------------------------------------------------
# Backend mode contract
# ---------------------------------------------------------------------------

class CacheBackendMode(str, Enum):
    """
    Explicit contract for cache backend failure semantics.

    STRICT_DISTRIBUTED (default for security-sensitive paths):
        Redis unavailable at startup or runtime -> raise CacheBackendUnavailableError.
        Never silently falls back to node-local state.
        Use this wherever cache-backed enforcement (rate limits, replay
        protection, policy gates) must be consistent across nodes.

    EXPLICIT_DEGRADED:
        Redis unavailable -> fall back to node-local VerificationCache,
        but only if the caller explicitly opts in.
        Every result from the fallback path is tagged with
        _degraded_mode=True and _cache_backend="local_degraded" so
        callers and auditors can detect the downgrade.
        A structured security event is emitted on mode activation.

    LOCAL_ONLY:
        Never touches Redis. Pure in-memory VerificationCache.
        For single-process use, tests, and the cached_verify() convenience
        wrapper where distributed semantics are not required.
    """
    STRICT_DISTRIBUTED = "STRICT_DISTRIBUTED"
    EXPLICIT_DEGRADED  = "EXPLICIT_DEGRADED"
    LOCAL_ONLY         = "LOCAL_ONLY"


class CacheBackendUnavailableError(RuntimeError):
    """
    Raised when STRICT_DISTRIBUTED mode cannot reach the Redis backend.

    This is intentional fail-closed behavior. The caller must handle this
    exception explicitly -- it must not be silently swallowed.

    In distributed deployments this typically means the request should be
    responded to with an UNVERIFIABLE result rather than proceeding with
    a node-local cache state that may diverge from other nodes.
    """


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------

@dataclass
class CacheEntry:
    """A cached verification result."""
    key: str
    dsl_code: str
    result: Dict[str, Any]
    created_at: float
    hit_count: int = 0
    last_accessed: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# In-memory LRU cache (unchanged, LOCAL_ONLY / EXPLICIT_DEGRADED fallback)
# ---------------------------------------------------------------------------

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
        """Generate an unambiguous cache key from DSL code and optional variables."""
        normalized = ' '.join(dsl_code.split())
        # Use a structured JSON object so "foo" + vars=[1] never collides with
        # "foo[1]" + vars=None (plain string concatenation would cause that).
        key_material = json.dumps(
            {"dsl": normalized, "vars": variables},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(key_material.encode()).hexdigest()[:32]

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

            return copy.deepcopy(entry.result)

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
            # If the key already exists, remove it first so the size
            # calculation below is accurate (update-in-place, no extra eviction).
            self._cache.pop(key, None)
            # Evict oldest only when adding a genuinely new key would exceed capacity.
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)

            self._cache[key] = CacheEntry(
                key=key,
                dsl_code=dsl_code,
                result=copy.deepcopy(result),
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
        with self._lock:
            return len(self._cache)

    def __contains__(self, dsl_code: str) -> bool:
        # Delegate to get() so TTL is respected and _lock is acquired.
        return self.get(dsl_code) is not None


# ---------------------------------------------------------------------------
# Redis-backed distributed cache (fail-closed by default)
# ---------------------------------------------------------------------------

class RedisCache:
    """
    Redis-backed verification cache for distributed deployments.

    Backend failure semantics are controlled by the ``mode`` parameter:

    * STRICT_DISTRIBUTED (default) -- Redis unavailable at startup or
      during a get/set/invalidate/clear call raises
      CacheBackendUnavailableError.  No silent node-local fallback.

    * EXPLICIT_DEGRADED -- Redis unavailable activates a node-local
      VerificationCache fallback, but only after emitting a structured
      security event.  Every result served from the fallback is tagged
      with ``_degraded_mode=True`` and
      ``_cache_backend="local_degraded"``.

    Issue #189: the previous behaviour of silently falling back to
    in-memory (fail-open) has been removed for STRICT_DISTRIBUTED mode.
    """

    def __init__(
        self,
        ttl_math: int = 3600,      # 1 hour for deterministic math
        ttl_logic: int = 300,       # 5 minutes for logic
        ttl_default: int = 600,     # 10 minutes default
        tenant_id: Optional[int] = None,
        enabled: bool = True,
        mode: CacheBackendMode = CacheBackendMode.STRICT_DISTRIBUTED,
    ):
        self.ttl_math = ttl_math
        self.ttl_logic = ttl_logic
        self.ttl_default = ttl_default
        self.tenant_id = tenant_id
        self.enabled = enabled
        self.mode = mode

        # LOCAL_ONLY is not valid for RedisCache -- use VerificationCache directly
        # or get_cache(use_redis=False). Reject at construction to surface misuse early.
        if self.mode == CacheBackendMode.LOCAL_ONLY:
            raise ValueError(
                "RedisCache does not support mode=LOCAL_ONLY. "
                "Use VerificationCache() directly, or get_cache(use_redis=False)."
            )

        # Import here to avoid circular imports
        from qwed_new.core.redis_config import get_redis_client, CacheKeys

        self._client = get_redis_client()
        self._cache_keys = CacheKeys

        # Metrics
        self._hits = 0
        self._misses = 0

        # Fallback cache -- only allowed in EXPLICIT_DEGRADED mode
        self._fallback_cache: Optional[VerificationCache] = None
        self._fallback_lock = Lock()

        if self._client is None:
            if self.mode == CacheBackendMode.STRICT_DISTRIBUTED:
                raise CacheBackendUnavailableError(
                    _STRICT_UNAVAILABLE_MSG +
                    "Fail-closed -- refusing to silently degrade to node-local cache. "
                    "To allow node-local fallback, use mode=EXPLICIT_DEGRADED explicitly. "
                    "To disable Redis entirely, use mode=LOCAL_ONLY or VerificationCache directly."
                )
            elif self.mode == CacheBackendMode.EXPLICIT_DEGRADED:
                self._fallback_cache = VerificationCache()
                self._emit_security_event(
                    "BACKEND_UNAVAILABLE_AT_STARTUP",
                    "Redis unavailable at construction; activating node-local fallback. "
                    "Results served from this node may diverge from other nodes."
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _recover_from_fallback(self) -> None:
        """Clear fallback state and emit recovery event (only on real transition)."""
        with self._fallback_lock:
            if self._fallback_cache is None:
                return
            self._fallback_cache = None
            self._emit_security_event("BACKEND_RECOVERED", MSG_BACKEND_RECOVERED)

    # Minimum seconds between connection retries when Redis is unavailable.
    # Prevents hammering Redis on every request and keeps tests isolated.
    _CLIENT_RETRY_INTERVAL: float = 30.0

    def _try_get_client(self):
        if self._client is not None:
            return self._client
        retry_after = getattr(self, "_client_retry_after", 0.0)
        if time.time() < retry_after:
            return None  # Still in cooldown
        from qwed_new.core.redis_config import get_redis_client
        client = get_redis_client()
        if client is not None:
            self._client = client
        else:
            self._client_retry_after = time.time() + self._CLIENT_RETRY_INTERVAL
        return client

    def _emit_security_event(self, event_type: str, detail: str) -> None:
        """Emit a structured security event when backend state changes."""
        _security_logger.warning(json.dumps({
            "event": event_type,
            "backend": "redis",
            "mode": self.mode,
            "tenant_id": self.tenant_id,
            "detail": detail,
            "timestamp": time.time(),
        }))

    def _get_ttl(self, result_type: str = "default") -> int:
        """Get TTL based on result type."""
        if result_type == "math":
            return self.ttl_math
        elif result_type == "logic":
            return self.ttl_logic
        return self.ttl_default

    def _generate_key(self, dsl_code: str, variables: Optional[list] = None) -> str:
        """Generate an unambiguous cache key from DSL code and optional variables."""
        normalized = ' '.join(dsl_code.split())
        key_material = json.dumps(
            {"dsl": normalized, "vars": variables},
            sort_keys=True,
            separators=(",", ":"),
        )
        query_hash = hashlib.sha256(key_material.encode()).hexdigest()[:32]
        return self._cache_keys.verification_key(self.tenant_id, query_hash)

    def _handle_runtime_redis_error(self, operation: str, exc: Exception) -> None:
        """
        Handle a Redis error that occurs during get/set/invalidate/clear.

        STRICT_DISTRIBUTED: raises CacheBackendUnavailableError immediately.
        EXPLICIT_DEGRADED:  emits a security event (fallback already active
                            from __init__, or activates it now if Redis died
                            at runtime after a successful startup).
        """
        # Mark the client dead immediately so _try_get_client's cooldown path
        # kicks in instead of retrying the same broken connection on every call.
        self._client = None
        self._client_retry_after = time.time() + self._CLIENT_RETRY_INTERVAL
        # Also clear the module-level cached client so get_redis_client()
        # creates a fresh connection instead of returning the stale object.
        from qwed_new.core.redis_config import invalidate_redis_client
        invalidate_redis_client()

        if self.mode == CacheBackendMode.STRICT_DISTRIBUTED:
            raise CacheBackendUnavailableError(
                f"RedisCache(mode=STRICT_DISTRIBUTED): Redis {operation} failed: {exc}. "
                "Fail-closed -- not falling back to node-local cache."
            ) from exc

        # EXPLICIT_DEGRADED: activate fallback lazily on runtime loss
        with self._fallback_lock:
            if self._fallback_cache is None:
                self._fallback_cache = VerificationCache()
                self._emit_security_event(
                    "BACKEND_UNAVAILABLE_AT_RUNTIME",
                    f"Redis {operation} failed: {exc}. "
                    "Activating node-local fallback; results may diverge across nodes."
                )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get(self, dsl_code: str, variables: Optional[list] = None) -> Optional[Dict[str, Any]]:
        """
        Get cached result for DSL code.

        Raises:
            CacheBackendUnavailableError: in STRICT_DISTRIBUTED mode when
                Redis is unavailable (startup or runtime).
        """
        if not self.enabled:
            return None

        key = self._generate_key(dsl_code, variables)

        client = self._try_get_client()
        if client is None and self.mode == CacheBackendMode.STRICT_DISTRIBUTED:
            raise CacheBackendUnavailableError(
                _STRICT_UNAVAILABLE_MSG +
                _STRICT_COOLDOWN_MSG
            )

        cached = None
        if client is not None:
            try:
                cached = client.get(key)
            except Exception as exc:
                self._handle_runtime_redis_error("get", exc)
            else:
                self._recover_from_fallback()
                if cached is None:
                    self._misses += 1
                    return None
                self._hits += 1
                return json.loads(cached)  # JSON errors propagate naturally

        # Snapshot under lock to avoid TOCTOU race with _recover_from_fallback()
        with self._fallback_lock:
            fallback = self._fallback_cache

        if fallback is not None:
            # EXPLICIT_DEGRADED path -- tag result so callers can detect downgrade
            result = fallback.get(dsl_code, variables)
            if result is not None:
                result = dict(result)
                result["_degraded_mode"] = True
                result["_cache_backend"] = "local_degraded"
            return result
            
        return None

    def set(
        self,
        dsl_code: str,
        result: Dict[str, Any],
        variables: Optional[list] = None,
        result_type: str = "default"
    ) -> None:
        """
        Cache a verification result.

        Raises:
            CacheBackendUnavailableError: in STRICT_DISTRIBUTED mode when
                Redis is unavailable.
        """
        if not self.enabled:
            return

        key = self._generate_key(dsl_code, variables)
        ttl = self._get_ttl(result_type)

        client = self._try_get_client()
        if client is None and self.mode == CacheBackendMode.STRICT_DISTRIBUTED:
            raise CacheBackendUnavailableError(
                _STRICT_UNAVAILABLE_MSG +
                _STRICT_COOLDOWN_MSG
            )
        if client is not None:
            payload = json.dumps(result)  # JSON errors propagate naturally -- not a Redis issue
            try:
                client.setex(key, ttl, payload)
            except Exception as exc:
                self._handle_runtime_redis_error("set", exc)
            else:
                self._recover_from_fallback()
                return

        # Snapshot under lock to avoid TOCTOU race with _recover_from_fallback()
        with self._fallback_lock:
            fallback = self._fallback_cache

        if fallback is not None:
            fallback.set(dsl_code, result, variables)

    def invalidate(self, dsl_code: str, variables: Optional[list] = None) -> bool:
        """
        Remove a specific entry from cache.

        Raises:
            CacheBackendUnavailableError: in STRICT_DISTRIBUTED mode when
                Redis is unavailable.
        """
        key = self._generate_key(dsl_code, variables)
        client = self._try_get_client()
        if client is None and self.mode == CacheBackendMode.STRICT_DISTRIBUTED:
            raise CacheBackendUnavailableError(
                _STRICT_UNAVAILABLE_MSG +
                _STRICT_COOLDOWN_MSG
            )

        redis_failed = False
        if client is not None:
            try:
                ret = client.delete(key) > 0
                
                self._recover_from_fallback()
                return ret

            except Exception as exc:
                self._handle_runtime_redis_error("invalidate", exc)
                redis_failed = True

        fallback = None
        with self._fallback_lock:
            fallback = self._fallback_cache

        if redis_failed:
            raise CacheBackendUnavailableError(
                "RedisCache(mode=EXPLICIT_DEGRADED): Redis invalidate failed. "
                "Cannot confirm distributed deletion from node-local fallback."
            )

        if fallback is not None:
            return fallback.invalidate(dsl_code, variables)
        return False

    def _clear_redis_pattern(self, client, pattern: str) -> int:
        """Helper to scan and delete keys matching a pattern.

        Args:
            client: Active Redis client (already validated by caller).
            pattern: Key pattern to match.
        """
        cursor = 0
        deleted = 0
        while True:
            cursor, keys = client.scan(cursor, match=pattern, count=100)
            if keys:
                deleted += client.delete(*keys)
            if cursor == 0:
                break
        return deleted

    def clear(self, pattern: Optional[str] = None) -> int:
        """
        Clear cached entries.

        Args:
            pattern: Optional pattern to match (e.g., "qwed:verify:*")
                    If None, clears all QWED verification cache

        Raises:
            CacheBackendUnavailableError: in STRICT_DISTRIBUTED mode when
                Redis is unavailable.
        """
        client = self._try_get_client()
        if client is None and self.mode == CacheBackendMode.STRICT_DISTRIBUTED:
            raise CacheBackendUnavailableError(
                _STRICT_UNAVAILABLE_MSG +
                _STRICT_COOLDOWN_MSG
            )
        redis_failed = False
        if client is not None:
            try:
                if pattern is None:
                    pattern = f"{self._cache_keys.VERIFICATION}:*"

                deleted = self._clear_redis_pattern(client, pattern)

                self._hits = 0
                self._misses = 0

                self._recover_from_fallback()
                return deleted

            except Exception as exc:
                self._handle_runtime_redis_error("clear", exc)
                redis_failed = True

        fallback = None
        with self._fallback_lock:
            fallback = self._fallback_cache

        if redis_failed:
            raise CacheBackendUnavailableError(
                "RedisCache(mode=EXPLICIT_DEGRADED): Redis clear failed. "
                "Cannot confirm distributed deletion from node-local fallback."
            )

        if fallback is not None:
            return fallback.clear()
        return 0

    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._fallback_lock:
            fallback = self._fallback_cache
        if fallback is not None:
            stats = fallback.stats
            stats["backend"] = "local_degraded"
            stats["mode"] = self.mode
            stats["degraded"] = True
            return stats

        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0

        try:
            info = self._client.info("memory")
            return {
                "backend": "redis",
                "mode": self.mode,
                "degraded": False,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "redis_used_memory": info.get("used_memory_human"),
                "enabled": self.enabled,
                "tenant_id": self.tenant_id,
            }
        except Exception:
            with self._fallback_lock:
                degraded = self._fallback_cache is not None
            return {
                "backend": "redis",
                "mode": self.mode,
                "degraded": degraded,
                "backend_error": True,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "enabled": self.enabled,
                "tenant_id": self.tenant_id,
            }


# ---------------------------------------------------------------------------
# Global cache factory
# ---------------------------------------------------------------------------

# Global singletons (kept for backward compat with existing callers)
# _verification_caches is a per-tenant mapping to prevent cross-tenant leakage
# in LOCAL_ONLY / no-Redis paths: VerificationCache._generate_key has no tenant
# context, so we maintain separate instances per tenant_id.
_verification_caches: Dict[Optional[int], VerificationCache] = {}
# Per-(tenant_id, mode) RedisCache map — protected by _cache_factory_lock
# to prevent concurrent callers racing and crossing tenant boundaries.
_redis_caches: Dict[tuple, RedisCache] = {}
# Per-(tenant_id, mode) timestamp — prevents get_cache() from holding the factory
# lock while hammering a dead Redis connection on every call.
_redis_cache_retry_after: Dict[tuple, float] = {}
_constructing_events: Dict[tuple, Event] = {}  # signals when construction completes
_cache_factory_lock = Lock()


def _get_or_create_local_cache(tenant_id: Optional[int]) -> VerificationCache:
    with _cache_factory_lock:
        cache = _verification_caches.get(tenant_id)
        if cache is None:
            cache = VerificationCache()
            _verification_caches[tenant_id] = cache
    return cache


def _raise_if_retry_cooldown_active(cache_key: tuple, mode: CacheBackendMode) -> None:
    retry_after = _redis_cache_retry_after.get(cache_key, 0.0)
    if time.time() < retry_after:
        raise CacheBackendUnavailableError(
            f"RedisCache(mode={mode.value}): Redis backend unavailable "
            f"(cooldown active for {retry_after - time.time():.0f}s). "
            "Fail-closed."
        )


def _await_or_claim_redis_cache_construction(
    cache_key: tuple,
    mode: CacheBackendMode,
) -> tuple[Optional[RedisCache], Event]:
    while True:
        with _cache_factory_lock:
            cache = _redis_caches.get(cache_key)
            if cache is not None:
                return cache, Event()
            _raise_if_retry_cooldown_active(cache_key, mode)
            event = _constructing_events.get(cache_key)
            if event is None:
                event = Event()
                _constructing_events[cache_key] = event
                return None, event

        completed = event.wait(timeout=10.0)
        if not completed and mode == CacheBackendMode.STRICT_DISTRIBUTED:
            raise CacheBackendUnavailableError(
                f"RedisCache(mode={mode.value}): Cache construction timed out. "
                "Fail-closed."
            )


def _record_redis_cache_construction_failure(cache_key: tuple) -> None:
    with _cache_factory_lock:
        _constructing_events.pop(cache_key, None)
        _redis_cache_retry_after[cache_key] = time.time() + RedisCache._CLIENT_RETRY_INTERVAL


def get_cache(
    use_redis: bool = True,
    tenant_id: Optional[int] = None,
    mode: CacheBackendMode = CacheBackendMode.STRICT_DISTRIBUTED,
) -> "Union[VerificationCache, RedisCache]":
    """
    Get the appropriate verification cache.

    Args:
        use_redis: Whether to use the Redis backend.
        tenant_id: Optional tenant ID for multi-tenant isolation.
        mode: Backend failure semantics (see CacheBackendMode).
              Defaults to STRICT_DISTRIBUTED -- Redis unavailable raises
              CacheBackendUnavailableError instead of silently degrading.

    Returns:
        Cache instance.  May be RedisCache or VerificationCache depending
        on use_redis and mode.

    Raises:
        CacheBackendUnavailableError: when use_redis=True,
            mode=STRICT_DISTRIBUTED, and Redis is unavailable.
    """
    if not use_redis or mode == CacheBackendMode.LOCAL_ONLY:
        return _get_or_create_local_cache(tenant_id)

    # Redis path — per-(tenant_id, mode) singleton, locked to prevent races
    cache_key = (tenant_id, mode)

    cache, event = _await_or_claim_redis_cache_construction(cache_key, mode)
    if cache is not None:
        return cache

    # Construct outside the lock -- RedisCache.__init__ calls
    # get_redis_client() which may block on a 5-second network timeout.
    try:
        new_cache = RedisCache(tenant_id=tenant_id, mode=mode)
    except CacheBackendUnavailableError:
        _record_redis_cache_construction_failure(cache_key)
        event.set()  # Wake waiters after state is consistent
        raise
    except Exception:
        _record_redis_cache_construction_failure(cache_key)
        event.set()
        raise

    # Insert into dict, THEN signal waiters so they always find the cache.
    with _cache_factory_lock:
        _constructing_events.pop(cache_key, None)
        cache = _redis_caches.get(cache_key)
        if cache is not None:
            event.set()
            return cache
        _redis_caches[cache_key] = new_cache
    event.set()  # Wake waiters — cache is now in the dict
    return new_cache


def cached_verify(
    dsl_code: str,
    variables: Optional[list] = None,
    verify_fn: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Verify with caching (single-process convenience wrapper).

    Uses LOCAL_ONLY mode -- no Redis, no distributed semantics.
    For distributed deployments, call get_cache(mode=STRICT_DISTRIBUTED)
    directly and manage the cache lifecycle explicitly.

    Args:
        dsl_code: The QWED-DSL expression
        variables: Variable declarations
        verify_fn: Function to call on cache miss (should return result dict)

    Returns:
        Verification result (from cache or fresh)
    """
    # LOCAL_ONLY: deterministic, no distributed concerns
    cache = get_cache(use_redis=False, mode=CacheBackendMode.LOCAL_ONLY)

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
if __name__ == "__main__":  # pragma: no cover
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
