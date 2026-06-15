import sys
import os
import re

file_path = os.path.join("src", "qwed_new", "core", "cache.py")
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add import copy at the top if not present
if "import copy" not in content:
    content = content.replace("import hashlib\n", "import hashlib\nimport copy\n")

# 2. Update __init__ to add _fallback_lock
content = content.replace(
    "self._fallback_cache: Optional[VerificationCache] = None",
    "self._fallback_cache: Optional[VerificationCache] = None\n        self._fallback_lock = Lock()"
)

# 3. Add _try_get_client method
try_get_code = '''
    def _try_get_client(self):
        if self._client is not None:
            return self._client
        # Lazy import to avoid circular imports during startup
        from qwed_new.core.redis_config import get_redis_client
        self._client = get_redis_client()
        return self._client
'''
content = content.replace(
    "    def _emit_security_event(self, event_type: str, detail: str) -> None:",
    try_get_code.lstrip('\n') + "\n    def _emit_security_event(self, event_type: str, detail: str) -> None:"
)

# 4. Thread-safe _recover_from_fallback
content = content.replace(
    "        if self._fallback_cache is not None:\n            self._fallback_cache = None",
    "        with self._fallback_lock:\n            if self._fallback_cache is not None:\n                self._fallback_cache = None"
)

# 5. Thread-safe _handle_runtime_redis_error
content = content.replace(
    "        if self._fallback_cache is None:\n            self._fallback_cache = VerificationCache()",
    "        with self._fallback_lock:\n            if self._fallback_cache is None:\n                self._fallback_cache = VerificationCache()"
)

# 6. Rewrite get() method
old_get = '''
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

        if self._client is not None:
            try:
                cached = self._client.get(key)
                
                self._recover_from_fallback()

                if cached is None:
                    self._misses += 1
                    return None

                self._hits += 1
                return json.loads(cached)

            except Exception as exc:
                self._handle_runtime_redis_error("get", exc)

        if self._fallback_cache is not None:
            # EXPLICIT_DEGRADED path -- tag result so callers can detect downgrade
            result = self._fallback_cache.get(dsl_code, variables)
            if result is not None:
                result = dict(result)
                result["_degraded_mode"] = True
                result["_cache_backend"] = "local_degraded"
            return result
            
        return None
'''

new_get = '''
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

        if client is not None:
            try:
                cached = client.get(key)
                
                self._recover_from_fallback()

                if cached is None:
                    self._misses += 1
                    return None

                self._hits += 1
                return json.loads(cached)

            except Exception as exc:
                self._handle_runtime_redis_error("get", exc)

        fallback = None
        with self._fallback_lock:
            fallback = self._fallback_cache

        if fallback is not None:
            # EXPLICIT_DEGRADED path -- tag result so callers can detect downgrade
            result = fallback.get(dsl_code, variables)
            if result is not None:
                result = copy.deepcopy(result)
                result["_degraded_mode"] = True
                result["_cache_backend"] = "local_degraded"
            return result
            
        return None
'''
content = content.replace(old_get.strip('\n'), new_get.strip('\n'))

# 7. Rewrite set() method
old_set = '''
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

        if self._client is not None:
            try:
                self._client.setex(key, ttl, json.dumps(result))
                
                self._recover_from_fallback()
                return

            except Exception as exc:
                self._handle_runtime_redis_error("set", exc)

        if self._fallback_cache is not None:
            self._fallback_cache.set(dsl_code, result, variables)
'''
new_set = '''
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

        if client is not None:
            try:
                client.setex(key, ttl, json.dumps(result))
                
                self._recover_from_fallback()
                return

            except Exception as exc:
                self._handle_runtime_redis_error("set", exc)

        fallback = None
        with self._fallback_lock:
            fallback = self._fallback_cache

        if fallback is not None:
            fallback.set(dsl_code, result, variables)
'''
content = content.replace(old_set.strip('\n'), new_set.strip('\n'))

# 8. Rewrite invalidate() method
old_inv = '''
    def invalidate(self, dsl_code: str, variables: Optional[list] = None) -> bool:
        """
        Remove a specific entry from cache.

        Raises:
            CacheBackendUnavailableError: in STRICT_DISTRIBUTED mode when
                Redis is unavailable.
        """
        key = self._generate_key(dsl_code, variables)

        if self._client is not None:
            try:
                ret = self._client.delete(key) > 0
                
                self._recover_from_fallback()
                return ret

            except Exception as exc:
                self._handle_runtime_redis_error("invalidate", exc)

        if self._fallback_cache is not None:
            return self._fallback_cache.invalidate(dsl_code, variables)
        return False
'''
new_inv = '''
    def invalidate(self, dsl_code: str, variables: Optional[list] = None) -> bool:
        """
        Remove a specific entry from cache.

        Raises:
            CacheBackendUnavailableError: in STRICT_DISTRIBUTED mode when
                Redis is unavailable.
        """
        key = self._generate_key(dsl_code, variables)
        client = self._try_get_client()

        if client is not None:
            try:
                ret = client.delete(key) > 0
                
                self._recover_from_fallback()
                return ret

            except Exception as exc:
                self._handle_runtime_redis_error("invalidate", exc)

        fallback = None
        with self._fallback_lock:
            fallback = self._fallback_cache

        if fallback is not None:
            return fallback.invalidate(dsl_code, variables)
        return False
'''
content = content.replace(old_inv.strip('\n'), new_inv.strip('\n'))

# 9. Rewrite clear() method
old_clear = '''
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
        if self._client is not None:
            try:
                if pattern is None:
                    pattern = f"{self._cache_keys.VERIFICATION}:*"

                deleted = self._clear_redis_pattern(pattern)

                self._hits = 0
                self._misses = 0

                self._recover_from_fallback()
                return deleted

            except Exception as exc:
                self._handle_runtime_redis_error("clear", exc)

        if self._fallback_cache is not None:
            return self._fallback_cache.clear()
        return 0
'''
new_clear = '''
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
        if client is not None:
            try:
                if pattern is None:
                    pattern = f"{self._cache_keys.VERIFICATION}:*"

                deleted = self._clear_redis_pattern(pattern)

                self._hits = 0
                self._misses = 0

                self._recover_from_fallback()
                return deleted

            except Exception as exc:
                self._handle_runtime_redis_error("clear", exc)

        fallback = None
        with self._fallback_lock:
            fallback = self._fallback_cache

        if fallback is not None:
            return fallback.clear()
        return 0
'''
content = content.replace(old_clear.strip('\n'), new_clear.strip('\n'))

# 10. Fix _clear_redis_pattern to use _try_get_client()
content = content.replace("self._client.scan(cursor", "self._try_get_client().scan(cursor")
content = content.replace("self._client.delete(*keys)", "self._try_get_client().delete(*keys)")

# 11. Fix stats to use _fallback_lock and fix "degraded" boolean
old_stats = '''
    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self._fallback_cache is not None:
            stats = self._fallback_cache.stats
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
                "ttl_seconds": self.ttl_default,
                "enabled": self.enabled,
                "tenant_id": self.tenant_id,
                "memory_used": info.get("used_memory_human", "0B"),
            }
        except Exception:
            return {
                "backend": "redis",
                "mode": self.mode,
                "degraded": self.mode != CacheBackendMode.STRICT_DISTRIBUTED,
                "backend_error": True,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "enabled": self.enabled,
                "tenant_id": self.tenant_id,
            }
'''
new_stats = '''
    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        fallback = None
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
        
        client = self._try_get_client()

        try:
            if client is None:
                raise CacheBackendUnavailableError("Redis is unavailable")
            info = client.info("memory")
            return {
                "backend": "redis",
                "mode": self.mode,
                "degraded": False,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "ttl_seconds": self.ttl_default,
                "enabled": self.enabled,
                "tenant_id": self.tenant_id,
                "memory_used": info.get("used_memory_human", "0B"),
            }
        except Exception:
            # We use fallback is not None for degraded because if fallback is None
            # we are not actually in a degraded state (either strict distributed, or fallback not activated)
            fallback = None
            with self._fallback_lock:
                fallback = self._fallback_cache
            return {
                "backend": "redis",
                "mode": self.mode,
                "degraded": fallback is not None,
                "backend_error": True,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "enabled": self.enabled,
                "tenant_id": self.tenant_id,
            }
'''
content = content.replace(old_stats.strip('\n'), new_stats.strip('\n'))

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)
print("Updated successfully")
