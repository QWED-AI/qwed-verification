"""
Tests for Issue #189: Redis fallback fail-closed fix.

Verifies that:
- STRICT_DISTRIBUTED mode never silently falls back to node-local cache
- EXPLICIT_DEGRADED mode falls back with audit markers and security events
- LOCAL_ONLY mode never touches Redis
- cached_verify() uses LOCAL_ONLY (backward compatible, no breaking change)
- Cross-node isolation is explicit, not silent
"""
import json
import logging
import pytest
from unittest.mock import MagicMock, patch

from qwed_new.core.cache import (
    CacheBackendMode,
    CacheBackendUnavailableError,
    RedisCache,
    VerificationCache,
    get_cache,
    cached_verify,
)
from qwed_new.core.redis_config import reset_redis_state
import qwed_new.core.cache as cache_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# STRICT_DISTRIBUTED: startup Redis down
# ---------------------------------------------------------------------------

class TestStrictDistributedStartupDown:

    def test_raises_on_startup_redis_down(self):
        """STRICT_DISTRIBUTED + Redis unavailable at startup -> raise, never fallback."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            with pytest.raises(CacheBackendUnavailableError) as exc_info:
                RedisCache(mode=CacheBackendMode.STRICT_DISTRIBUTED)

        assert "STRICT_DISTRIBUTED" in str(exc_info.value)
        assert "Fail-closed" in str(exc_info.value)

    def test_error_message_suggests_alternatives(self):
        """Error message must guide caller to EXPLICIT_DEGRADED or LOCAL_ONLY."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            with pytest.raises(CacheBackendUnavailableError) as exc_info:
                RedisCache(mode=CacheBackendMode.STRICT_DISTRIBUTED)

        msg = str(exc_info.value)
        assert "EXPLICIT_DEGRADED" in msg
        assert "LOCAL_ONLY" in msg

    def test_no_fallback_cache_created_on_strict(self):
        """STRICT_DISTRIBUTED must never instantiate a VerificationCache fallback."""
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.STRICT_DISTRIBUTED)

        assert cache._fallback_cache is None


# ---------------------------------------------------------------------------
# STRICT_DISTRIBUTED: runtime Redis error
# ---------------------------------------------------------------------------

class TestStrictDistributedRuntimeError:

    def _make_strict_cache(self):
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.STRICT_DISTRIBUTED)
        cache._client = mock_client
        return cache, mock_client

    def test_get_raises_on_runtime_redis_error(self):
        """Runtime Redis error on get -> raise CacheBackendUnavailableError."""
        cache, mock_client = self._make_strict_cache()
        mock_client.get.side_effect = Exception("connection lost")

        with pytest.raises(CacheBackendUnavailableError) as exc_info:
            cache.get("(= x 1)")

        assert "get" in str(exc_info.value).lower()

    def test_set_raises_on_runtime_redis_error(self):
        """Runtime Redis error on set -> raise CacheBackendUnavailableError."""
        cache, mock_client = self._make_strict_cache()
        mock_client.setex.side_effect = Exception("connection lost")

        with pytest.raises(CacheBackendUnavailableError) as exc_info:
            cache.set("(= x 1)", {"status": "SAT"})

        assert "set" in str(exc_info.value).lower()

    def test_invalidate_raises_on_runtime_redis_error(self):
        """Runtime Redis error on invalidate -> raise CacheBackendUnavailableError."""
        cache, mock_client = self._make_strict_cache()
        mock_client.delete.side_effect = Exception("connection lost")

        with pytest.raises(CacheBackendUnavailableError):
            cache.invalidate("(= x 1)")

    def test_clear_raises_on_runtime_redis_error(self):
        """Runtime Redis error on clear -> raise CacheBackendUnavailableError."""
        cache, mock_client = self._make_strict_cache()
        mock_client.scan.side_effect = Exception("connection lost")

        with pytest.raises(CacheBackendUnavailableError):
            cache.clear()

    def test_strict_never_activates_fallback_on_runtime_error(self):
        """STRICT_DISTRIBUTED must never create _fallback_cache even after runtime error."""
        cache, mock_client = self._make_strict_cache()
        mock_client.get.side_effect = Exception("connection lost")

        with pytest.raises(CacheBackendUnavailableError):
            cache.get("(= x 1)")

        assert cache._fallback_cache is None


# ---------------------------------------------------------------------------
# EXPLICIT_DEGRADED: startup Redis down
# ---------------------------------------------------------------------------

class TestExplicitDegradedStartupDown:

    def test_activates_local_fallback_when_redis_down(self):
        """EXPLICIT_DEGRADED + Redis down -> activates VerificationCache fallback."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)

        assert cache._fallback_cache is not None
        assert isinstance(cache._fallback_cache, VerificationCache)

    def test_emits_security_event_on_startup_fallback(self, caplog):
        """EXPLICIT_DEGRADED fallback activation must emit a structured security event."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            with caplog.at_level(logging.WARNING, logger="qwed.cache.security"):
                RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)

        assert any("BACKEND_UNAVAILABLE_AT_STARTUP" in r.message for r in caplog.records)

    def test_security_event_is_valid_json(self, caplog):
        """Security event payload must be valid JSON for structured log parsing."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            with caplog.at_level(logging.WARNING, logger="qwed.cache.security"):
                RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)

        security_records = [r for r in caplog.records if "BACKEND_UNAVAILABLE" in r.message]
        assert security_records, "No security event emitted"
        event = json.loads(security_records[0].message)
        assert event["event"] == "BACKEND_UNAVAILABLE_AT_STARTUP"
        assert event["mode"] == CacheBackendMode.EXPLICIT_DEGRADED
        assert "timestamp" in event

    def test_get_tags_result_with_degraded_marker(self):
        """Results from fallback path must carry _degraded_mode=True."""
        # Patch for the full test body so _try_get_client() does not
        # reconnect to a real Redis between construction and get().
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
            result = {"status": "SAT", "verified": True}
            cache.set("(= x 1)", result)
            hit = cache.get("(= x 1)")

        assert hit is not None
        assert hit["_degraded_mode"] is True
        assert hit["_cache_backend"] == "local_degraded"

    def test_set_uses_fallback_without_json_serializing_when_redis_down(self):
        """
        EXPLICIT_DEGRADED fallback stores Python objects directly; Redis JSON
        serialization must not run when no Redis client is available.
        """
        sentinel = object()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
            cache.set("(= x 1)", {"status": "SAT", "sentinel": sentinel})
            hit = cache.get("(= x 1)")

        assert hit is not None
        assert "sentinel" in hit
        assert hit["_degraded_mode"] is True
        assert hit["_cache_backend"] == "local_degraded"

    def test_stats_reports_degraded(self):
        """stats() must expose degraded=True when in fallback mode."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)

        s = cache.stats
        assert s["degraded"] is True
        assert s["backend"] == "local_degraded"


# ---------------------------------------------------------------------------
# EXPLICIT_DEGRADED: runtime Redis loss
# ---------------------------------------------------------------------------

class TestExplicitDegradedRuntimeLoss:

    def _make_degraded_cache_healthy_start(self):
        """Cache that starts healthy (Redis up) but will lose it at runtime."""
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
        cache._client = mock_client
        return cache, mock_client

    def test_activates_fallback_on_runtime_redis_loss(self):
        """Redis dies at runtime -> EXPLICIT_DEGRADED activates fallback lazily."""
        cache, mock_client = self._make_degraded_cache_healthy_start()
        mock_client.get.side_effect = Exception("connection reset")

        # Should not raise -- should activate fallback
        result = cache.get("(= x 1)")
        assert result is None  # miss (nothing in fallback yet)
        assert cache._fallback_cache is not None

    def test_emits_security_event_on_runtime_loss(self, caplog):
        """Runtime Redis loss -> security event emitted."""
        cache, mock_client = self._make_degraded_cache_healthy_start()
        mock_client.get.side_effect = Exception("connection reset")

        with caplog.at_level(logging.WARNING, logger="qwed.cache.security"):
            cache.get("(= x 1)")

        assert any("BACKEND_UNAVAILABLE_AT_RUNTIME" in r.message for r in caplog.records)

    def test_cross_node_isolation_is_explicit_not_silent(self):
        """
        Two EXPLICIT_DEGRADED nodes with separate fallback caches produce
        divergent state -- but the divergence is EXPLICIT via the degraded marker,
        not silent.

        This test documents the known limitation: cross-node consistency is
        lost in EXPLICIT_DEGRADED. The audit marker is the explicit signal.
        """
        # Patch for the full test body — keeps Redis unavailable for all
        # get()/set() calls so _try_get_client() stays in cooldown.
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            # Node A: Redis down, writes to fallback
            node_a = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
            node_a.set("(= x 1)", {"status": "SAT", "verified": True})
            hit_a = node_a.get("(= x 1)")

            # Node B: own fallback — does not see A's data
            node_b = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
            hit_b = node_b.get("(= x 1)")

        # A has data, B doesn't -- divergence exists
        assert hit_a is not None
        assert hit_b is None  # cross-node isolation broken (expected, documented)

        # But A's result is explicitly marked as degraded -- not silent
        assert hit_a["_degraded_mode"] is True
        assert hit_a["_cache_backend"] == "local_degraded"


# ---------------------------------------------------------------------------
# LOCAL_ONLY: never touches Redis
# ---------------------------------------------------------------------------

class TestLocalOnlyMode:

    def test_local_only_never_calls_get_redis_client(self):
        """LOCAL_ONLY must never attempt a Redis connection."""
        with patch("qwed_new.core.redis_config.get_redis_client") as mock_get:
            cache = get_cache(use_redis=False, mode=CacheBackendMode.LOCAL_ONLY)

        mock_get.assert_not_called()
        assert isinstance(cache, VerificationCache)

    def test_local_only_consistent_within_process(self):
        """LOCAL_ONLY provides consistent state within a single process."""
        cache = VerificationCache()
        cache.set("(= x 1)", {"status": "SAT"})
        result = cache.get("(= x 1)")
        assert result is not None
        assert result["status"] == "SAT"


# ---------------------------------------------------------------------------
# get_cache() contract
# ---------------------------------------------------------------------------

class TestGetCacheContract:

    def setup_method(self):
        # Reset global singletons between tests
        cache_mod._verification_caches.clear()
        cache_mod._redis_caches.clear()
        cache_mod._redis_cache_retry_after.clear()
        reset_redis_state()

    def test_strict_distributed_raises_when_redis_down(self):
        """get_cache(mode=STRICT_DISTRIBUTED) + Redis down -> raise."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            with pytest.raises(CacheBackendUnavailableError):
                get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)

    def test_local_only_returns_verification_cache(self):
        """get_cache(use_redis=False) returns plain VerificationCache."""
        cache = get_cache(use_redis=False, mode=CacheBackendMode.LOCAL_ONLY)
        assert isinstance(cache, VerificationCache)

    def test_explicit_degraded_returns_redis_cache_in_degraded_state(self):
        """get_cache(mode=EXPLICIT_DEGRADED) + Redis down -> RedisCache in fallback."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            cache = get_cache(use_redis=True, mode=CacheBackendMode.EXPLICIT_DEGRADED)

        assert isinstance(cache, RedisCache)
        assert cache._fallback_cache is not None

    def test_default_mode_is_strict_distributed(self):
        """get_cache() default mode is STRICT_DISTRIBUTED (fail-closed by default)."""
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            with pytest.raises(CacheBackendUnavailableError):
                get_cache(use_redis=True)  # no mode arg -> STRICT_DISTRIBUTED


# ---------------------------------------------------------------------------
# cached_verify() backward compat
# ---------------------------------------------------------------------------

class TestCachedVerifyBackwardCompat:

    def setup_method(self):
        cache_mod._verification_caches.clear()
        cache_mod._redis_caches.clear()

    def test_cached_verify_uses_local_only_no_redis(self):
        """cached_verify() must never attempt Redis connection."""
        with patch("qwed_new.core.redis_config.get_redis_client") as mock_get:
            result = cached_verify(
                "(= x 1)",
                verify_fn=lambda: {"status": "SAT", "verified": True}
            )

        mock_get.assert_not_called()
        assert result["status"] == "SAT"

    def test_cached_verify_caches_on_second_call(self):
        """cached_verify() returns cached result on second call."""
        cache_mod._verification_caches.clear()

        call_count = 0
        def compute():
            nonlocal call_count
            call_count += 1
            return {"status": "SAT", "verified": True}

        cached_verify("(= x 42)", verify_fn=compute)
        cached_verify("(= x 42)", verify_fn=compute)

        assert call_count == 1  # second call served from cache

    def test_cached_verify_no_degraded_marker(self):
        """LOCAL_ONLY results must not carry _degraded_mode marker."""
        cache_mod._verification_caches.clear()

        r1 = cached_verify("(= y 7)", verify_fn=lambda: {"status": "SAT"})
        assert "_degraded_mode" not in r1

        # Cache hit also clean
        r2 = cached_verify("(= y 7)", verify_fn=lambda: {"status": "SAT"})
        assert "_degraded_mode" not in r2


# ---------------------------------------------------------------------------
# RedisCache rejects LOCAL_ONLY at construction
# ---------------------------------------------------------------------------

class TestRedisCacheLocalOnlyRejected:

    def test_redis_cache_raises_on_local_only_mode(self):
        """RedisCache(mode=LOCAL_ONLY) must raise ValueError -- misuse guard."""
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            with pytest.raises(ValueError) as exc_info:
                RedisCache(mode=CacheBackendMode.LOCAL_ONLY)

        assert "LOCAL_ONLY" in str(exc_info.value)
        assert "VerificationCache" in str(exc_info.value)

    def test_redis_cache_raises_before_connecting_on_local_only(self):
        """LOCAL_ONLY guard fires before any Redis connection attempt."""
        with patch("qwed_new.core.redis_config.get_redis_client") as mock_get:
            with pytest.raises(ValueError):
                RedisCache(mode=CacheBackendMode.LOCAL_ONLY)
        # get_redis_client must NOT have been called
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# VerificationCache __len__ and __contains__ correctness
# ---------------------------------------------------------------------------

class TestVerificationCacheContains:

    def test_contains_returns_false_for_missing_key(self):
        cache = VerificationCache()
        assert ("(= x 1)" in cache) is False

    def test_contains_returns_true_for_present_key(self):
        cache = VerificationCache()
        cache.set("(= x 1)", {"status": "SAT"})
        assert ("(= x 1)" in cache) is True

    def test_contains_returns_false_for_expired_entry(self):
        """__contains__ must respect TTL -- expired entries are not present."""
        cache = VerificationCache(ttl_seconds=-1)  # negative TTL guarantees immediate expiry
        cache.set("(= x 1)", {"status": "SAT"})
        # ttl=0 means immediately expired
        assert ("(= x 1)" in cache) is False

    def test_len_reflects_live_entries(self):
        cache = VerificationCache()
        assert len(cache) == 0
        cache.set("(= x 1)", {"status": "SAT"})
        assert len(cache) == 1


# ---------------------------------------------------------------------------
# Redis Recovery from Runtime Loss
# ---------------------------------------------------------------------------

class TestRedisRecovery:

    def _make_degraded_cache(self):
        """Build a RedisCache in EXPLICIT_DEGRADED with a live mock client."""
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
        # Inject client directly — bypasses _try_get_client cooldown so
        # the test can exercise the recovery path synchronously.
        cache._client = mock_client
        return cache, mock_client

    def test_recovers_when_redis_returns(self, caplog):
        """If Redis fails and then recovers, fallback must be cleared."""
        cache, mock_client = self._make_degraded_cache()

        # 1. Healthy
        mock_client.get.return_value = '{"status": "SAT"}'
        assert cache.get("(= x 1)")["status"] == "SAT"

        # 2. Redis dies -> activates fallback
        mock_client.get.side_effect = Exception("connection reset")
        cache.get("(= x 1)")
        assert cache._fallback_cache is not None

        # 3. Redis recovers -- _handle_runtime_redis_error set self._client = None
        # and applied a cooldown. Re-inject the mock and reset cooldown to simulate
        # Redis coming back without patching get_redis_client().
        cache._client = mock_client
        cache._client_retry_after = 0.0
        mock_client.get.side_effect = None
        mock_client.get.return_value = '{"status": "UNSAT"}'

        with caplog.at_level(logging.WARNING, logger="qwed.cache.security"):
            res = cache.get("(= x 1)")

        # Result is from Redis now, no degraded marker
        assert res["status"] == "UNSAT"
        assert "_degraded_mode" not in res
        
        # Fallback cache must be cleared to exit degraded mode
        assert cache._fallback_cache is None
        
        # Security event must be emitted
        assert any("BACKEND_RECOVERED" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# stats() edge cases
# ---------------------------------------------------------------------------

class TestStatsEdgeCases:

    def test_stats_reports_backend_error_on_strict_distributed(self):
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.STRICT_DISTRIBUTED)
        cache._client = mock_client
        mock_client.info.side_effect = Exception("timeout")

        s = cache.stats
        assert s["backend_error"] is True
        assert s["degraded"] is False  # strict distributed never degrades

    def test_stats_reports_degraded_on_explicit_degraded_error(self):
        # Redis was up at init (mock_client returned), so _fallback_cache is None.
        # If info() throws, degraded = _fallback_cache is not None = False.
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
        cache._client = mock_client
        mock_client.info.side_effect = Exception("timeout")

        s = cache.stats
        assert s["backend_error"] is True
        assert s["degraded"] is False  # no fallback is active

    def test_stats_reports_degraded_true_when_fallback_active(self):
        # Redis down at init -> _fallback_cache activated -> degraded = True
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
        assert cache._fallback_cache is not None

        # stats() when fallback is active returns the fallback cache's stats dict
        # with backend="local_degraded" and degraded=True
        s = cache.stats
        assert s["degraded"] is True
        assert s["backend"] == "local_degraded"


# ---------------------------------------------------------------------------
# Tenant isolation in LOCAL_ONLY / no-redis path
# ---------------------------------------------------------------------------

class TestTenantIsolation:

    def setup_method(self, _):
        cache_mod._verification_caches.clear()
        cache_mod._redis_caches.clear()
        cache_mod._redis_cache_retry_after.clear()
        cache_mod._constructing_events.clear()
        reset_redis_state()

    def test_different_tenants_get_different_caches(self):
        """Each tenant_id must return a distinct VerificationCache instance."""
        c1 = get_cache(use_redis=False, tenant_id=1)
        c2 = get_cache(use_redis=False, tenant_id=2)
        assert c1 is not c2

    def test_same_tenant_returns_same_instance(self):
        c1 = get_cache(use_redis=False, tenant_id=1)
        c2 = get_cache(use_redis=False, tenant_id=1)
        assert c1 is c2

    def test_tenant_a_data_invisible_to_tenant_b(self):
        """Cache entries stored for tenant A must not appear for tenant B."""
        c1 = get_cache(use_redis=False, tenant_id=1)
        c1.set("(= x 1)", {"status": "SAT"})

        c2 = get_cache(use_redis=False, tenant_id=2)
        assert c2.get("(= x 1)") is None


# ---------------------------------------------------------------------------
# VerificationCache deep-copy boundary tests
# ---------------------------------------------------------------------------

class TestVerificationCacheDeepCopy:

    def test_mutating_returned_result_does_not_corrupt_cache(self):
        """get() must return a deep copy; mutating it must not affect the store."""
        cache = VerificationCache()
        cache.set("(= x 1)", {"status": "SAT", "meta": {"a": 1}})

        result = cache.get("(= x 1)")
        result["meta"]["a"] = 999  # mutate nested object

        result2 = cache.get("(= x 1)")
        assert result2["meta"]["a"] == 1  # original must be untouched

    def test_mutating_stored_dict_does_not_corrupt_cache(self):
        """set() must store a deep copy; mutating the input after set must not affect cache."""
        original = {"status": "SAT", "meta": {"b": 2}}
        cache = VerificationCache()
        cache.set("(= x 2)", original)

        original["meta"]["b"] = 888  # mutate original after set

        result = cache.get("(= x 2)")
        assert result["meta"]["b"] == 2  # cache must hold the original value


# ---------------------------------------------------------------------------
# _recover_from_fallback — only emits event on real state transition
# ---------------------------------------------------------------------------

class TestRecoverFromFallbackOnTransition:

    def test_no_event_when_no_fallback_was_active(self, caplog):
        """_recover_from_fallback must be a no-op when fallback is not active."""
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.STRICT_DISTRIBUTED)
        cache._client = mock_client

        with caplog.at_level(logging.WARNING, logger="qwed.cache.security"):
            cache._recover_from_fallback()

        events = [r.message for r in caplog.records if "BACKEND_RECOVERED" in r.message]
        assert len(events) == 0, "No event expected when fallback was never active"

    def test_event_emitted_only_on_first_recovery(self, caplog):
        """BACKEND_RECOVERED event must appear exactly once when fallback transitions to None."""
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            cache = RedisCache(mode=CacheBackendMode.EXPLICIT_DEGRADED)
        cache._client = mock_client

        with caplog.at_level(logging.WARNING, logger="qwed.cache.security"):
            cache._recover_from_fallback()  # real transition
            cache._recover_from_fallback()  # should be no-op now

        events = [r.message for r in caplog.records if "BACKEND_RECOVERED" in r.message]
        assert len(events) == 1, f"Expected exactly 1 BACKEND_RECOVERED event, got {len(events)}"


# ---------------------------------------------------------------------------
# STRICT_DISTRIBUTED fail-closed during cooldown
# ---------------------------------------------------------------------------

class TestStrictDistributedCooldownFailClosed:
    """
    After a runtime Redis error, _handle_runtime_redis_error sets self._client = None
    and starts a 30-second cooldown. During that window, _try_get_client() returns None.
    All public methods must still raise CacheBackendUnavailableError, never silently
    returning None / False / 0 — that would break the fail-closed contract.
    """

    def _make_strict_cache_with_dead_client(self):
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            cache = RedisCache(mode=CacheBackendMode.STRICT_DISTRIBUTED)
        # Put client into cooldown (as _handle_runtime_redis_error would)
        cache._client = None
        cache._client_retry_after = float("inf")  # Never retry in this test
        return cache

    def test_get_raises_during_cooldown(self):
        cache = self._make_strict_cache_with_dead_client()
        with pytest.raises(CacheBackendUnavailableError):
            cache.get("(= x 1)")

    def test_set_raises_during_cooldown(self):
        cache = self._make_strict_cache_with_dead_client()
        with pytest.raises(CacheBackendUnavailableError):
            cache.set("(= x 1)", {"status": "SAT"})

    def test_invalidate_raises_during_cooldown(self):
        cache = self._make_strict_cache_with_dead_client()
        with pytest.raises(CacheBackendUnavailableError):
            cache.invalidate("(= x 1)")

    def test_clear_raises_during_cooldown(self):
        cache = self._make_strict_cache_with_dead_client()
        with pytest.raises(CacheBackendUnavailableError):
            cache.clear()


# ---------------------------------------------------------------------------
# get_cache() anti-hammering cooldown
# ---------------------------------------------------------------------------

class TestGetCacheAntiHammering:

    def setup_method(self, _):
        cache_mod._verification_caches.clear()
        cache_mod._redis_caches.clear()
        cache_mod._redis_cache_retry_after.clear()
        cache_mod._constructing_events.clear()
        reset_redis_state()

    def test_second_call_raises_immediately_without_reconnect(self):
        """
        If STRICT_DISTRIBUTED construction fails, the second get_cache() call must
        raise CacheBackendUnavailableError without attempting a new connection
        (avoids hammering Redis and holding the factory lock).
        """
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
            with pytest.raises(CacheBackendUnavailableError):
                get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)

        # Second call — still in cooldown window — must NOT call get_redis_client()
        with patch("qwed_new.core.redis_config.get_redis_client") as mock_grk:
            with pytest.raises(CacheBackendUnavailableError):
                get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)
            mock_grk.assert_not_called()

    def test_successful_construction_is_cached(self):
        """Successful RedisCache is reused across get_cache() calls."""
        mock_client = MagicMock()
        with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
            c1 = get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)
            c2 = get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)
        assert c1 is c2

    def test_generic_construction_error_starts_retry_cooldown(self):
        """
        Non-availability RedisCache construction failures should also enter
        cooldown so repeated callers do not hammer the factory path.
        """
        with patch.object(RedisCache, "__init__", side_effect=ValueError("bad mode")):
            with pytest.raises(ValueError):
                get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)

        cache_key = (None, CacheBackendMode.STRICT_DISTRIBUTED)
        assert cache_mod._redis_cache_retry_after[cache_key] > 0

        with patch.object(RedisCache, "__init__") as mock_init:
            with pytest.raises(CacheBackendUnavailableError):
                get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)
            mock_init.assert_not_called()

    def test_explicit_degraded_waiter_raises_after_construction_failure(self):
        """
        A waiter must not receive a bare unregistered VerificationCache after
        another EXPLICIT_DEGRADED construction attempt fails.
        """
        cache_key = (None, CacheBackendMode.EXPLICIT_DEGRADED)
        cache_mod._redis_cache_retry_after[cache_key] = float("inf")

        with pytest.raises(CacheBackendUnavailableError) as exc_info:
            get_cache(use_redis=True, mode=CacheBackendMode.EXPLICIT_DEGRADED)

        assert "EXPLICIT_DEGRADED" in str(exc_info.value)
        assert "cooldown active" in str(exc_info.value)

    def test_strict_distributed_waiter_timeout_fails_closed(self):
        """STRICT_DISTRIBUTED waiters should fail closed on construction timeout."""
        cache_key = (None, CacheBackendMode.STRICT_DISTRIBUTED)

        class TimeoutEvent:
            def wait(self, timeout):
                return False

        cache_mod._constructing_events[cache_key] = TimeoutEvent()

        with pytest.raises(CacheBackendUnavailableError) as exc_info:
            get_cache(use_redis=True, mode=CacheBackendMode.STRICT_DISTRIBUTED)

        assert "timed out" in str(exc_info.value)

    def test_explicit_degraded_waiter_rechecks_after_timeout(self):
        """
        EXPLICIT_DEGRADED waiters should not hard-fail on a bounded wait timeout;
        they should keep waiting/rechecking until construction completes.
        """
        cache_key = (None, CacheBackendMode.EXPLICIT_DEGRADED)

        class SlowEvent:
            def __init__(self):
                self.calls = 0

            def wait(self, timeout):
                self.calls += 1
                if self.calls == 1:
                    return False
                cache_mod._redis_caches[cache_key] = VerificationCache()
                return True

        event = SlowEvent()
        cache_mod._constructing_events[cache_key] = event

        cache = get_cache(use_redis=True, mode=CacheBackendMode.EXPLICIT_DEGRADED)

        assert isinstance(cache, VerificationCache)
        assert event.calls == 2
