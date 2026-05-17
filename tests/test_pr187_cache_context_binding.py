"""
Regression tests for Issue #187:
VerificationCache cache key is query-only, enabling cross-context replay.

Acceptance criteria:
- Cache hit occurs ONLY when query and all context-bound fields match exactly.
- Context mismatch always yields miss.
- Legacy (query-only) entries are never auto-trusted.
- Tests cover provider switch, policy version change, session/tenant change.
"""

import pytest
from pathlib import Path

from qwed_sdk.cache import CacheContext, VerificationCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx(**overrides) -> CacheContext:
    defaults = dict(provider="openai", model="gpt-4o", policy_version="v1", tenant_id=None)
    defaults.update(overrides)
    return CacheContext(**defaults)


RESULT_A = {"status": "VERIFIED", "verified": True, "provider": "openai"}
RESULT_B = {"status": "VERIFIED", "verified": True, "provider": "claude"}


# ---------------------------------------------------------------------------
# Core context-binding tests
# ---------------------------------------------------------------------------

class TestContextBinding:
    """Cache key must include all context dimensions, not query alone."""

    def test_hit_on_exact_context_match(self, tmp_path):
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx = _make_ctx()
        cache.set("2+2", RESULT_A, ctx)

        result = cache.get("2+2", ctx)

        assert result is not None
        assert result["verified"] is True

    def test_miss_on_provider_change(self, tmp_path):
        """Provider switch must yield a cache miss — replay prevention."""
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx_a = _make_ctx(provider="openai")
        ctx_b = _make_ctx(provider="claude")

        cache.set("2+2", RESULT_A, ctx_a)
        result = cache.get("2+2", ctx_b)

        assert result is None, "Different provider must not return cached result from provider_a"

    def test_miss_on_model_change(self, tmp_path):
        """Model change must yield a cache miss."""
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx_a = _make_ctx(model="gpt-4o")
        ctx_b = _make_ctx(model="gpt-3.5-turbo")

        cache.set("what is 1+1?", {"verified": True}, ctx_a)
        result = cache.get("what is 1+1?", ctx_b)

        assert result is None

    def test_miss_on_policy_version_change(self, tmp_path):
        """Policy version change must yield a cache miss."""
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx_v1 = _make_ctx(policy_version="v1")
        ctx_v2 = _make_ctx(policy_version="v2")

        cache.set("derivative of x^2", {"verified": True}, ctx_v1)
        result = cache.get("derivative of x^2", ctx_v2)

        assert result is None

    def test_miss_on_tenant_change(self, tmp_path):
        """Tenant/session scope change must yield a cache miss."""
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx_tenant_a = _make_ctx(tenant_id="tenant-alpha")
        ctx_tenant_b = _make_ctx(tenant_id="tenant-beta")

        cache.set("is x > 0?", {"verified": True}, ctx_tenant_a)
        result = cache.get("is x > 0?", ctx_tenant_b)

        assert result is None

    def test_miss_on_env_fingerprint_change(self, tmp_path):
        """Environment fingerprint change must yield a cache miss."""
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx_env1 = _make_ctx(env_fingerprint="hash-abc")
        ctx_env2 = _make_ctx(env_fingerprint="hash-def")

        cache.set("2+2", RESULT_A, ctx_env1)
        result = cache.get("2+2", ctx_env2)

        assert result is None

    def test_same_query_different_context_both_stored_independently(self, tmp_path):
        """Different contexts for the same query must be stored as independent entries."""
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx_a = _make_ctx(provider="openai")
        ctx_b = _make_ctx(provider="claude")

        cache.set("2+2", RESULT_A, ctx_a)
        cache.set("2+2", RESULT_B, ctx_b)

        assert cache.get("2+2", ctx_a)["provider"] == "openai"
        assert cache.get("2+2", ctx_b)["provider"] == "claude"

    def test_query_normalization_still_applies(self, tmp_path):
        """Query normalization (case, whitespace) must still produce a hit within same context."""
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx = _make_ctx()

        cache.set("  2 + 2  ", RESULT_A, ctx)
        result = cache.get("2 + 2", ctx)

        assert result is not None


# ---------------------------------------------------------------------------
# TTL behaviour
# ---------------------------------------------------------------------------

class TestTTL:
    def test_expired_entry_is_a_miss(self, tmp_path, monkeypatch):
        import qwed_sdk.cache as cache_module

        current_time = {"value": 1000.0}
        monkeypatch.setattr(cache_module.time, "time", lambda: current_time["value"])

        cache = VerificationCache(cache_dir=str(tmp_path), ttl=10)
        ctx = _make_ctx()
        cache.set("2+2", RESULT_A, ctx)

        current_time["value"] += 15.0  # advance past TTL
        result = cache.get("2+2", ctx)

        assert result is None


# ---------------------------------------------------------------------------
# Stats and helpers
# ---------------------------------------------------------------------------

class TestStats:
    def test_hit_increments_hit_counter(self, tmp_path):
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx = _make_ctx()
        cache.set("2+2", RESULT_A, ctx)
        cache.get("2+2", ctx)

        assert cache.stats.hits == 1
        assert cache.stats.misses == 0

    def test_miss_increments_miss_counter(self, tmp_path):
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx = _make_ctx()
        cache.get("unseen query", ctx)

        assert cache.stats.hits == 0
        assert cache.stats.misses == 1

    def test_context_mismatch_increments_miss_counter(self, tmp_path):
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx_a = _make_ctx(provider="openai")
        ctx_b = _make_ctx(provider="claude")
        cache.set("2+2", RESULT_A, ctx_a)
        cache.get("2+2", ctx_b)  # context mismatch

        assert cache.stats.misses == 1

    def test_clear_resets_all_entries(self, tmp_path):
        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx = _make_ctx()
        cache.set("2+2", RESULT_A, ctx)
        cache.clear()

        assert cache.get("2+2", ctx) is None
        assert cache.get_stats().total_entries == 0

    def test_print_stats_plain_fallback(self, tmp_path, capsys):
        """print_stats must work without colorama installed."""
        import builtins
        original_import = builtins.__import__

        def fake_import(name, globals_=None, locals_=None, fromlist=(), level=0):
            if name == "colorama":
                raise ImportError("colorama unavailable in test")
            return original_import(name, globals_, locals_, fromlist, level)

        cache = VerificationCache(cache_dir=str(tmp_path))
        ctx = _make_ctx()
        cache.set("2+2", RESULT_A, ctx)

        import unittest.mock as mock
        with mock.patch("builtins.__import__", side_effect=fake_import):
            cache.print_stats()

        output = capsys.readouterr().out
        assert "Cache Statistics" in output
