"""
QWED Cache Module — Context-bound caching for verification results.

Verification cache entries are context-bound: a cache hit requires an exact
match of both the normalized query **and** all trust-bound context dimensions
(provider, model, policy version, tenant/session scope).  A mismatch on any
dimension is a deterministic cache miss — the cache never returns a result
across trust boundaries.

This design prevents cross-context replay of verification artifacts (Issue #187).
"""

import sqlite3
import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Public context type
# ---------------------------------------------------------------------------

@dataclass
class CacheContext:
    """Trust-bound context dimensions required for every cache operation.

    All fields participate in the cache key.  Omitting or changing any field
    causes a deterministic cache miss — the cache never falls back to a
    query-only match.

    Attributes:
        provider:        Provider / API endpoint identifier (e.g. "openai").
        model:           Model / deployment name (e.g. "gpt-4o").
        policy_version:  Verifier policy version string (e.g. "v1").
        tenant_id:       Optional tenant or session scope identifier.
        env_fingerprint: Optional environment / config fingerprint for
                         additional binding.
    """
    provider: str
    model: str
    policy_version: str
    tenant_id: Optional[str] = None
    env_fingerprint: Optional[str] = None

    def canonical_dict(self) -> Dict[str, Any]:
        """Return a deterministic dict for key derivation."""
        return {
            "provider": self.provider,
            "model": self.model,
            "policy_version": self.policy_version,
            "tenant_id": self.tenant_id,
            "env_fingerprint": self.env_fingerprint,
        }


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    total_entries: int = 0
    cache_size_bytes: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


# ---------------------------------------------------------------------------
# VerificationCache
# ---------------------------------------------------------------------------

class VerificationCache:
    """Context-bound cache for verification results.

    Cache hits require an exact match of both the normalized query **and**
    the trust-bound :class:`CacheContext`.  A mismatch on any context
    dimension is a deterministic cache miss.  This prevents cross-session,
    cross-provider, and cross-policy replay of verification artifacts.

    Legacy entries stored without a context fingerprint are **never** returned.

    Example::

        from qwed_sdk.cache import CacheContext, VerificationCache

        ctx = CacheContext(provider="openai", model="gpt-4o", policy_version="v1")
        cache = VerificationCache()

        result = cache.get("2+2", ctx)       # None (miss)
        cache.set("2+2", {"verified": True}, ctx)
        result = cache.get("2+2", ctx)       # hit

        # Different context — deterministic miss (replay prevention)
        ctx2 = CacheContext(provider="claude", model="claude-opus-4-5", policy_version="v1")
        result = cache.get("2+2", ctx2)      # None
    """

    DEFAULT_TTL = 86400   # 24 hours
    MAX_ENTRIES = 1000

    def __init__(self, cache_dir: Optional[str] = None, ttl: int = DEFAULT_TTL):
        """Initialize cache.

        Args:
            cache_dir: Directory for cache DB (default: ~/.qwed/cache).
            ttl:       Time-to-live in seconds (default: 24 hours).
        """
        self.ttl = ttl

        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".qwed" / "cache"

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "verifications.db"

        self.stats = CacheStats()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Initialize SQLite database with the v2 context-bound schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # v2 table: composite PRIMARY KEY (key, context_fingerprint) ensures
        # that identical queries stored under different contexts never collide.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache_v2 (
                key                 TEXT NOT NULL,
                context_fingerprint TEXT NOT NULL,
                query               TEXT NOT NULL,
                context_json        TEXT NOT NULL,
                result              TEXT NOT NULL,
                created_at          INTEGER NOT NULL,
                accessed_at         INTEGER NOT NULL,
                access_count        INTEGER DEFAULT 1,
                PRIMARY KEY (key, context_fingerprint)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_v2_created_at
            ON cache_v2(created_at)
        """)

        conn.commit()
        conn.close()
        self._update_stats()

    def _normalize_query(self, query: str) -> str:
        """Normalize query for consistent caching."""
        return " ".join(query.lower().strip().split())

    def _hash_query(self, query: str) -> str:
        """Generate SHA-256 hash for the normalized query."""
        normalized = self._normalize_query(query)
        return hashlib.sha256(normalized.encode()).hexdigest()

    def _hash_context(self, context: CacheContext) -> str:
        """Generate SHA-256 hash for the canonical context dict."""
        canonical = json.dumps(
            context.canonical_dict(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, query: str, context: CacheContext) -> Optional[Dict[str, Any]]:
        """Return cached result for (query, context) or ``None`` on miss.

        A miss is returned when:
        - No entry exists for this (query, context) pair.
        - The entry has expired (TTL).
        - The stored context fingerprint does not match *context* (replay guard).

        Args:
            query:   The verification query string.
            context: Trust-bound context that must match exactly.

        Returns:
            The cached result dict, or ``None`` on any miss.
        """
        key = self._hash_query(query)
        ctx_fp = self._hash_context(context)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT result, created_at, access_count, context_fingerprint
            FROM cache_v2
            WHERE key = ? AND context_fingerprint = ?
        """, (key, ctx_fp))

        row = cursor.fetchone()

        if not row:
            conn.close()
            self.stats.misses += 1
            return None

        result_json, created_at, access_count, stored_fp = row

        # Re-validate fingerprint (defence-in-depth)
        if stored_fp != ctx_fp:
            conn.close()
            self.stats.misses += 1
            return None

        # TTL check
        age = time.time() - created_at
        if age > self.ttl:
            cursor.execute(
                "DELETE FROM cache_v2 WHERE key = ? AND context_fingerprint = ?",
                (key, ctx_fp),
            )
            conn.commit()
            conn.close()
            self.stats.misses += 1
            return None

        cursor.execute("""
            UPDATE cache_v2
            SET accessed_at = ?, access_count = ?
            WHERE key = ? AND context_fingerprint = ?
        """, (int(time.time()), access_count + 1, key, ctx_fp))

        conn.commit()
        conn.close()

        self.stats.hits += 1
        return json.loads(result_json)

    def set(self, query: str, result: Dict[str, Any], context: CacheContext) -> None:
        """Store a verification result bound to (query, context).

        Args:
            query:   The verification query string.
            result:  Verification result dict to cache.
            context: Trust-bound context to bind this entry to.
        """
        key = self._hash_query(query)
        ctx_fp = self._hash_context(context)
        normalized = self._normalize_query(query)
        result_json = json.dumps(result)
        context_json = json.dumps(context.canonical_dict(), sort_keys=True)
        now = int(time.time())

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO cache_v2
                (key, context_fingerprint, query, context_json, result,
                 created_at, accessed_at, access_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """, (key, ctx_fp, normalized, context_json, result_json, now, now))

        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM cache_v2")
        count = cursor.fetchone()[0]

        if count > self.MAX_ENTRIES:
            to_remove = count - self.MAX_ENTRIES
            cursor.execute("""
                DELETE FROM cache_v2
                WHERE (key, context_fingerprint) IN (
                    SELECT key, context_fingerprint FROM cache_v2
                    ORDER BY accessed_at ASC
                    LIMIT ?
                )
            """, (to_remove,))
            conn.commit()

        conn.close()
        self._update_stats()

    def clear(self) -> None:
        """Clear all cached entries."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cache_v2")
        conn.commit()
        conn.close()
        self.stats = CacheStats()
        self._update_stats()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def _update_stats(self) -> None:
        """Update cache statistics from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cache_v2")
        self.stats.total_entries = cursor.fetchone()[0]
        cursor.execute("SELECT SUM(LENGTH(result)) FROM cache_v2")
        size = cursor.fetchone()[0]
        self.stats.cache_size_bytes = size or 0
        conn.close()

    def get_stats(self) -> CacheStats:
        """Return current cache statistics."""
        self._update_stats()
        return self.stats

    def print_stats(self) -> None:
        """Print cache statistics."""
        stats = self.get_stats()

        brand = info = success = value = reset = ""
        has_color = False
        try:
            from colorama import Fore, Style, init
            init(autoreset=True)
            brand = Fore.MAGENTA + Style.BRIGHT
            info = Fore.CYAN
            success = Fore.GREEN + Style.BRIGHT
            value = Fore.BLUE + Style.BRIGHT
            reset = Style.RESET_ALL
            has_color = True
        except ImportError:
            has_color = False

        if has_color:
            print(f"\n{brand}📊 Cache Statistics{reset}")
            print(f"{info}Hits:{reset} {success}{stats.hits}{reset}")
            print(f"{info}Misses:{reset} {stats.misses}")
            print(f"{info}Hit Rate:{reset} {value}{stats.hit_rate:.1%}{reset}")
            print(f"{info}Total Entries:{reset} {stats.total_entries}/{self.MAX_ENTRIES}")
            print(f"{info}Cache Size:{reset} {stats.cache_size_bytes / 1024:.1f} KB\n")
        else:
            print("\n📊 Cache Statistics")
            print(f"Hits: {stats.hits}")
            print(f"Misses: {stats.misses}")
            print(f"Hit Rate: {stats.hit_rate:.1%}")
            print(f"Total Entries: {stats.total_entries}/{self.MAX_ENTRIES}")
            print(f"Cache Size: {stats.cache_size_bytes / 1024:.1f} KB\n")
