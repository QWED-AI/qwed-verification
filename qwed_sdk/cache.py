"""
QWED Cache Module - Smart caching for verification results.

Saves API costs and speeds up repeated queries.
Uses SQLite for persistent storage.
"""

import sqlite3
import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
import os


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


class VerificationCache:
    """
    Smart cache for verification results.
    
    Features:
    - SQLite-based persistent storage
    - SHA256 hashing for cache keys
    - TTL (time-to-live) expiration
    - Size limits (max 1000 entries)
    - Query normalization
    
    Example:
        cache = VerificationCache()
        
        # Cache miss (first time)
        result = cache.get("2+2")  # None
        cache.set("2+2", {"verified": True, "value": 4})
        
        # Cache hit (instant!)
        result = cache.get("2+2")  # {"verified": True, "value": 4}
    """
    
    DEFAULT_TTL = 86400  # 24 hours
    MAX_ENTRIES = 1000
    
    def __init__(self, cache_dir: Optional[str] = None, ttl: int = DEFAULT_TTL):
        """
        Initialize cache.
        
        Args:
            cache_dir: Directory for cache DB (default: ~/.qwed/cache)
            ttl: Time-to-live in seconds (default: 24 hours)
        """
        self.ttl = ttl
        
        # Setup cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".qwed" / "cache"
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "verifications.db"
        
        # Stats tracking
        self.stats = CacheStats()
        
        # Initialize database
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database with schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                query TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                accessed_at INTEGER NOT NULL,
                access_count INTEGER DEFAULT 1
            )
        """)
        
        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_created_at 
            ON cache(created_at)
        """)
        
        conn.commit()
        conn.close()
        
        # Update stats
        self._update_stats()
    
    def _normalize_query(self, query: str) -> str:
        """
        Normalize query for consistent caching.
        
        - Lowercase
        - Strip whitespace
        - Remove extra spaces
        """
        return " ".join(query.lower().strip().split())
    
    def _hash_query(self, query: str) -> str:
        """Generate SHA256 hash for query."""
        normalized = self._normalize_query(query)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def get(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Get cached result for query.
        
        Returns None if not found or expired.
        """
        key = self._hash_query(query)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get entry
        cursor.execute("""
            SELECT result, created_at, access_count
            FROM cache
            WHERE key = ?
        """, (key,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            self.stats.misses += 1
            return None
        
        result_json, created_at, access_count = row
        
        # Check TTL
        age = time.time() - created_at
        if age > self.ttl:
            # Expired, delete
            cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()
            conn.close()
            self.stats.misses += 1
            return None
        
        # Update access stats
        cursor.execute("""
            UPDATE cache
            SET accessed_at = ?, access_count = ?
            WHERE key = ?
        """, (int(time.time()), access_count + 1, key))
        
        conn.commit()
        conn.close()
        
        # Cache hit!
        self.stats.hits += 1
        return json.loads(result_json)
    
    def set(self, query: str, result: Dict[str, Any]):
        """
        Cache verification result.
        
        Args:
            query: Original query
            result: Verification result dict
        """
        key = self._hash_query(query)
        normalized = self._normalize_query(query)
        result_json = json.dumps(result)
        now = int(time.time())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert or replace
        cursor.execute("""
            INSERT OR REPLACE INTO cache (key, query, result, created_at, accessed_at)
            VALUES (?, ?, ?, ?, ?)
        """, (key, normalized, result_json, now, now))
        
        conn.commit()
        
        # Check size limit
        cursor.execute("SELECT COUNT(*) FROM cache")
        count = cursor.fetchone()[0]
        
        if count > self.MAX_ENTRIES:
            # Remove oldest entries
            to_remove = count - self.MAX_ENTRIES
            cursor.execute("""
                DELETE FROM cache
                WHERE key IN (
                    SELECT key FROM cache
                    ORDER BY accessed_at ASC
                    LIMIT ?
                )
            """, (to_remove,))
            conn.commit()
        
        conn.close()
        self._update_stats()
    
    def clear(self):
        """Clear all cached entries."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cache")
        conn.commit()
        conn.close()
        
        self.stats = CacheStats()
        self._update_stats()
    
    def _update_stats(self):
        """Update cache statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count entries
        cursor.execute("SELECT COUNT(*) FROM cache")
        self.stats.total_entries = cursor.fetchone()[0]
        
        # Calculate cache size
        cursor.execute("SELECT SUM(LENGTH(result)) FROM cache")
        size = cursor.fetchone()[0]
        self.stats.cache_size_bytes = size or 0
        
        conn.close()
    
    def get_stats(self) -> CacheStats:
        """Get current cache statistics."""
        self._update_stats()
        return self.stats
    
    def print_stats(self):
        """Print cache statistics with colors."""
        stats = self.get_stats()
        
        try:
            from qwed_sdk.qwed_local import QWED, HAS_COLOR
        except:
            HAS_COLOR = False
            class QWED:
                BRAND = INFO = SUCCESS = VALUE = RESET = ""
        
        if HAS_COLOR:
            print(f"\n{QWED.BRAND}📊 Cache Statistics{QWED.RESET}")
            print(f"{QWED.INFO}Hits:{QWED.RESET} {QWED.SUCCESS}{stats.hits}{QWED.RESET}")
            print(f"{QWED.INFO}Misses:{QWED.RESET} {stats.misses}")
            print(f"{QWED.INFO}Hit Rate:{QWED.RESET} {QWED.VALUE}{stats.hit_rate:.1%}{QWED.RESET}")
            print(f"{QWED.INFO}Total Entries:{QWED.RESET} {stats.total_entries}/{self.MAX_ENTRIES}")
            print(f"{QWED.INFO}Cache Size:{QWED.RESET} {stats.cache_size_bytes / 1024:.1f} KB\n")
        else:
            print("\n📊 Cache Statistics")
            print(f"Hits: {stats.hits}")
            print(f"Misses: {stats.misses}")
            print(f"Hit Rate: {stats.hit_rate:.1%}")
            print(f"Total Entries: {stats.total_entries}/{self.MAX_ENTRIES}")
            print(f"Cache Size: {stats.cache_size_bytes / 1024:.1f} KB\n")
