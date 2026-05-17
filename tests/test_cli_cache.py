"""
Smoke test for VerificationCache context-bound API.

Updated for Issue #187: get/set now require a CacheContext argument.
"""

import sys
sys.path.insert(0, ".")

from qwed_sdk.cache import CacheContext, VerificationCache

print("=" * 60)
print("🧪 Testing VerificationCache (context-bound, Issue #187)")
print("=" * 60)

ctx = CacheContext(provider="openai", model="gpt-4o", policy_version="v1")

# Test 1: Cache Basic Functionality
print("\n1️⃣ Testing Cache...")
cache = VerificationCache()
cache.clear()
print("  ✅ Cache cleared (starting fresh)")

# Cache miss
result = cache.get("2+2", ctx)
assert result is None, "Should be cache MISS"
print("  ✅ Cache MISS works")

# Set cache
cache.set("2+2", {"verified": True, "value": 4, "confidence": 1.0, "evidence": {}}, ctx)
print("  ✅ Cache SET works")

# Cache hit
result = cache.get("2+2", ctx)
assert result is not None, "Should be cache HIT"
assert result["value"] == 4, "Value should be 4"
print("  ✅ Cache HIT works")

# Query normalization (case) — use a word query where case actually changes
cache.set("Verify Math Query", {"verified": True, "value": "ok"}, ctx)
result = cache.get("verify math query", ctx)   # lowercase lookup
assert result is not None, "Should normalize case"
print("  ✅ Case normalization works")

# Whitespace normalization
cache.set("   Test   Query   ", {"verified": True, "value": "test"}, ctx)
result = cache.get("test query", ctx)
assert result is not None, "Should normalize whitespace"
print("  ✅ Whitespace normalization works")

# Context mismatch → miss
ctx_b = CacheContext(provider="claude", model="claude-opus-4-5", policy_version="v1")
result = cache.get("2+2", ctx_b)
assert result is None, "Cross-context lookup must be a miss"
print("  ✅ Cross-context miss works (replay prevention)")

# Print stats
print("\n📊 Cache Stats:")
cache.print_stats()

cache.clear()
print("✅ Cache cleared")

print("\n" + "=" * 60)
print("✅ All automated tests PASSED!")
print("=" * 60)
