"""
Tests for the unauthenticated hot path hardening (issues #333, #334).

#333: hash_api_key must be a microsecond keyed MAC, not a 100k-iteration
      PBKDF2 on the pre-auth lookup path.
#334: bcrypt must never run on the event loop, and anonymous /auth/*
      routes must be per-IP rate limited with an email-enumeration
      timing equalizer.
"""

import time
import unittest
from unittest.mock import patch

from qwed_new.auth.security import hash_api_key, generate_api_key, hash_password, verify_password
from qwed_new.core.rate_limiter import RateLimiter, check_auth_rate_limit, client_ip_of


class TestApiKeyLookupDigest(unittest.TestCase):
    """#333: the lookup digest is a fast keyed MAC."""

    def test_deterministic_and_correct_length(self):
        key = "qwed_live_abc123"
        h1, h2 = hash_api_key(key), hash_api_key(key)
        self.assertEqual(h1, h2)
        self.assertEqual(64, len(h1))  # sha256 hex
        int(h1, 16)  # valid hex

    def test_generate_api_key_roundtrip(self):
        raw, hashed = generate_api_key()
        self.assertEqual(hashed, hash_api_key(raw))

    def test_lookup_cost_is_not_a_kdf(self):
        """1000 lookups must be far faster than even a single PBKDF2-100k
        pass (~67ms each). The old code spent ~67ms PER REQUEST here."""
        key = "qwed_live_somegarbageattemptedkeyvalue"
        start = time.perf_counter()
        for _ in range(1000):
            hash_api_key(key)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 0.5, f"1000 lookups took {elapsed:.3f}s — KDF regression?")


class _StubRequest:
    """Minimal stand-in for fastapi Request in limiter tests."""

    def __init__(self, client_host="1.2.3.4", forwarded=None):
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}
        self.client = type("C", (), {"host": client_host})()


class TestPerIpAuthRateLimit(unittest.TestCase):
    """#334: anonymous /auth/* routes get a per-IP bucket."""

    def _limiter(self, limit=3):
        with patch.dict("os.environ", {"QWED_RATE_LIMIT_PER_IP": str(limit)}):
            return RateLimiter()

    def test_blocks_after_limit(self):
        limiter = self._limiter(limit=3)
        for _ in range(3):
            self.assertTrue(limiter.check_ip_limit("1.2.3.4"))
        self.assertFalse(limiter.check_ip_limit("1.2.3.4"))
        # Other IPs unaffected
        self.assertTrue(limiter.check_ip_limit("5.6.7.8"))

    def test_window_expiry_allows_again(self):
        limiter = self._limiter(limit=1)
        self.assertTrue(limiter.check_ip_limit("1.2.3.4"))
        self.assertFalse(limiter.check_ip_limit("1.2.3.4"))
        # Age the recorded request out of the window
        limiter.ip_requests["1.2.3.4"][0] -= limiter.PER_IP_WINDOW + 1
        self.assertTrue(limiter.check_ip_limit("1.2.3.4"))

    def test_ip_table_bounded(self):
        """Above the cap, fully-expired IP windows are evicted on write."""
        limiter = self._limiter()
        limiter.MAX_TRACKED_IPS = 3
        for i in range(4):
            limiter.check_ip_limit(f"10.0.0.{i}")
        # Fresh windows survive the prune (only expired entries are dropped)
        self.assertEqual(4, len(limiter.ip_requests))
        # Age every window out, then write again — expired entries evicted
        cutoff = limiter.PER_IP_WINDOW + 1
        for stamps in limiter.ip_requests.values():
            stamps[0] -= cutoff
        limiter.check_ip_limit("10.9.9.9")
        self.assertEqual(1, len(limiter.ip_requests))
        self.assertIn("10.9.9.9", limiter.ip_requests)

    def test_check_auth_rate_limit_raises_429(self):
        from fastapi import HTTPException

        limiter = self._limiter(limit=1)
        req = _StubRequest()
        with patch("qwed_new.core.rate_limiter.rate_limiter", limiter):
            check_auth_rate_limit(req)  # first passes
            with self.assertRaises(HTTPException) as ctx:
                check_auth_rate_limit(req)
        self.assertEqual(429, ctx.exception.status_code)
        self.assertIn("Retry-After", ctx.exception.headers)

    def test_forwarded_for_preferred(self):
        self.assertEqual("9.9.9.9", client_ip_of(_StubRequest(forwarded="9.9.9.9, 10.0.0.1")))
        self.assertEqual("1.2.3.4", client_ip_of(_StubRequest(client_host="1.2.3.4")))


class TestSigninTimingEqualizer(unittest.TestCase):
    """#334: unknown-email signins still burn one bcrypt verify."""

    def test_unknown_email_runs_bcrypt(self):
        from qwed_new.auth import routes
        import asyncio

        calls = []

        def fake_verify(password, hashed):
            calls.append((password, hashed))
            return True

        with patch.object(routes, "verify_password", side_effect=fake_verify):
            asyncio.run(routes._burn_one_bcrypt("guessed-password"))

        self.assertEqual(1, len(calls))
        self.assertEqual("guessed-password", calls[0][0])
        # The dummy hash is a real bcrypt hash of the equalizer secret
        self.assertTrue(calls[0][1].startswith("$2"))

    def test_dummy_hash_is_valid_bcrypt_hash(self):
        from qwed_new.auth import routes
        import asyncio

        asyncio.run(routes._burn_one_bcrypt("x"))
        self.assertTrue(verify_password("qwed-timing-equalizer", routes._dummy_password_hash))
        self.assertFalse(verify_password("wrong", routes._dummy_password_hash))


if __name__ == "__main__":
    unittest.main()
