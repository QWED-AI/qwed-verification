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

from qwed_new.auth.security import hash_api_key, generate_api_key, verify_password
from qwed_new.core.rate_limiter import RateLimiter, check_auth_rate_limit, client_ip_of


class TestApiKeyLookupDigest(unittest.TestCase):
    """#333: the lookup digest is a fast keyed MAC."""

    def test_deterministic_and_correct_length(self):
        sample = "abc123"
        h1, h2 = hash_api_key(sample), hash_api_key(sample)
        self.assertEqual(hash_api_key(sample), h1)
        self.assertEqual(h1, h2)
        self.assertEqual(64, len(h1))  # sha256 hex
        int(h1, 16)  # valid hex

    def test_generate_api_key_roundtrip(self):
        raw, hashed = generate_api_key()
        self.assertEqual(hash_api_key(raw), hashed)

    def test_lookup_cost_is_not_a_kdf(self):
        """1000 lookups must be far faster than even a single PBKDF2-100k
        pass (~67ms each). The old code spent ~67ms PER REQUEST here."""
        sample = "garbage-attempted-lookup-input"
        start = time.perf_counter()
        for _ in range(1000):
            hash_api_key(sample)
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

    def test_ip_table_never_exceeds_cap(self):
        """The table is hard-bounded: expired entries are pruned above the
        cap, and at a full cap of fresh buckets the least-recently-active
        one is evicted before a new IP is added."""
        limiter = self._limiter()
        limiter.MAX_TRACKED_IPS = 5
        for i in range(50):
            limiter.check_ip_limit(f"10.0.1.{i}")
        self.assertLessEqual(len(limiter.ip_requests), 5)

    def test_hard_cap_evicts_oldest_active_bucket(self):
        """Always-fresh IPs must not grow the table past the cap: the
        least-recently-active bucket is evicted (CodeRabbit/CodeAnt)."""
        limiter = self._limiter()
        limiter.MAX_TRACKED_IPS = 3
        for i in range(3):
            limiter.check_ip_limit(f"10.0.0.{i}")
        # Make 10.0.0.0 the least-recently-active
        stamps = limiter.ip_requests["10.0.0.0"]
        stamps[-1] -= 10
        limiter.check_ip_limit("10.9.9.9")  # brand-new IP at full cap
        self.assertEqual(3, len(limiter.ip_requests))
        self.assertNotIn("10.0.0.0", limiter.ip_requests)
        self.assertIn("10.9.9.9", limiter.ip_requests)

    def test_retry_after_never_zero_while_blocked(self):
        """Rounded-up reset (CodeRabbit clock injection): a window with a
        fractional second remaining must report >= 1, never 0."""
        now = [1000.0]
        limiter = RateLimiter(clock=lambda: now[0])
        with patch.dict("os.environ", {"QWED_RATE_LIMIT_PER_IP": "2"}):
            limiter = RateLimiter(clock=lambda: now[0])
        limiter.ip_requests["1.2.3.4"] = [1000.0 - 59.5, 1000.0 - 59.2]
        self.assertFalse(limiter.check_ip_limit("1.2.3.4"))
        self.assertEqual(1, limiter.get_ip_reset_time("1.2.3.4"))  # ceil(0.5)
        now[0] += 0.4
        self.assertEqual(1, limiter.get_ip_reset_time("1.2.3.4"))  # ceil(0.1)
        now[0] += 0.6
        self.assertEqual(0, limiter.get_ip_reset_time("1.2.3.4"))  # expired

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

    def test_untrusted_peer_header_ignored(self):
        """Default: X-Forwarded-For is NOT honored — the client must not be
        able to choose its rate-limit key (CodeRabbit/CodeAnt on PR #345)."""
        self.assertEqual(
            "1.2.3.4", client_ip_of(_StubRequest(client_host="1.2.3.4", forwarded="9.9.9.9"))
        )

    def test_trusted_proxy_last_hop_wins(self):
        """A trusted proxy appends the real client after client-supplied
        entries, so the rightmost hop is the one our infrastructure saw."""
        import ipaddress
        from qwed_new.core import rate_limiter as rl

        trusted = [ipaddress.ip_network("10.0.0.0/8")]
        with patch.object(rl, "_TRUSTED_PROXIES", trusted):
            req = _StubRequest(client_host="10.1.2.3", forwarded="1.2.3.4, 5.6.7.8")
            self.assertEqual("5.6.7.8", client_ip_of(req))
            # Untrusted peer even WITH header -> direct peer
            req2 = _StubRequest(client_host="1.2.3.4", forwarded="5.6.7.8")
            self.assertEqual("1.2.3.4", client_ip_of(req2))
            # Port-suffixed hops normalize to the bare IP (Sentry on PR #345):
            # port rotation must not mint fresh bucket keys
            req3 = _StubRequest(client_host="10.1.2.3", forwarded="1.2.3.4:8080, 5.6.7.8:9091")
            self.assertEqual("5.6.7.8", client_ip_of(req3))
            req4 = _StubRequest(client_host="10.1.2.3", forwarded="[2001:db8::1]:8080")
            self.assertEqual("2001:db8::1", client_ip_of(req4))


    def test_get_ip_reset_time_unknown_ip_is_zero(self):
        limiter = self._limiter()
        assert limiter.get_ip_reset_time("nobody") == 0

    def test_expired_jwt_returns_none(self):
        """Covers the ExpiredSignatureError branch of decode_access_token."""
        from datetime import timedelta
        from qwed_new.auth.security import create_access_token, decode_access_token

        token = create_access_token(
            {"sub": "u1"}, expires_delta=timedelta(minutes=-5)
        )
        assert decode_access_token(token) is None


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
