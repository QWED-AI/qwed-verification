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
        self.assertEqual(h1, hash_api_key(sample))
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # sha256 hex
        int(h1, 16)  # valid hex

    def test_generate_api_key_roundtrip(self):
        raw, hashed = generate_api_key()
        self.assertEqual(hashed, hash_api_key(raw))

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
        """The table is hard-bounded: at the cap, a new address is admitted
        only by evicting an EXPIRED first-inserted bucket — never by
        evicting a live one (Greptile P1 round 2, PR #345)."""
        limiter = self._limiter()
        limiter.MAX_TRACKED_IPS = 5
        for i in range(50):
            limiter.check_ip_limit(f"10.0.1.{i}")
        self.assertLessEqual(len(limiter.ip_requests), 5)

    def test_hard_cap_rejects_new_ip_while_front_bucket_live(self):
        """At a full table of live buckets a new address is rejected instead
        of evicting a live bucket — eviction would reset the evicted
        client's budget before its window expires (Greptile P1, PR #345)."""
        limiter = self._limiter()
        limiter.MAX_TRACKED_IPS = 3
        for i in range(3):
            limiter.check_ip_limit(f"10.0.1.{i}")
        allowed, reset = limiter.check_ip_limit_with_reset("10.9.9.9")
        self.assertFalse(allowed)
        self.assertGreaterEqual(reset, 1)
        self.assertLessEqual(reset, limiter.PER_IP_WINDOW)
        # The live bucket survives with its budget intact
        self.assertIn("10.0.1.0", limiter.ip_requests)
        self.assertNotIn("10.9.9.9", limiter.ip_requests)

    def test_hard_cap_evicts_expired_front_bucket(self):
        """An expired first-inserted bucket is evicted in O(1) to admit a
        new address once its window has fully expired."""
        limiter = self._limiter()
        limiter.MAX_TRACKED_IPS = 3
        for i in range(3):
            limiter.check_ip_limit(f"10.0.1.{i}")
        limiter.ip_requests["10.0.1.0"] = [
            limiter._clock() - limiter.PER_IP_WINDOW - 1
        ]
        self.assertTrue(limiter.check_ip_limit("10.9.9.9"))
        self.assertEqual(len(limiter.ip_requests), 3)
        self.assertNotIn("10.0.1.0", limiter.ip_requests)
        self.assertIn("10.9.9.9", limiter.ip_requests)

    def test_nonpositive_per_ip_limit_fails_construction(self):
        """A 0/negative QWED_RATE_LIMIT_PER_IP must fail at construction,
        not 500 every anonymous /auth/* request via min()-of-empty-bucket
        (CodeRabbit on PR #345)."""
        for bad in ("0", "-3"):
            with patch.dict("os.environ", {"QWED_RATE_LIMIT_PER_IP": bad}):
                with self.assertRaises(ValueError):
                    RateLimiter()

    def test_retry_after_never_zero_while_blocked(self):
        """Rounded-up reset (CodeRabbit clock injection): a window with a
        fractional second remaining must report >= 1, never 0."""
        now = [1000.0]
        with patch.dict("os.environ", {"QWED_RATE_LIMIT_PER_IP": "2"}):
            limiter = RateLimiter(clock=lambda: now[0])
        limiter.ip_requests["1.2.3.4"] = [1000.0 - 59.5, 1000.0 - 59.2]
        self.assertFalse(limiter.check_ip_limit("1.2.3.4"))
        self.assertEqual(limiter.get_ip_reset_time("1.2.3.4"), 1)  # ceil(0.5)
        now[0] += 0.4
        self.assertEqual(limiter.get_ip_reset_time("1.2.3.4"), 1)  # ceil(0.1)
        now[0] += 0.6
        self.assertEqual(limiter.get_ip_reset_time("1.2.3.4"), 0)  # expired

    def test_atomic_check_and_reset(self):
        """Blocked check returns the reset time in the same locked call
        (Sentry TOCTOU on PR #345) — and it is never 0 while blocked."""
        limiter = self._limiter(limit=2)
        allowed, reset = limiter.check_ip_limit_with_reset("1.2.3.4")
        self.assertTrue(allowed)
        self.assertEqual(reset, 0)
        limiter.check_ip_limit("1.2.3.4")
        allowed, reset = limiter.check_ip_limit_with_reset("1.2.3.4")
        self.assertFalse(allowed)
        self.assertGreaterEqual(reset, 1)
        self.assertLessEqual(reset, 60)

    def test_check_auth_rate_limit_raises_429(self):
        from fastapi import HTTPException

        limiter = self._limiter(limit=1)
        req = _StubRequest()
        with patch("qwed_new.core.rate_limiter.rate_limiter", limiter):
            check_auth_rate_limit(req)  # first passes
            with self.assertRaises(HTTPException) as ctx:
                check_auth_rate_limit(req)
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("Retry-After", ctx.exception.headers)

    def test_untrusted_peer_header_ignored(self):
        """Default: X-Forwarded-For is NOT honored — the client must not be
        able to choose its rate-limit key (CodeRabbit/CodeAnt on PR #345)."""
        self.assertEqual(
            client_ip_of(_StubRequest(client_host="1.2.3.4", forwarded="9.9.9.9")), "1.2.3.4"
        )

    def test_trusted_proxy_last_hop_wins(self):
        """A trusted proxy appends the real client after client-supplied
        entries, so the rightmost hop is the one our infrastructure saw."""
        import ipaddress
        from qwed_new.core import rate_limiter as rl

        trusted = [ipaddress.ip_network("172.16.0.0/12")]
        with patch.object(rl, "_TRUSTED_PROXIES", trusted):
            req = _StubRequest(client_host="172.16.1.2", forwarded="1.2.3.4, 5.6.7.8")
            self.assertEqual(client_ip_of(req), "5.6.7.8")
            # Untrusted peer even WITH header -> direct peer
            req2 = _StubRequest(client_host="1.2.3.4", forwarded="5.6.7.8")
            self.assertEqual(client_ip_of(req2), "1.2.3.4")
            # Port-suffixed hops normalize to the bare IP (Sentry on PR #345):
            # port rotation must not mint fresh bucket keys
            req3 = _StubRequest(client_host="172.16.1.2", forwarded="1.2.3.4:8080, 5.6.7.8:9091")
            self.assertEqual(client_ip_of(req3), "5.6.7.8")
            req4 = _StubRequest(client_host="172.16.1.2", forwarded="[2001:db8::1]:8080")
            self.assertEqual(client_ip_of(req4), "2001:db8::1")
            # Malformed unterminated bracket must NOT truncate into a
            # different valid address (Sentry on PR #345): [2001:db8::1
            # would slice to 2001:db8:: (a real, different IP)
            req5 = _StubRequest(client_host="172.16.1.2", forwarded="[2001:db8::1")
            self.assertEqual(client_ip_of(req5), "[2001:db8::1")


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


class TestApiKeyLookupSecret(unittest.TestCase):
    """CodeRabbit on PR #345: the lookup MAC is decoupled from the JWT
    secret. QWED_API_KEY_LOOKUP_SECRET is REQUIRED (fail closed) — conftest
    wires deterministic test material, and each test pins the exact env it
    needs so assertions never depend on the ambient process environment."""

    def test_dedicated_secret_changes_digest(self):
        sample = "abc123"
        baseline = hash_api_key(sample)
        with patch.dict("os.environ", {"QWED_API_KEY_LOOKUP_SECRET": "test-dedi-42"}):
            with_dedicated = hash_api_key(sample)
            # Stable while the same dedicated secret is set
            self.assertEqual(with_dedicated, hash_api_key(sample))
        self.assertNotEqual(baseline, with_dedicated)

    def test_changing_the_dedicated_secret_changes_digest(self):
        """Digests must depend on the dedicated secret only — a one-time
        re-issue is expected whenever it changes."""
        sample = "abc123"
        with patch.dict("os.environ", {"QWED_API_KEY_LOOKUP_SECRET": "test-dedi-42"}):
            first = hash_api_key(sample)
        with patch.dict("os.environ", {"QWED_API_KEY_LOOKUP_SECRET": "test-dedi-99"}):
            self.assertNotEqual(first, hash_api_key(sample))

    def test_missing_lookup_secret_fails_closed(self):
        """No fallback: an unset dedicated secret must raise, never silently
        key digests with the JWT secret (CodeRabbit, PR #345 round 2) —
        that fallback also logged a warning on every call (Sentry)."""
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(RuntimeError):
                hash_api_key("abc123")


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

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "guessed-password")
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
