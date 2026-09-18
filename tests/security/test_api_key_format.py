"""Tests for the v2 checksummed API-key format (issue #366).

v2: ``qwed_live_<30 Base62 random><6 Base62 CRC32 checksum>`` — validatable
offline with no DB. v1 (legacy): ``qwed_live_<43 base64url>`` — accepted for
backward compatibility. The checksum authenticates *shape*, never
*authorization*: auth still requires the HMAC lookup in ``hash_api_key``.
"""

import unittest

from qwed_new.auth.security import (
    generate_api_key,
    hash_api_key,
    is_valid_key_checksum,
    validate_api_key_format,
)


def _v1_key() -> str:
    """Build a legacy v1 key the way the pre-#366 generator did."""
    import secrets as _s

    return "qwed_live_" + _s.token_urlsafe(32)


class TestGenerateV2(unittest.TestCase):
    """The centralized generator emits well-formed v2 keys."""

    def test_shape_and_exact_length(self):
        key, _ = generate_api_key()
        self.assertTrue(key.startswith("qwed_live_"))
        body = key[len("qwed_live_"):]
        # prefix(10) + 30 random + 6 checksum
        self.assertEqual(len(key), 46)
        self.assertEqual(len(body), 36)

    def test_body_is_strictly_alphanumeric(self):
        key, _ = generate_api_key()
        body = key[len("qwed_live_"):]
        self.assertTrue(body.isalnum(), f"non-alphanumeric char in body: {body!r}")
        self.assertNotIn("-", body)
        self.assertNotIn("_", body)

    def test_generated_key_passes_checksum(self):
        for _ in range(50):
            key, _ = generate_api_key()
            self.assertTrue(is_valid_key_checksum(key))
            self.assertEqual(validate_api_key_format(key), "v2")

    def test_roundtrip_hash_matches(self):
        key, hashed = generate_api_key()
        self.assertEqual(hash_api_key(key), hashed)

    def test_keys_are_unique(self):
        keys = {generate_api_key()[0] for _ in range(200)}
        self.assertEqual(len(keys), 200)

    def test_test_prefix_uses_same_format(self):
        key, _ = generate_api_key(prefix="qwed_test")
        self.assertTrue(key.startswith("qwed_test_"))
        body = key[len("qwed_test_"):]
        self.assertEqual(len(body), 36)
        self.assertTrue(body.isalnum())

    def test_unknown_prefix_rejected(self):
        with self.assertRaises(ValueError):
            generate_api_key(prefix="qwed_admin")


class TestChecksumValidation(unittest.TestCase):
    """Corruption / tampering is caught offline, pre-DB."""

    def _make(self) -> str:
        return generate_api_key()[0]

    def test_valid_key_accepted(self):
        self.assertTrue(is_valid_key_checksum(self._make()))

    def test_corrupted_checksum_rejected(self):
        key = self._make()
        # flip the last checksum char to a different alphanumeric
        last = key[-1]
        repl = "A" if last != "A" else "B"
        tampered = key[:-1] + repl
        self.assertFalse(is_valid_key_checksum(tampered))

    def test_corrupted_body_rejected(self):
        key = self._make()
        mid = len("qwed_live_") + 5
        ch = key[mid]
        repl = "z" if ch != "z" else "y"
        tampered = key[:mid] + repl + key[mid + 1:]
        self.assertFalse(is_valid_key_checksum(tampered))

    def test_truncated_key_rejected(self):
        key = self._make()
        self.assertFalse(is_valid_key_checksum(key[:-1]))
        self.assertFalse(is_valid_key_checksum(key[:20]))

    def test_extended_key_rejected(self):
        key = self._make()
        self.assertFalse(is_valid_key_checksum(key + "x"))

    def test_non_alnum_body_rejected(self):
        # a 36-char body containing a '-' fails the charset check
        bad = "qwed_live_" + "a" * 35 + "-"
        self.assertFalse(is_valid_key_checksum(bad))

    def test_wrong_prefix_rejected(self):
        self.assertFalse(is_valid_key_checksum("qwed_test_" + "a" * 36))
        self.assertFalse(is_valid_key_checksum("sk_live_" + "a" * 36))

    def test_garbage_rejected(self):
        for bad in ("", "qwed_live_", "not-a-key", "qwed_live", None, 12345):
            self.assertFalse(is_valid_key_checksum(bad))


class TestFormatClassification(unittest.TestCase):
    """validate_api_key_format distinguishes v2 / v1 / invalid."""

    def test_v2_classified(self):
        key, _ = generate_api_key()
        self.assertEqual(validate_api_key_format(key), "v2")

    def test_v1_classified(self):
        self.assertEqual(validate_api_key_format(_v1_key()), "v1")

    def test_v1_with_internal_underscore_classified(self):
        # base64url bodies can contain '_'; only the first '_' separates.
        key = "qwed_live_" + ("a" * 10) + "_" + ("b" * 32)  # 43-char body
        self.assertEqual(len(key) - len("qwed_live_"), 43)
        self.assertEqual(validate_api_key_format(key), "v1")

    def test_v2_shape_with_bad_checksum_is_invalid_not_v1(self):
        # 36-char alnum body but wrong checksum -> not v2, and not 43-char v1
        key = "qwed_live_" + "a" * 36
        self.assertEqual(validate_api_key_format(key), "invalid")

    def test_invalid_shapes(self):
        for bad in ("", "qwed_live_short", "qwed_live_" + "a" * 20,
                    "random_string", "qwed_live_" + "!" * 43):
            self.assertEqual(validate_api_key_format(bad), "invalid")


class TestDualVersionAcceptance(unittest.TestCase):
    """Both v1 and v2 authenticate through the same HMAC lookup path."""

    def test_v1_roundtrip(self):
        key = _v1_key()
        self.assertEqual(validate_api_key_format(key), "v1")
        self.assertEqual(hash_api_key(key), hash_api_key(key))

    def test_v1_not_misclassified_as_v2(self):
        self.assertFalse(is_valid_key_checksum(_v1_key()))

    def test_v1_and_v2_hashes_differ(self):
        v1 = _v1_key()
        v2, _ = generate_api_key()
        self.assertNotEqual(hash_api_key(v1), hash_api_key(v2))


if __name__ == "__main__":
    unittest.main()
