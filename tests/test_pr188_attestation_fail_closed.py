"""
P0 Regression tests for Issue #188:
Attestation service allows proof-boundary downgrade via silent failure.

Acceptance criteria verified here:
- [x] No code path returns silent None for attestation failure
- [x] Attestation failure is represented by explicit security state (BLOCKED / UNVERIFIABLE)
- [x] Key lifecycle events are explicit and auditable (generated_at, continuity_policy)
- [x] Verification paths do not proceed as VERIFIED without a valid attestation artifact
- [x] Tests cover signing failure, crypto unavailable, restart continuity, caller fail-closed
"""

import unittest
from unittest.mock import patch, MagicMock
import src.qwed_new.core.attestation as attest_mod
from src.qwed_new.core.attestation import (
    AttestationResult,
    AttestationService,
    AttestationStatus,
    HAS_CRYPTO,
    IssuerKeyPair,
    create_verification_attestation,
    get_attestation_service,
)


# ---------------------------------------------------------------------------
# Tests that do NOT require real crypto (HAS_CRYPTO may be False)
# These run unconditionally — they patch HAS_CRYPTO or test pure structure
# ---------------------------------------------------------------------------

class TestFailClosedNoCrypto(unittest.TestCase):
    """Fail-closed assertions that must run even when crypto is absent."""

    def test_crypto_unavailable_returns_unverifiable(self):
        """When HAS_CRYPTO is False, result is UNVERIFIABLE — not None."""
        with patch.object(attest_mod, "HAS_CRYPTO", False):
            result = create_verification_attestation(
                status="VERIFIED", verified=True, engine="math", query="2+2"
            )

        self.assertIsNotNone(result, "MUST NOT return None — fail-closed contract")
        self.assertEqual(result.status, AttestationStatus.UNVERIFIABLE)
        self.assertFalse(result.is_issued)
        self.assertEqual(result.error_code, "CRYPTO_UNAVAILABLE")
        self.assertIsNone(result.token)

    def test_no_none_return_crypto_unavailable_path(self):
        """Parametrized no-None check: crypto-unavailable path."""
        with patch.object(attest_mod, "HAS_CRYPTO", False):
            result = create_verification_attestation("VERIFIED", True, "math", "2+2")
        self.assertIsNotNone(result)

    def test_caller_must_hardblock_on_unverifiable(self):
        """Callers must not treat UNVERIFIABLE result as VERIFIED."""
        with patch.object(attest_mod, "HAS_CRYPTO", False):
            result = create_verification_attestation("VERIFIED", True, "math", "q")

        self.assertFalse(
            result.is_issued,
            "Caller MUST NOT proceed as VERIFIED when attestation is UNVERIFIABLE"
        )

    def test_is_issued_true_only_for_issued_status(self):
        """is_issued must be True only when status is AttestationStatus.ISSUED."""
        issued = AttestationResult(
            status=AttestationStatus.ISSUED, token="tok", error_code=None, error=None
        )
        blocked = AttestationResult(
            status=AttestationStatus.BLOCKED, token=None,
            error_code="SIGNING_FAILURE", error="e"
        )
        unverifiable = AttestationResult(
            status=AttestationStatus.UNVERIFIABLE, token=None,
            error_code="CRYPTO_UNAVAILABLE", error="e"
        )

        self.assertTrue(issued.is_issued)
        self.assertFalse(blocked.is_issued)
        self.assertFalse(unverifiable.is_issued)


# ---------------------------------------------------------------------------
# Tests that DO require real crypto
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAS_CRYPTO, "cryptography not installed")
class TestFailClosedContract(unittest.TestCase):
    """create_verification_attestation() must never return None (Issue #188)."""

    def setUp(self):
        self.service = AttestationService(issuer_did="did:test:188", key_suffix="p0")

    def test_success_returns_issued_with_token(self):
        """Happy path: successful attestation returns ISSUED status with JWT."""
        with patch.object(attest_mod, "get_attestation_service", return_value=self.service):
            result = create_verification_attestation(
                status="VERIFIED", verified=True, engine="math", query="2+2=4"
            )

        self.assertIsInstance(result, AttestationResult)
        self.assertEqual(result.status, AttestationStatus.ISSUED)
        self.assertTrue(result.is_issued)
        self.assertIsNotNone(result.token)
        self.assertIsNone(result.error_code)
        self.assertIsNone(result.error)

    def test_issued_token_is_valid_jwt(self):
        """The token inside AttestationResult must be a verifiable JWT."""
        with patch.object(attest_mod, "get_attestation_service", return_value=self.service):
            result = create_verification_attestation(
                status="VERIFIED", verified=True, engine="math", query="is 4 prime?"
            )

        self.assertTrue(result.is_issued)
        is_valid, claims, err = self.service.verify_attestation(result.token)
        self.assertTrue(is_valid, f"JWT verification failed: {err}")
        self.assertEqual(claims["qwed"]["result"]["engine"], "math")

    def test_signing_failure_returns_blocked_not_none(self):
        """If signing raises, result must be BLOCKED — never None."""
        broken_service = AttestationService(issuer_did="did:test:188", key_suffix="broken")
        broken_service.create_attestation = MagicMock(side_effect=RuntimeError("key corrupt"))

        with patch.object(attest_mod, "get_attestation_service", return_value=broken_service):
            result = create_verification_attestation(
                status="VERIFIED", verified=True, engine="math", query="2+2"
            )

        self.assertIsNotNone(result, "MUST NOT return None — fail-closed contract")
        self.assertIsInstance(result, AttestationResult)
        self.assertEqual(result.status, AttestationStatus.BLOCKED)
        self.assertFalse(result.is_issued)
        self.assertEqual(result.error_code, "SIGNING_FAILURE")
        self.assertIsNone(result.token)

    def test_service_init_failure_returns_blocked(self):
        """If get_attestation_service() itself raises, result is BLOCKED."""
        with patch.object(attest_mod, "get_attestation_service", side_effect=Exception("svc down")):
            result = create_verification_attestation(
                status="VERIFIED", verified=True, engine="math", query="q"
            )

        self.assertEqual(result.status, AttestationStatus.BLOCKED)
        self.assertEqual(result.error_code, "SIGNING_FAILURE")
        self.assertIsNone(result.token)

    def test_no_none_return_success_path(self):
        with patch.object(attest_mod, "get_attestation_service", return_value=self.service):
            result = create_verification_attestation("VERIFIED", True, "math", "2+2")
        self.assertIsNotNone(result)

    def test_no_none_return_signing_failure_path(self):
        svc = AttestationService(issuer_did="did:test:188", key_suffix="fail")
        svc.create_attestation = MagicMock(side_effect=ValueError("bad key"))
        with patch.object(attest_mod, "get_attestation_service", return_value=svc):
            result = create_verification_attestation("VERIFIED", True, "math", "2+2")
        self.assertIsNotNone(result)

    def test_caller_must_hardblock_on_blocked(self):
        """Callers must not treat BLOCKED result as VERIFIED."""
        broken = AttestationService(issuer_did="did:test:188", key_suffix="hb")
        broken.create_attestation = MagicMock(side_effect=RuntimeError("fail"))

        with patch.object(attest_mod, "get_attestation_service", return_value=broken):
            result = create_verification_attestation("VERIFIED", True, "math", "q")

        self.assertFalse(
            result.is_issued,
            "Caller MUST NOT proceed as VERIFIED when attestation is BLOCKED"
        )


@unittest.skipUnless(HAS_CRYPTO, "cryptography not installed")
class TestKeyLifecycleMetadata(unittest.TestCase):
    """Key continuity events must be explicit and auditable (Issue #188)."""

    def test_key_pair_has_generated_at(self):
        kp = IssuerKeyPair("did:test:188", "key-test")
        self.assertIsInstance(kp.generated_at, int)
        self.assertGreater(kp.generated_at, 0)

    def test_key_pair_has_continuity_policy(self):
        kp = IssuerKeyPair("did:test:188", "key-test")
        self.assertEqual(kp.key_continuity_policy, "ephemeral")

    def test_key_pair_accepts_persistent_policy(self):
        kp = IssuerKeyPair("did:test:188", "key-persist", key_continuity_policy="persistent")
        self.assertEqual(kp.key_continuity_policy, "persistent")

    def test_invalid_policy_raises(self):
        """Invalid key_continuity_policy must raise ValueError immediately."""
        with self.assertRaises(ValueError):
            IssuerKeyPair("did:test:188", "key-bad", key_continuity_policy="persistant")

    def test_get_issuer_info_exposes_key_lifecycle(self):
        svc = AttestationService(issuer_did="did:test:188", key_suffix="lifecycle")
        info = svc.get_issuer_info()
        self.assertIn("key_generated_at", info)
        self.assertIn("key_continuity_policy", info)
        self.assertIsInstance(info["key_generated_at"], int)
        self.assertEqual(info["key_continuity_policy"], "ephemeral")

    def test_restart_yields_new_ephemeral_key(self):
        """Singleton reset simulates a process restart — new key material must differ."""
        old = attest_mod._default_service
        try:
            attest_mod._default_service = None
            svc1 = get_attestation_service()
            kp1_pub = svc1._ensure_key_pair().public_key_pem

            attest_mod._default_service = None
            svc2 = get_attestation_service()
            kp2_pub = svc2._ensure_key_pair().public_key_pem

            self.assertNotEqual(kp1_pub, kp2_pub)
        finally:
            attest_mod._default_service = old

    def test_key_generation_logged(self):
        """Key generation must produce a structured log entry (audit trail)."""
        with self.assertLogs("src.qwed_new.core.attestation", level="INFO") as cm:
            IssuerKeyPair("did:test:188", "key-log")

        audit_log = " ".join(cm.output)
        self.assertIn("attestation.key_generated", audit_log)
        self.assertIn("did:test:188", audit_log)

    def test_injectable_issued_at_and_jti(self):
        """create_attestation must use injected iat/jti for determinism."""
        svc = AttestationService(issuer_did="did:test:188", key_suffix="det")
        from src.qwed_new.core.attestation import VerificationResult
        vr = VerificationResult(status="VERIFIED", verified=True, engine="math")
        att = svc.create_attestation(vr, "2+2", issued_at=1_000_000, jti="att_deterministic")

        self.assertEqual(att.claims.iat, 1_000_000)
        self.assertEqual(att.claims.jti, "att_deterministic")


@unittest.skipUnless(HAS_CRYPTO, "cryptography not installed")
class TestAttestationStatusEnum(unittest.TestCase):
    """AttestationStatus enum must include fail-closed states."""

    def test_blocked_status_exists(self):
        self.assertEqual(AttestationStatus.BLOCKED.value, "blocked")

    def test_unverifiable_status_exists(self):
        self.assertEqual(AttestationStatus.UNVERIFIABLE.value, "unverifiable")

    def test_original_states_unchanged(self):
        self.assertEqual(AttestationStatus.ISSUED.value, "issued")
        self.assertEqual(AttestationStatus.VALID.value, "valid")
        self.assertEqual(AttestationStatus.EXPIRED.value, "expired")
        self.assertEqual(AttestationStatus.REVOKED.value, "revoked")


if __name__ == "__main__":
    unittest.main()
