
import unittest
import base64
import json
from unittest.mock import patch
from src.qwed_new.core.attestation import (
    AttestationService,
    VerificationResult,
    Attestation,
    AttestationClaims,
    AttestationStatus,
    IssuerKeyPair,
    create_verification_attestation,
    get_attestation_service,
    HAS_CRYPTO,
)


class TestAttestationCoverage(unittest.TestCase):
    """Targeted tests to improve coverage of attestation.py"""

    def setUp(self):
        if not HAS_CRYPTO:
            self.skipTest("Cryptography not available")
        self.service = AttestationService(issuer_did="did:test:123", key_suffix="test")

    # ── Dataclass and Enum coverage ──────────────────────────────

    def test_attestation_status_enum(self):
        """Test AttestationStatus enum values."""
        self.assertEqual(AttestationStatus.ISSUED.value, "issued")
        self.assertEqual(AttestationStatus.VALID.value, "valid")
        self.assertEqual(AttestationStatus.EXPIRED.value, "expired")
        self.assertEqual(AttestationStatus.REVOKED.value, "revoked")

    def test_verification_result_dataclass(self):
        """Test VerificationResult dataclass fields."""
        vr = VerificationResult(
            status="VERIFIED", verified=True, engine="math",
            confidence=0.95, query_hash="abc", proof_hash="def"
        )
        self.assertEqual(vr.status, "VERIFIED")
        self.assertTrue(vr.verified)
        self.assertEqual(vr.engine, "math")
        self.assertEqual(vr.confidence, 0.95)
        self.assertEqual(vr.query_hash, "abc")
        self.assertEqual(vr.proof_hash, "def")

    def test_attestation_to_dict(self):
        """Test Attestation.to_dict() method."""
        claims = AttestationClaims(
            iss="did:test:1", sub="hash1", iat=1000, exp=2000,
            jti="att_123", qwed={"result": {"verified": True}, "version": "1.0"}
        )
        att = Attestation(jwt_token="tok.en.sig", claims=claims, header={"alg": "ES256"})
        d = att.to_dict()
        self.assertEqual(d["jwt"], "tok.en.sig")
        self.assertEqual(d["jti"], "att_123")
        self.assertEqual(d["iss"], "did:test:1")
        self.assertEqual(d["iat"], 1000)
        self.assertEqual(d["exp"], 2000)
        self.assertEqual(d["result"]["verified"], True)

    # ── IssuerKeyPair coverage ───────────────────────────────────

    def test_key_pair_generation(self):
        """Test internal key pair generation and all properties."""
        kp = self.service._ensure_key_pair()
        # PEM properties
        self.assertIn(b"BEGIN PRIVATE KEY", kp.private_key_pem)
        self.assertIn(b"BEGIN PUBLIC KEY", kp.public_key_pem)
        # JWK property
        jwk = kp.jwk
        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["crv"], "P-256")
        self.assertIn("x", jwk)
        self.assertIn("y", jwk)
        self.assertEqual(jwk["kid"], kp.key_id)

    def test_key_pair_no_crypto_raises(self):
        """Test IssuerKeyPair raises when crypto not available."""
        with patch("src.qwed_new.core.attestation.HAS_CRYPTO", False):
            with self.assertRaises(RuntimeError):
                IssuerKeyPair("did:test:1", "key1")

    # ── AttestationService init and helpers ──────────────────────

    def test_service_init_defaults(self):
        """Test AttestationService default initialization."""
        svc = AttestationService()
        self.assertEqual(svc.issuer_did, "did:qwed:node:local")
        self.assertEqual(svc.validity_days, 365)
        self.assertEqual(svc.key_id, "did:qwed:node:local#signing-key-v1")
        self.assertIsNone(svc._key_pair)
        self.assertEqual(len(svc._revoked_attestations), 0)
        self.assertEqual(len(svc._attestations), 0)

    def test_ensure_key_pair_caching(self):
        """Test _ensure_key_pair returns same instance on second call."""
        kp1 = self.service._ensure_key_pair()
        kp2 = self.service._ensure_key_pair()
        self.assertIs(kp1, kp2)

    def test_hash_content(self):
        """Test _hash_content produces sha256 hashes."""
        h = self.service._hash_content("hello")
        self.assertTrue(h.startswith("sha256:"))
        self.assertEqual(len(h), 7 + 64)  # "sha256:" + 64 hex chars

    # ── create_attestation coverage ──────────────────────────────

    def test_create_attestation_basic(self):
        """Test basic attestation creation."""
        result = VerificationResult(status="ok", verified=True, engine="test")
        att = self.service.create_attestation(result, "what is 2+2?")

        self.assertIsNotNone(att.jwt_token)
        self.assertEqual(att.claims.iss, "did:test:123")
        self.assertEqual(att.claims.qwed["result"]["verified"], True)
        self.assertEqual(att.claims.qwed["result"]["engine"], "test")
        self.assertEqual(att.claims.qwed["version"], "1.0")
        self.assertIn("query_hash", att.claims.qwed)

    def test_create_attestation_with_proof_and_chain(self):
        """Test creating attestation with all options (proof, chain)."""
        result = VerificationResult(status="ok", verified=True, engine="test")
        att = self.service.create_attestation(
            result, "query",
            proof_data="proof123",
            chain_id="chain1",
            chain_index=5,
        )
        claims = att.claims.qwed
        self.assertEqual(claims["proof_hash"], self.service._hash_content("proof123"))
        self.assertEqual(claims["chain_id"], "chain1")
        self.assertEqual(claims["chain_index"], 5)

    def test_create_attestation_stored_in_registry(self):
        """Test attestation is stored and retrievable."""
        result = VerificationResult(status="ok", verified=True, engine="test")
        att = self.service.create_attestation(result, "query")

        retrieved = self.service.get_attestation(att.claims.jti)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.jwt_token, att.jwt_token)

    def test_get_attestation_missing(self):
        """Test get_attestation returns None for unknown ID."""
        self.assertIsNone(self.service.get_attestation("nonexistent"))

    # ── verify_attestation coverage ──────────────────────────────

    def test_verify_valid_attestation(self):
        """Test full create → verify round-trip."""
        result = VerificationResult(status="ok", verified=True, engine="test")
        att = self.service.create_attestation(result, "query")

        is_valid, claims, error = self.service.verify_attestation(att.jwt_token)
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertEqual(claims["qwed"]["result"]["verified"], True)

    def test_verify_invalid_token_format_not_json(self):
        """Test handling of tokens with non-JSON payloads."""
        header = "eyJhbGciOiJFUzI1NiJ9"
        payload = base64.urlsafe_b64encode(b"not json").decode().rstrip("=")
        token = f"{header}.{payload}.signature"

        is_valid, _, error = self.service.verify_attestation(token)
        self.assertFalse(is_valid)
        self.assertIn("Invalid token format", error)

    def test_verify_invalid_token_not_dict(self):
        """Test handling of tokens where payload is not a JSON object."""
        header = "eyJhbGciOiJFUzI1NiJ9"
        payload = base64.urlsafe_b64encode(b'"just a string"').decode().rstrip("=")
        token = f"{header}.{payload}.signature"

        is_valid, _, error = self.service.verify_attestation(token)
        self.assertFalse(is_valid)
        self.assertIn("Invalid token format", error)

    def test_verify_untrusted_issuer(self):
        """Test verification with an untrusted issuer."""
        other = AttestationService(issuer_did="did:malicious:999", key_suffix="evil")
        result = VerificationResult(status="fake", verified=True, engine="fake")
        att = other.create_attestation(result, "query")

        is_valid, _, error = self.service.verify_attestation(att.jwt_token)
        self.assertFalse(is_valid)
        self.assertIn("Untrusted issuer", error)

    def test_verify_external_issuer_not_implemented(self):
        """Test verification with external issuer returns not-implemented error."""
        # Build a valid-looking payload with a trusted but non-self issuer
        payload = json.dumps({"iss": "did:external:xyz", "sub": "h", "iat": 0, "exp": 0, "jti": "x"})
        header = base64.urlsafe_b64encode(b'{"alg":"ES256"}').decode().rstrip("=")
        body = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        token = f"{header}.{body}.fakesig"

        is_valid, _, error = self.service.verify_attestation(
            token, trusted_issuers=["did:external:xyz"]
        )
        self.assertFalse(is_valid)
        self.assertIn("External issuer key resolution not implemented", error)

    def test_verify_revoked_attestation(self):
        """Test verification of a revoked attestation."""
        result = VerificationResult(status="ok", verified=True, engine="test")
        att = self.service.create_attestation(result, "query")
        self.service.revoke_attestation(att.claims.jti)

        is_valid, _, error = self.service.verify_attestation(att.jwt_token)
        self.assertFalse(is_valid)
        self.assertIn("revoked", error)

    def test_verify_expired_token(self):
        """Test verification of expired token."""
        self.service.validity_days = -1
        result = VerificationResult(status="ok", verified=True, engine="test")
        att = self.service.create_attestation(result, "query")

        is_valid, _, error = self.service.verify_attestation(att.jwt_token)
        self.assertFalse(is_valid)
        self.assertIn("expired", error)
        self.service.validity_days = 365

    def test_verify_tampered_signature(self):
        """Test verification with tampered signature."""
        result = VerificationResult(status="ok", verified=True, engine="test")
        att = self.service.create_attestation(result, "query")
        # Replace entire signature portion with garbage to guarantee failure
        parts = att.jwt_token.split(".")
        parts[2] = "AAAA_tampered_signature_BBBB"
        tampered = ".".join(parts)

        is_valid, _, _ = self.service.verify_attestation(tampered)
        self.assertFalse(is_valid)

    # ── revoke and info ──────────────────────────────────────────

    def test_revoke_attestation(self):
        """Test revoking an attestation."""
        self.assertTrue(self.service.revoke_attestation("some_id"))
        self.assertIn("some_id", self.service._revoked_attestations)

    def test_get_issuer_info(self):
        """Test get_issuer_info returns correct structure."""
        info = self.service.get_issuer_info()
        self.assertEqual(info["did"], "did:test:123")
        self.assertEqual(info["status"], "active")
        self.assertEqual(info["certification_level"], "basic")
        self.assertIn("public_keys", info)
        self.assertEqual(len(info["public_keys"]), 1)
        self.assertEqual(info["name"], "QWED Local Node")

    # ── Module-level helper functions ────────────────────────────

    def test_get_attestation_service_singleton(self):
        """Test get_attestation_service returns a singleton."""
        import src.qwed_new.core.attestation as mod
        old = mod._default_service
        try:
            mod._default_service = None
            svc1 = get_attestation_service()
            svc2 = get_attestation_service()
            self.assertIs(svc1, svc2)
        finally:
            mod._default_service = old

    def test_create_verification_attestation_helper(self):
        """Test the convenience function."""
        with patch("src.qwed_new.core.attestation.get_attestation_service", return_value=self.service):
            token = create_verification_attestation(
                status="verified", verified=True,
                engine="test_engine", query="test query"
            )
            self.assertIsNotNone(token)
            is_valid, claims, _ = self.service.verify_attestation(token)
            self.assertTrue(is_valid)
            self.assertEqual(claims["qwed"]["result"]["engine"], "test_engine")

    def test_create_verification_attestation_with_proof(self):
        """Test convenience function with proof_data."""
        with patch("src.qwed_new.core.attestation.get_attestation_service", return_value=self.service):
            token = create_verification_attestation(
                status="verified", verified=True,
                engine="test", query="q",
                confidence=0.99, proof_data="proof_data_here"
            )
            self.assertIsNotNone(token)

    def test_create_verification_attestation_failure(self):
        """Test the convenience function handles exceptions."""
        with patch("src.qwed_new.core.attestation.get_attestation_service", side_effect=Exception("Boom")):
            token = create_verification_attestation("s", True, "e", "q")
            self.assertIsNone(token)


if __name__ == '__main__':
    unittest.main()
