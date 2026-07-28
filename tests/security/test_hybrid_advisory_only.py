"""
Regression tests for Issue #257: Image, Graph, Reasoning, and Consensus
engines must never return VERIFIED from heuristic/model fallback paths.
"""
from qwed_new.core.image_verifier import ImageVerifier
from qwed_new.core.graph_fact_verifier import GraphFactVerifier
from qwed_new.core.reasoning_verifier import ReasoningVerifier
from qwed_new.core.consensus_verifier import ConsensusVerifier, EngineResult


class StubVLMProvider:
    """Stub VLM that returns SUPPORTED — must NOT produce VERIFIED."""
    def verify_image(self, image_bytes, claim):
        return {"verdict": "SUPPORTED", "confidence": 0.9, "reasoning": "Stub VLM says yes"}


class StubTask:
    def __init__(self, expression="2+2", expected_value="4"):
        self.expression = expression
        self.expected_value = expected_value
        self.reasoning = None


# ========================================================================
# ImageVerifier — VLM path must be UNVERIFIABLE, never VERIFIED
# ========================================================================

class TestImageVerifierAdvisoryOnly:

    def setup_method(self):
        self.verifier = ImageVerifier(vlm_provider=StubVLMProvider(), use_vlm_fallback=True)

    def test_vlm_path_never_verified(self):
        """VLM_REQUIRED + VLM available → status UNVERIFIABLE, not VERIFIED."""
        result = self.verifier.verify_image(b"fake-png-bytes", "The person is wearing a uniform")
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"
        assert result.proof_ref is None

    def test_vlm_advisory_checks_present(self):
        """VLM advisory verdict/confidence must be in advisory_checks."""
        result = self.verifier.verify_image(b"fake-png-bytes", "The person is wearing a uniform")
        checks = result.advisory_checks
        assert len(checks) >= 1
        assert all(c.advisory_only for c in checks)

    def test_vlm_no_provider_returns_unverifiable(self):
        """No VLM provider → UNVERIFIABLE."""
        verifier = ImageVerifier(use_vlm_fallback=False)
        result = verifier.verify_image(b"fake-png-bytes", "The person is wearing a uniform")
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"

    def test_deterministic_size_match_verified(self):
        """Deterministic dimension match → VERIFIED with proof_ref."""
        png_header = b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\x00IHDR'
        w, h = 100, 200
        header = png_header + w.to_bytes(4, 'big') + h.to_bytes(4, 'big')
        result = self.verifier.verify_image(header + b'A' * 100, "100x200")
        assert result.is_verified
        assert result.proof_ref is not None

    def test_empty_input_unverifiable(self):
        """Empty image/claim → UNVERIFIABLE."""
        result = self.verifier.verify_image(b"", "")
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"

    def test_vlm_confidence_not_in_status_field(self):
        """VLM confidence must NOT appear in status — only in advisory_checks."""
        result = self.verifier.verify_image(b"fake-png-bytes", "Describe this image")
        assert result.status.value == "UNVERIFIABLE"
        # There should be no 'confidence' key at the top level of to_dict
        d = result.to_dict()
        assert "confidence" not in d.get("developer_fields", {})


# ========================================================================
# GraphFactVerifier — partial support must be UNVERIFIABLE
# ========================================================================

class TestGraphFactVerifierAdvisoryOnly:

    def setup_method(self):
        self.verifier = GraphFactVerifier()

    def test_all_triples_matched_verified(self):
        """All claim triples matched → VERIFIED."""
        result = self.verifier.verify(
            "Modi is the Prime Minister",
            "Narendra Modi serves as Prime Minister of India",
        )
        assert result.is_verified
        assert result.proof_ref is not None

    def test_partial_support_unverifiable(self):
        """Only some triples matched → UNVERIFIABLE (was VERIFIED at 50%)."""
        result = self.verifier.verify(
            "Alice founded Acme. Bob founded Twitter.",
            "Alice founded Acme.",
        )
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"

    def test_no_matches_unverifiable(self):
        """No triples matched → UNVERIFIABLE."""
        result = self.verifier.verify(
            "Elon Musk bought Twitter",
            "The weather is nice today",
        )
        assert not result.is_verified

    def test_insufficient_context_unverifiable(self):
        """Empty claim → UNVERIFIABLE."""
        result = self.verifier.verify("", "Some context")
        assert not result.is_verified

    def test_coverage_in_developer_fields(self):
        """Partial support exposes coverage ratio in developer_fields."""
        result = self.verifier.verify(
            "Alice founded Acme. Bob founded Twitter.",
            "Alice founded Acme.",
        )
        assert "coverage" in result.developer_fields

    def test_nli_advisory_only(self):
        """NLI fallback → UNVERIFIABLE with advisory_checks, never VERIFIED."""
        result = self.verifier.verify_with_nli(
            "Modi is the President",
            "Narendra Modi serves as Prime Minister of India",
        )
        # Graph alone won't verify this (President ≠ Prime Minister)
        assert not result.is_verified
        # NLI output should be in advisory_checks
        checks = result.advisory_checks
        assert any("nli" in c.name.lower() or "nli" in str(c.details).lower() for c in checks)


# ========================================================================
# ReasoningVerifier — no provider must be UNVERIFIABLE
# ========================================================================

class TestReasoningVerifierAdvisoryOnly:

    def setup_method(self):
        self.verifier = ReasoningVerifier(providers=[], enable_cache=False)

    def test_no_provider_unverifiable(self):
        """No provider/proof path → UNVERIFIABLE (was is_valid=True)."""
        result = self.verifier.verify_understanding("2+2", StubTask())
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"
        assert result.proof_ref is None

    def test_no_provider_has_constraint_id(self):
        """No provider path should have constraint_id=reasoning_verifier.no_provider."""
        result = self.verifier.verify_understanding("2+2", StubTask())
        assert result.constraint_id == "reasoning_verifier.no_provider"

    def test_no_provider_heuristic_advisory(self):
        """Heuristic checks without provider → advisory_checks present."""
        self.verifier = ReasoningVerifier(providers=[], enable_cache=False)
        result = self.verifier.verify_understanding(
            "Alice has 10 apples and Bob has 5",
            StubTask(),
        )
        checks = result.advisory_checks
        assert len(checks) >= 1
        assert all(c.advisory_only for c in checks)


# ========================================================================
# ConsensusVerifier — no fabrication, status preserved
# ========================================================================

class TestConsensusVerifierAdvisoryOnly:

    def setup_method(self):
        self.verifier = ConsensusVerifier()

    def test_parse_math_query_translation_failure_blocked(self):
        """Translation failure → BLOCKED (not fabricated sum)."""
        result = self.verifier._verify_with_math("Add apples and oranges")
        assert result.status == "BLOCKED"
        assert result.error is not None

    def test_parse_math_missing_expected_blocked(self):
        """Missing claimed_answer → BLOCKED (not defaulted to 0)."""
        engine_result = self.verifier._verify_with_math("What is 2+2?")
        assert engine_result.status == "BLOCKED"

    def test_blocked_propagates_through_consensus(self):
        """BLOCKED engine status → consensus status is BLOCKED."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=None,
                confidence=0.0, latency_ms=10, success=False,
                error="Translation failed", status="BLOCKED",
            ),
            EngineResult(
                engine_name="Python", method="code", result=4,
                confidence=0.99, latency_ms=10, success=True,
                status="VERIFIED",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        assert consensus["diagnostic_status"] == "BLOCKED"
        assert consensus["status"] == "blocked"

    def test_all_unverifiable_propagates(self):
        """All UNVERIFIABLE → consensus status UNVERIFIABLE."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=None,
                confidence=0.0, latency_ms=10, success=False,
                error="Inconclusive", status="UNVERIFIABLE",
            ),
            EngineResult(
                engine_name="Python", method="code", result=None,
                confidence=0.0, latency_ms=10, success=False,
                error="Inconclusive", status="UNVERIFIABLE",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        assert consensus["diagnostic_status"] == "UNVERIFIABLE"

    def test_verified_without_blocked(self):
        """All VERIFIED (unanimous) → consensus VERIFIED with agreement."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=4,
                confidence=1.0, latency_ms=10, success=True,
                status="VERIFIED",
            ),
            EngineResult(
                engine_name="Python", method="code", result=4,
                confidence=0.99, latency_ms=10, success=True,
                status="VERIFIED",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        assert consensus["diagnostic_status"] == "VERIFIED"

    def test_majority_consensus_unverifiable(self):
        """Majority agreement → consensus UNVERIFIABLE (not unanimous)."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=4,
                confidence=1.0, latency_ms=10, success=True,
                status="VERIFIED",
            ),
            EngineResult(
                engine_name="Python", method="code", result=5,
                confidence=0.99, latency_ms=10, success=True,
                status="VERIFIED",
            ),
            EngineResult(
                engine_name="Z3", method="logic", result=4,
                confidence=0.995, latency_ms=10, success=True,
                status="VERIFIED",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        assert consensus["diagnostic_status"] == "UNVERIFIABLE"
        assert consensus["status"] == "majority"

    def test_split_consensus_unverifiable(self):
        """Split agreement (3 engines, 3 different answers) → consensus UNVERIFIABLE."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=4,
                confidence=1.0, latency_ms=10, success=True,
                status="VERIFIED",
            ),
            EngineResult(
                engine_name="Python", method="code", result=5,
                confidence=0.99, latency_ms=10, success=True,
                status="VERIFIED",
            ),
            EngineResult(
                engine_name="Z3", method="logic", result=6,
                confidence=0.995, latency_ms=10, success=True,
                status="VERIFIED",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        assert consensus["diagnostic_status"] == "UNVERIFIABLE"
        assert consensus["status"] == "split"

    def test_stats_result_zero_gets_full_confidence(self):
        """Stats result=0 should get 0.98 confidence (not 0.0 from truthiness)."""
        result = EngineResult(
            engine_name="Stats", method="statistical_analysis",
            result=0, confidence=0.98,
            latency_ms=10, success=True, status="VERIFIED",
        )
        assert result.confidence == 0.98


# ========================================================================
# ImageVerifier — deterministic refutation and MultiVLM edge cases
# ========================================================================

class TestImageVerifierEdgeCases:

    def setup_method(self):
        self.verifier = ImageVerifier(use_vlm_fallback=False)

    def test_deterministic_refutation_blocked(self):
        """Dimension mismatch → BLOCKED (not VERIFIED)."""
        png_header = b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\x00IHDR'
        w, h = 100, 200
        header = png_header + w.to_bytes(4, 'big') + h.to_bytes(4, 'big')
        # Claim 800x600 but actual is 100x200
        result = self.verifier.verify_image(header + b'A' * 100, "800x600")
        assert not result.is_verified
        assert result.status.value == "BLOCKED"
        assert result.constraint_id == "image_verifier.deterministic_refuted"

    def test_image_width_refutation_blocked(self):
        """Width mismatch → BLOCKED."""
        png_header = b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\x00IHDR'
        w, h = 100, 200
        header = png_header + w.to_bytes(4, 'big') + h.to_bytes(4, 'big')
        result = self.verifier.verify_image(header + b'A' * 100, "width is 999")
        assert not result.is_verified
        assert result.status.value == "BLOCKED"


# ========================================================================
# GraphFactVerifier — near-exact threshold edge cases
# ========================================================================

class TestGraphFactVerifierThresholdEdgeCases:

    def setup_method(self):
        self.verifier = GraphFactVerifier()

    def test_mixed_scores_partial_and_absent(self):
        """One near-exact + one partial → UNVERIFIABLE, not VERIFIED."""
        result = self.verifier.verify(
            "Alice founded Acme. Bob founded Twitter.",
            "Alice founded Acme. Charlie founded Twitter.",
        )
        assert not result.is_verified

    def test_all_near_exact_verified(self):
        """All triples with near-exact scores → VERIFIED."""
        result = self.verifier.verify(
            "Alice founded Acme. Bob founded Twitter.",
            "Alice founded Acme. Bob founded Twitter.",
        )
        assert result.is_verified
