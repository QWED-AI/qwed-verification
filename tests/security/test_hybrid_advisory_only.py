"""
Regression tests for Issue #257: Image, Graph, Reasoning, and Consensus
engines must never return VERIFIED from heuristic/model fallback paths.
"""
from qwed_new.core.image_verifier import ImageVerifier
from qwed_new.core.graph_fact_verifier import GraphFactVerifier
from qwed_new.core.reasoning_verifier import ReasoningVerifier
from qwed_new.core.consensus_verifier import ConsensusVerifier, EngineResult, SECURE_EXECUTION_REQUIRED
from qwed_new.core.fact_verifier import FactVerifier


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

    def test_blocked_filtered_gives_graceful_degradation(self):
        """BLOCKED engine is filtered out; remaining engines determine consensus."""
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
        # Python is the only active engine → unanimous, but blocked engine prevents VERIFIED
        assert consensus["diagnostic_status"] == "UNVERIFIABLE"
        assert consensus["status"] == "unanimous"

    def test_all_blocked_propagates(self):
        """All BLOCKED → consensus BLOCKED."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=None,
                confidence=0.0, latency_ms=10, success=False,
                error="Translation failed", status="BLOCKED",
            ),
            EngineResult(
                engine_name="Python", method="code", result=None,
                confidence=0.0, latency_ms=10, success=False,
                error="Execution timeout", status="BLOCKED",
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
        result = self.verifier._verify_with_stats("average of 0, 0, and 0")
        assert result.result == 0
        assert result.confidence == 0.98
        assert result.status == "UNVERIFIABLE"

    def test_stats_unverifiable_cannot_produce_verified_consensus(self):
        """Stats UNVERIFIABLE result prevents VERIFIED consensus even if unanimous."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=4,
                confidence=1.0, latency_ms=10, success=True,
                status="VERIFIED",
            ),
            EngineResult(
                engine_name="Stats", method="statistical_analysis", result=4,
                confidence=0.98, latency_ms=10, success=True,
                status="UNVERIFIABLE",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        assert consensus["diagnostic_status"] == "UNVERIFIABLE"
        assert consensus["status"] == "unanimous"

    def test_verified_evidence_answer_none_stays_null_and_type_differs(self):
        """Verified consensus evidence: answer None→null, repr carries type info (#266)."""
        from decimal import Decimal

        verifier = ConsensusVerifier(enable_circuit_breaker=False)

        none_result = verifier._calculate_consensus([
            EngineResult("Logic", "logic", None, 1.0, 1.0, True, status="VERIFIED"),
            EngineResult("Math", "symbolic_math", None, 1.0, 1.0, True, status="VERIFIED"),
        ])
        assert none_result["verified_evidence"]["answer"] is None

        typed_result = verifier._calculate_consensus([
            EngineResult("Logic", "logic", Decimal("1.0"), 1.0, 1.0, True, status="VERIFIED"),
            EngineResult("Math", "symbolic_math", Decimal("1.0"), 1.0, 1.0, True, status="VERIFIED"),
        ])
        float_result = verifier._calculate_consensus([
            EngineResult("Logic", "logic", 1.0, 1.0, 1.0, True, status="VERIFIED"),
            EngineResult("Math", "symbolic_math", 1.0, 1.0, 1.0, True, status="VERIFIED"),
        ])

        assert typed_result["verified_evidence"]["answer"] != float_result["verified_evidence"]["answer"]


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

    def test_substring_not_matched_by_word_boundary(self):
        """Substring containment like 'Tim' in 'Timothy' must NOT match."""
        verifier = GraphFactVerifier()
        assert not verifier._entity_matches("Tim", "Timothy")
        assert not verifier._entity_matches("apple", "pineapple")

    def test_alias_matching_succeeds(self):
        """Alias groups match correctly (e.g. 'usa' ↔ 'us')."""
        verifier = GraphFactVerifier()
        assert verifier._entity_matches("usa", "us")

    def test_predicate_word_overlap_matches(self):
        """Word overlap in predicates still matches."""
        verifier = GraphFactVerifier()
        assert verifier._predicate_matches("runs", "runs fast")


class TestConsensusVerifierEdgeCases:

    def setup_method(self):
        self.verifier = ConsensusVerifier()

    def test_empty_results_list(self):
        """Empty results → UNVERIFIABLE."""
        consensus = self.verifier._calculate_consensus([])
        assert consensus["diagnostic_status"] == "UNVERIFIABLE"
        assert consensus["status"] == "no_results"

    def test_secure_execution_required_blocked(self):
        """SECURE_EXECUTION_REQUIRED error → BLOCKED."""
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=None,
                confidence=0.0, latency_ms=10, success=False,
                error=SECURE_EXECUTION_REQUIRED,
                status="BLOCKED",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        assert consensus["diagnostic_status"] == "BLOCKED"
        assert consensus["status"] == "blocked_secure_execution"

    def test_consensus_answer_key_none(self):
        """_consensus_answer_key returns sentinel for None."""
        key = self.verifier._consensus_answer_key(None)
        from qwed_new.core.consensus_verifier import _NONE_CONSENSUS_KEY
        assert key == _NONE_CONSENSUS_KEY

    def test_none_results_skipped_in_unanimous_check(self):
        """None results in unanimous check must compare via _consensus_answer_key."""
        # All VERIFIED with None results (which normalizes to same key)
        results = [
            EngineResult(
                engine_name="SymPy", method="math", result=None,
                confidence=1.0, latency_ms=10, success=True,
                status="VERIFIED",
            ),
            EngineResult(
                engine_name="Python", method="code", result=None,
                confidence=0.99, latency_ms=10, success=True,
                status="VERIFIED",
            ),
        ]
        consensus = self.verifier._calculate_consensus(results)
        # Both None → unanimous (same _consensus_answer_key)
        assert consensus["status"] == "unanimous"


class TestImageVerifierExtraCoverage:

    def setup_method(self):
        self.verifier = ImageVerifier(use_vlm_fallback=False)

    def test_claim_too_long(self):
        """Claim over 500 chars → UNVERIFIABLE."""
        long_claim = "A" * 501
        result = self.verifier.verify_image(b'\x89PNG\r\n\x1a\n' + b'A' * 100, long_claim)
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"

    def test_semantic_claim_no_vlm(self):
        """Semantic claim with VLM disabled → UNVERIFIABLE."""
        result = self.verifier.verify_image(b'\x89PNG\r\n\x1a\n' + b'A' * 100, "some semantic claim")
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"


# ========================================================================
# FactVerifier — advisory-only tests (#259, #133)
# ========================================================================

class TestFactVerifierAdvisoryOnly:

    def setup_method(self):
        self.verifier = FactVerifier(use_llm_fallback=False)

    def test_supported_unverifiable_heuristic_only(self):
        """Heuristic SUPPORTED → UNVERIFIABLE, never VERIFIED #267."""
        result = self.verifier.verify_fact("The sky is blue", "The sky is blue today")
        assert result.status.value == "UNVERIFIABLE"
        assert result.is_verified is False
        assert result.proof_ref is None
        assert result.developer_fields["deterministic_verdict"] == "SUPPORTED"
        assert result.developer_fields["constraint_id"] == "fact_verifier.heuristic_supported"
        # Heuristic verdict must live in advisory_checks, not in status (#267)
        assert result.developer_fields["advisory_checks"][0].constraint_id == "fact_verifier.tfidf_cosine_similarity"

    def test_refuted_blocked(self):
        """REFUTED (negation conflict) → BLOCKED."""
        result = self.verifier.verify_fact(
            "The policy covers water damage",
            "The policy does not cover water damage"
        )
        assert not result.is_verified
        assert result.status.value == "BLOCKED"
        assert result.developer_fields["deterministic_verdict"] == "REFUTED"

    def test_neutral_unverifiable(self):
        """NEUTRAL → UNVERIFIABLE."""
        result = self.verifier.verify_fact(
            "Quantum physics is complex",
            "The weather is nice today"
        )
        assert not result.is_verified
        assert result.status.value == "UNVERIFIABLE"

    def test_empty_input_unverifiable(self):
        """Empty claim → UNVERIFIABLE."""
        result = self.verifier.verify_fact("", "context")
        assert not result.is_verified
        assert result.constraint_id == "fact_verifier.empty_input"

    def test_insufficient_evidence_unverifiable(self):
        """Low aggregate → UNVERIFIABLE."""
        result = self.verifier.verify_fact(
            "Unrelated claim about nothing",
            "Completely different context here"
        )
        assert not result.is_verified

    def test_methods_used_structured(self):
        """methods_used contains structured entries with advisory_only flag."""
        result = self.verifier.verify_fact("The sky is blue", "The sky is blue today")
        methods = result.developer_fields["methods_used"]
        assert len(methods) >= 4
        for m in methods:
            assert "name" in m
            assert "advisory_only" in m

    def test_deterministic_confidence_in_fields(self):
        """Confidence is in developer_fields, not in status."""
        result = self.verifier.verify_fact("The sky is blue", "The sky is blue today")
        assert "deterministic_confidence" in result.developer_fields
        # No confidence field at top level
        d = result.to_dict()
        assert "confidence" not in d.get("developer_fields", {})

    def test_evidence_in_developer_fields(self):
        """Deterministic reasoning is in developer_fields evidence."""
        result = self.verifier.verify_fact("The sky is blue", "The sky is blue today")
        assert "evidence" in result.developer_fields

    def test_citations_included(self):
        """Citations are included in developer_fields."""
        result = self.verifier.verify_fact("The sky is blue", "The sky is blue today")
        assert len(result.developer_fields.get("citations", [])) > 0


class TestFactVerifierLLMAdvisoryOnly:

    """LLM fallback never overwrites deterministic verdict (#133)."""

    def test_llm_does_not_change_verdict(self):
        """LLM advisory is separate — verdict stays deterministic."""
        verifier = FactVerifier(use_llm_fallback=True)
        result = verifier.verify_fact(
            "Random unrelated claim",
            "Completely different topic here",
            provider="dummy",
        )
        assert hasattr(result, "status")
        assert "deterministic_verdict" in result.developer_fields

    def test_llm_advisory_check_populated(self, monkeypatch):
        """When LLM returns a result, advisory_checks are populated."""
        verifier = FactVerifier(use_llm_fallback=True)

        def mock_llm(claim, context, provider):
            return {"verdict": "SUPPORTED", "confidence": 0.85, "reasoning": "Mock LLM analysis"}

        monkeypatch.setattr(verifier, "_llm_fallback", mock_llm)
        result = verifier.verify_fact(
            "Random unrelated claim",
            "Completely different topic here",
            provider="dummy",
        )
        checks = result.advisory_checks
        assert len(checks) >= 1
        llm_check = [c for c in checks if c.name == "llm_fallback"]
        assert len(llm_check) == 1
        assert llm_check[0].advisory_only
        assert llm_check[0].details["llm_verdict"] == "SUPPORTED"

    def test_pipeline_exception_returns_blocked(self, monkeypatch):
        """Exception in deterministic pipeline → BLOCKED."""
        verifier = FactVerifier(use_llm_fallback=False)

        def crash(*args, **kwargs):
            raise RuntimeError("Something broke")

        monkeypatch.setattr(verifier, "_segment_sentences", crash)
        result = verifier.verify_fact("claim", "context")
        assert result.status.value == "BLOCKED"
        assert result.constraint_id == "fact_verifier.execution_error"
