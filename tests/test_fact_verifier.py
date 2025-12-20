"""
Tests for Enterprise Fact Verification Engine.

Tests semantic similarity, keyword overlap, entity matching, and citation extraction.
"""

import pytest
from qwed_new.core.fact_verifier import FactVerifier, BatchFactVerifier


class TestFactVerifierBasics:
    """Test basic fact verification."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_exact_match_supported(self, verifier):
        """Test claim that exactly matches context."""
        claim = "The company was founded in 2020."
        context = "The company was founded in 2020 by John Smith in New York."
        
        result = verifier.verify_fact(claim, context)
        
        # High overlap should give positive result
        assert result["verdict"] in ["SUPPORTED", "NEUTRAL"]
        assert result["confidence"] > 0.3
    
    def test_clear_refutation(self, verifier):
        """Test claim that is clearly refuted."""
        claim = "The company was founded in 2015."
        context = "The company was founded in 2020 by John Smith."
        
        result = verifier.verify_fact(claim, context)
        
        # Should detect the year mismatch
        assert result["verdict"] in ["REFUTED", "NEUTRAL", "INSUFFICIENT_EVIDENCE"]
    
    def test_no_evidence(self, verifier):
        """Test claim with no supporting evidence."""
        claim = "The moon is made of cheese."
        context = "The Earth orbits the Sun. Water is essential for life."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["verdict"] in ["NEUTRAL", "INSUFFICIENT_EVIDENCE"]
        assert result["confidence"] < 0.5
    
    def test_empty_claim(self, verifier):
        """Test empty claim."""
        result = verifier.verify_fact("", "Some context")
        
        assert result["verdict"] == "INSUFFICIENT_EVIDENCE"
    
    def test_empty_context(self, verifier):
        """Test empty context."""
        result = verifier.verify_fact("Some claim", "")
        
        assert result["verdict"] == "INSUFFICIENT_EVIDENCE"


class TestSemanticSimilarity:
    """Test semantic similarity scoring."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_high_similarity(self, verifier):
        """Test high semantic similarity."""
        claim = "Apple released the iPhone 15 in September 2023."
        context = "Apple released the iPhone 15 in September 2023 with new features."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["scores"]["semantic_similarity"] > 0.5
    
    def test_low_similarity(self, verifier):
        """Test low semantic similarity."""
        claim = "Dogs are mammals."
        context = "Python is a programming language used for web development."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["scores"]["semantic_similarity"] < 0.3


class TestKeywordOverlap:
    """Test keyword overlap analysis."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_high_keyword_overlap(self, verifier):
        """Test high keyword overlap."""
        claim = "Tesla produces electric vehicles."
        context = "Tesla is a company that produces electric vehicles and solar panels."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["scores"]["keyword_overlap"] > 0.5
    
    def test_partial_keyword_overlap(self, verifier):
        """Test partial keyword overlap."""
        claim = "Tesla produces rockets."
        context = "Tesla is a company that produces electric vehicles. SpaceX produces rockets."
        
        result = verifier.verify_fact(claim, context)
        
        # "Tesla" and "produces" match, but "rockets" doesn't associate with Tesla
        assert 0.2 < result["scores"]["keyword_overlap"] < 0.8


class TestEntityMatching:
    """Test entity matching (numbers, dates, names)."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_number_match(self, verifier):
        """Test number matching."""
        claim = "The building has 50 floors."
        context = "The Empire State Building has 50 floors and was built in 1931."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["scores"]["entity_match"] > 0.5
    
    def test_year_match(self, verifier):
        """Test year matching."""
        claim = "The event happened in 2019."
        context = "The conference was held in 2019 in San Francisco."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["scores"]["entity_match"] > 0.5
    
    def test_number_mismatch(self, verifier):
        """Test number mismatch."""
        claim = "The company has 500 employees."
        context = "The company has 1000 employees across 5 offices."
        
        result = verifier.verify_fact(claim, context)
        
        # 500 doesn't match 1000
        assert result["scores"]["entity_match"] < 0.5


class TestNegationDetection:
    """Test negation conflict detection."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_negation_conflict(self, verifier):
        """Test detection of negation conflict."""
        claim = "The policy covers water damage."
        context = "The policy does not cover water damage or flood damage."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["scores"]["negation_conflict"] == 1.0
    
    def test_no_negation_conflict(self, verifier):
        """Test no negation conflict."""
        claim = "The policy covers water damage."
        context = "The policy covers water damage and fire damage."
        
        result = verifier.verify_fact(claim, context)
        
        assert result["scores"]["negation_conflict"] == 0.0


class TestCitationExtraction:
    """Test citation extraction."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_citations_returned(self, verifier):
        """Test that citations are returned."""
        claim = "The price is 100 dollars."
        context = "Our product costs 100 dollars. Shipping is free. Returns are accepted."
        
        result = verifier.verify_fact(claim, context)
        
        assert len(result["citations"]) > 0
    
    def test_citation_relevance_sorted(self, verifier):
        """Test that citations are sorted by relevance."""
        claim = "Water damage is covered."
        context = """
        Section 1: Fire damage is covered under this policy.
        Section 2: Water damage is covered under this policy.
        Section 3: Earthquake damage is not covered.
        Section 4: The policyholder must pay a deductible.
        """
        
        result = verifier.verify_fact(claim, context)
        
        # Top citation should be most relevant
        if result["citations"]:
            top_citation = result["citations"][0]
            assert "water" in top_citation["sentence"].lower()


class TestMethodsUsed:
    """Test that methods are properly tracked."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_methods_tracked(self, verifier):
        """Test that all methods are tracked."""
        result = verifier.verify_fact("Test claim", "Test context")
        
        expected_methods = [
            "semantic_similarity",
            "keyword_overlap",
            "entity_matching",
            "negation_detection"
        ]
        
        for method in expected_methods:
            assert method in result["methods_used"]


class TestBatchVerification:
    """Test batch fact verification."""
    
    def test_batch_verification(self):
        """Test verifying multiple claims."""
        verifier = BatchFactVerifier()
        
        claims = [
            "The company was founded in 2020.",
            "The CEO is John Smith.",
            "The company has 500 employees."
        ]
        context = "The company was founded in 2020 by John Smith. Today it has 500 employees."
        
        result = verifier.verify_batch(claims, context)
        
        assert len(result["results"]) == 3
        assert result["summary"]["total"] == 3
        assert "supported" in result["summary"]
        assert "average_confidence" in result["summary"]


class TestRealWorldScenarios:
    """Test real-world fact checking scenarios."""
    
    @pytest.fixture
    def verifier(self):
        return FactVerifier(use_llm_fallback=False)
    
    def test_policy_verification(self, verifier):
        """Test insurance policy verification."""
        claim = "Water damage to the basement is covered."
        context = """
        COVERAGE SECTION
        This policy covers damage caused by:
        1. Fire and smoke
        2. Water damage to the basement
        3. Theft and vandalism
        4. Wind and hail damage
        
        EXCLUSIONS
        This policy does not cover:
        1. Flood damage
        2. Earthquake damage
        3. War and terrorism
        """
        
        result = verifier.verify_fact(claim, context)
        
        # Should find the relevant citation
        assert len(result["citations"]) > 0
        assert result["verdict"] in ["SUPPORTED", "NEUTRAL"]
    
    def test_financial_claim(self, verifier):
        """Test financial claim verification."""
        claim = "Revenue increased by 25% in Q3."
        context = """
        Third Quarter Results:
        Revenue increased by 25% compared to Q2, reaching $500 million.
        Net profit was $50 million, up 30% year-over-year.
        """
        
        result = verifier.verify_fact(claim, context)
        
        # Should find the 25 entity match
        assert result["scores"]["entity_match"] > 0
        assert result["verdict"] in ["SUPPORTED", "NEUTRAL"]
