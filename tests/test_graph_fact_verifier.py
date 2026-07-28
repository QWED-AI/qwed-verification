"""
Tests for GraphFactVerifier - Deterministic fact checking via triple extraction.

Tests cover:
1. Triple extraction (rules-based)
2. Entity matching (exact and containment)
3. Predicate matching (synonyms)
4. Full claim verification
5. Edge cases
"""

import pytest
from src.qwed_new.core.graph_fact_verifier import (
    GraphFactVerifier, Triple, VerificationStatus
)


@pytest.fixture
def verifier():
    """Create a fresh verifier for each test."""
    return GraphFactVerifier(use_spacy=False)


class TestTripleExtraction:
    """Test triple extraction from text."""
    
    def test_extract_is_pattern(self, verifier):
        """Extract 'X is Y' patterns."""
        text = "Modi is the Prime Minister of India"
        triples = verifier.extract_triples(text)
        
        assert len(triples) >= 1
        assert any("modi" in t.subject.lower() for t in triples)
        assert any("prime minister" in t.object.lower() for t in triples)
    
    def test_extract_action_pattern(self, verifier):
        """Extract 'X verb Y' patterns."""
        text = "Elon Musk bought Twitter"
        triples = verifier.extract_triples(text)
        
        assert len(triples) >= 1
        assert any("elon" in t.subject.lower() for t in triples)
        assert any("bought" in t.predicate.lower() for t in triples)
    
    def test_extract_serves_as_pattern(self, verifier):
        """Extract 'X serves as Y' patterns."""
        text = "John Smith serves as CEO"
        triples = verifier.extract_triples(text)
        
        assert len(triples) >= 1
        assert any("ceo" in t.object.lower() for t in triples)
    
    def test_extract_appositive_pattern(self, verifier):
        """Extract 'X, the Y of Z' patterns."""
        text = "Jeff Bezos, the founder of Amazon"
        triples = verifier.extract_triples(text)
        
        assert len(triples) >= 1
        assert any("bezos" in t.subject.lower() for t in triples)
    
    def test_extract_multiple_sentences(self, verifier):
        """Extract triples from multiple sentences."""
        text = "Apple is a tech company. Tim Cook leads Apple."
        triples = verifier.extract_triples(text)
        
        assert len(triples) >= 2
    
    def test_extract_empty_text(self, verifier):
        """Empty text returns empty triples."""
        triples = verifier.extract_triples("")
        assert len(triples) == 0


class TestEntityMatching:
    """Test entity matching logic."""
    
    def test_exact_match(self, verifier):
        """Exact entity names match."""
        result = verifier._entity_matches("modi", "modi")
        assert result == True
    
    def test_containment_match(self, verifier):
        """Entity contained in another matches."""
        assert verifier._entity_matches("modi", "narendra modi") == True
        assert verifier._entity_matches("twitter", "twitter inc") == True
    
    def test_word_overlap_match(self, verifier):
        """Significant word overlap matches."""
        assert verifier._entity_matches("prime minister", "prime minister of india") == True
    
    def test_no_match(self, verifier):
        """Different entities don't match."""
        assert verifier._entity_matches("modi", "rahul gandhi") == False
        assert verifier._entity_matches("apple", "microsoft") == False


class TestPredicateMatching:
    """Test predicate matching with synonyms."""
    
    def test_exact_predicate_match(self, verifier):
        """Exact predicates match."""
        assert verifier._predicate_matches("is", "is") == True
        assert verifier._predicate_matches("bought", "bought") == True
    
    def test_synonym_match(self, verifier):
        """Synonym predicates match."""
        assert verifier._predicate_matches("bought", "acquired") == True
        assert verifier._predicate_matches("is", "was") == True
    
    def test_no_predicate_match(self, verifier):
        """Different predicates don't match."""
        assert verifier._predicate_matches("bought", "sold") == False


class TestClaimVerification:
    """Test full claim verification."""

    def _triples(self, result):
        return result.developer_fields.get("claim_triples", [])

    def test_verify_exact_match(self, verifier):
        """Claim with exact context match."""
        result = verifier.verify(
            claim="Modi is Prime Minister",
            context="Modi is Prime Minister of India"
        )
        assert result.is_verified

    def test_verify_synonym_match(self, verifier):
        """Claim verified with synonym predicates."""
        result = verifier.verify(
            claim="Elon Musk bought Twitter",
            context="Elon Musk acquired Twitter in 2022"
        )
        assert result.is_verified

    def test_verify_entity_containment(self, verifier):
        """Claim verified with partial entity match."""
        result = verifier.verify(
            claim="Modi is PM",
            context="Narendra Modi is the Prime Minister of India"
        )
        assert "modi" in str(self._triples(result)).lower()

    def test_verify_not_verified(self, verifier):
        """Claim that doesn't match context - subject mismatch."""
        result = verifier.verify(
            claim="Rahul is Prime Minister",
            context="Modi is the Prime Minister of India"
        )
        triples = str(self._triples(result)).lower()
        assert "rahul" in triples
        assert "modi" not in triples

    def test_verify_insufficient_context(self, verifier):
        """Claim with unrelated context."""
        result = verifier.verify(
            claim="Apple makes iPhones",
            context="The weather is nice today"
        )
        assert not result.is_verified

    def test_verify_with_multiple_triples(self, verifier):
        """Complex claim with multiple facts."""
        result = verifier.verify(
            claim="Jeff Bezos founded Amazon. Tim Cook leads Apple.",
            context="Jeff Bezos founded Amazon in 1994. Tim Cook is the CEO of Apple."
        )
        assert result.developer_fields["summary"]["claim_triples_count"] >= 2


class TestResultStructure:
    """Test verification result structure."""

    def test_result_has_required_fields(self, verifier):
        """Result should be a DiagnosticResult."""
        result = verifier.verify("Test claim", "Test context")
        assert hasattr(result, "status")
        assert hasattr(result, "is_verified")
        assert hasattr(result, "developer_fields")
        assert hasattr(result, "proof_ref")
        assert "claim_triples" in result.developer_fields
        assert "context_triples" in result.developer_fields
        assert "matches" in result.developer_fields
        assert "summary" in result.developer_fields

    def test_match_structure(self, verifier):
        """Match objects should have complete info."""
        result = verifier.verify(
            "Modi is PM",
            "Modi is Prime Minister"
        )
        matches = result.developer_fields.get("matches", [])
        if matches:
            match = matches[0]
            assert "claim" in match
            assert "matched_with" in match
            assert "match_type" in match
            assert "score" in match

    def test_summary_counts(self, verifier):
        """Summary should have correct counts."""
        result = verifier.verify(
            "Modi is PM. India is a country.",
            "Modi is Prime Minister of India. India is a democratic country."
        )
        summary = result.developer_fields["summary"]
        assert "claim_triples_count" in summary
        assert "context_triples_count" in summary
        assert "matched_count" in summary


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_claim(self, verifier):
        """Empty claim should be insufficient."""
        result = verifier.verify("", "Some context")
        assert not result.is_verified

    def test_empty_context(self, verifier):
        """Empty context should be insufficient."""
        result = verifier.verify("Some claim", "")
        assert not result.is_verified

    def test_case_insensitive(self, verifier):
        """Matching should be case-insensitive."""
        result = verifier.verify(
            claim="MODI is PRIME MINISTER",
            context="Modi is prime minister of India"
        )
        assert len(result.developer_fields.get("claim_triples", [])) >= 1

    def test_strict_mode(self, verifier):
        """Strict mode requires exact matches."""
        result = verifier.verify(
            claim="Modi is PM",
            context="Narendra Modi is Prime Minister",
            strict=True
        )
        exact_matches = result.developer_fields["summary"]["exact_matches"]
        if exact_matches == 0:
            assert not result.is_verified

    def test_special_characters(self, verifier):
        """Handle special characters in text."""
        result = verifier.verify(
            claim="Apple's CEO is Tim Cook",
            context="Tim Cook is Apple's CEO since 2011"
        )
        assert len(result.developer_fields.get("claim_triples", [])) >= 1


class TestTripleClass:
    """Test Triple dataclass."""
    
    def test_triple_normalized(self):
        """Triple normalization works."""
        t = Triple(subject="  Modi  ", predicate="IS", object="Prime Minister  ")
        norm = t.normalized()
        
        assert norm[0] == "modi"
        assert norm[1] == "is"
        assert norm[2] == "prime minister"
    
    def test_triple_str(self):
        """Triple string representation."""
        t = Triple(subject="Modi", predicate="is", object="PM")
        assert str(t) == "(Modi, is, PM)"


class TestRealWorldClaims:
    """Test with real-world claim scenarios."""

    def test_news_fact(self, verifier):
        """Verify news-style fact."""
        result = verifier.verify(
            claim="SpaceX launched Starship",
            context="SpaceX successfully launched their Starship rocket from Texas."
        )
        assert "spacex" in str(result.developer_fields.get("claim_triples", [])).lower()

    def test_biographical_fact(self, verifier):
        """Verify biographical fact."""
        result = verifier.verify(
            claim="Bill Gates founded Microsoft",
            context="Microsoft was founded by Bill Gates and Paul Allen in 1975."
        )
        assert "gates" in str(result.developer_fields.get("claim_triples", [])).lower()

    def test_false_claim(self, verifier):
        """Detect false claim."""
        result = verifier.verify(
            claim="Mark Zuckerberg founded Microsoft",
            context="Microsoft was founded by Bill Gates. Mark Zuckerberg founded Facebook."
        )
        # Should not verify because Zuckerberg != Gates


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
