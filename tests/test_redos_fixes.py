from qwed_new.core.fact_verifier import FactVerifier
from qwed_new.core.image_verifier import ImageVerifier, ImageAnalysisResult

def test_fact_verifier_bounded_regex():
    """
    Test that FactVerifier's new bounded regexes correctly extract entities
    and handle long inputs without crashing.
    """
    verifier = FactVerifier(use_llm_fallback=False)
    
    # 1. Normal Input - Should extract numbers correctly
    claim = "The profit was 10.5 million in 2024."
    context = "In 2024, the company reported 10.5 million profit."
    
    # Analyze - this triggers _match_entities which uses the new \d{1,20} regex
    result = verifier.verify_fact(claim, context)
    
    # Verify entity matching logic still works
    assert "2024" in result["reasoning"] or result["scores"]["entity_match"] > 0.5
    
    # 2. Long Input - Should be truncated/handled safely
    # Create valid sentence structure but very long
    base_sentence = "This is a sentence. "
    long_context = base_sentence * 5000  # ~100k chars
    
    # This triggers _segment_sentences with the new safe_pattern
    result = verifier.verify_fact("test", long_context)
    # Should run without timeout/error
    assert result["verdict"] is not None

def test_image_verifier_bounded_regex():
    """
    Test that ImageVerifier's bounded regexes match valid dimensions
    and reject excessively long claims.
    """
    verifier = ImageVerifier(use_vlm_fallback=False)
    dummy_meta = ImageAnalysisResult(
        width=800, height=600, format="PNG", 
        has_text=False, extracted_text=[], 
        dominant_colors=[], detected_elements=[]
    )
    
    # 1. Valid Dimensions - Should match using the new \d{1,10} regex
    claim_valid = "The image is 800x600 pixels."
    # Use internal method for regex test, but ensure logic holds
    result_valid = verifier._verify_size_claim(claim_valid, dummy_meta)
    
    assert result_valid.verdict == "SUPPORTED"
    assert "Dimensions match" in result_valid.reasoning
    
    # 2. ReDoS Attempt - Should be blocked by length check
    long_claim = "a" * 600
    # Must call verify_image to hit the length guard
    result_blocked = verifier.verify_image(b"fake_bytes", long_claim)
    
    # Note: result_blocked is dict from verify_image, NOT object
    assert result_blocked["verdict"] == "INCONCLUSIVE"
    assert "Claim text too long" in result_blocked["reasoning"]
    
    # 3. Mixed spaces - Should match with bounded \s{0,5}
    claim_spaces = "800   x   600"
    result_spaces = verifier._verify_size_claim(claim_spaces, dummy_meta)
    assert result_spaces.verdict == "SUPPORTED"

def test_graph_verifier_bounded_regex():
    """
    Test that GraphFactVerifier's new bounded regexes correctly extract triples
    and handle long inputs without crashing.
    """
    from qwed_new.core.graph_fact_verifier import GraphFactVerifier, Triple
    
    verifier = GraphFactVerifier(use_spacy=False)
    
    # 1. Normal Input - Should extract triples correctly
    # Pattern 1: X is Y
    text1 = "Narendra Modi is the Prime Minister of India."
    triples1 = verifier._extract_triples_rules(text1)
    assert any(t.subject == "Narendra Modi" and t.object == "Prime Minister of India" for t in triples1)
    
    # Pattern 2: X bought Y
    text2 = "Elon Musk bought Twitter."
    triples2 = verifier._extract_triples_rules(text2)
    assert any(t.subject == "Elon Musk" and t.object == "Twitter" for t in triples2)

    # 2. Long Input (ReDoS Probe) - Should be handled safely
    # Create a string that would explode a bad regex: "A " * 1000 + "is B"
    # The old regex (nested +*) would choke here.
    long_input = ("A " * 2000) + "is B"
    
    # Limit input length if necessary (GraphVerifier default split is by sentence)
    # The new regexes are bounded {1,20} so they shouldn't match "A " * 2000 as a single name,
    # avoiding the pathologically long match attempt.
    triples_long = verifier._extract_triples_rules(long_input)
    # Should finish quickly
    assert isinstance(triples_long, list)
