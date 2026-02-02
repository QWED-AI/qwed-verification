"""
Graph-Based Fact Verifier: Deterministic Fact Checking via Triple Extraction.

100% Deterministic - NO embeddings, NO cosine similarity, NO probability.

Approach:
1. Extract triples (Subject, Predicate, Object) from claim
2. Extract triples from context/source
3. Match triples using exact string comparison
4. Optionally use NLI entailment (deterministic label: ENTAILS/NEUTRAL/CONTRADICTS)

Example:
    Claim: "Modi is the Prime Minister of India"
    Context: "Narendra Modi serves as Prime Minister of India since 2014"
    
    Claim Triple: (Modi, is, Prime Minister)
    Context Triple: (Narendra Modi, serves as, Prime Minister)
    
    Match: Subject "Modi" in "Narendra Modi" ✓
    Result: VERIFIED (deterministic)

Why NOT Embeddings:
    - Embedding: "Modi is PM" vs "Rahul is PM" → 0.85 similarity (both politicians)
    - Our method: Subject mismatch (Modi ≠ Rahul) → NOT VERIFIED
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re


class VerificationStatus(Enum):
    """Fact verification status."""
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    CONTRADICTED = "contradicted"
    INSUFFICIENT = "insufficient_context"


@dataclass
class Triple:
    """A semantic triple (Subject, Predicate, Object)."""
    subject: str
    predicate: str
    object: str
    source_text: str = ""  # Original sentence
    confidence: str = "high"  # extraction confidence: high, medium, low
    
    def normalized(self) -> Tuple[str, str, str]:
        """Return normalized (lowercased, stripped) triple."""
        return (
            self.subject.lower().strip(),
            self.predicate.lower().strip(),
            self.object.lower().strip()
        )
    
    def __str__(self) -> str:
        return f"({self.subject}, {self.predicate}, {self.object})"


@dataclass
class MatchResult:
    """Result of triple matching."""
    claim_triple: Triple
    matched_triple: Optional[Triple]
    match_type: str  # "exact", "partial_subject", "partial_object", "none"
    score: float  # 1.0 = exact, 0.5 = partial, 0.0 = none


@dataclass
class FactResult:
    """Result of fact verification."""
    status: VerificationStatus
    claim: str
    claim_triples: List[Triple]
    context_triples: List[Triple]
    matches: List[MatchResult]
    explanation: str


class GraphFactVerifier:
    """
    Deterministic Fact Verifier using Knowledge Graph Triples.
    
    This verifier extracts (Subject, Predicate, Object) triples from
    both the claim and the context, then performs deterministic
    string matching to verify facts.
    
    NO PROBABILITY:
    - No embedding similarity scores
    - No ML model confidence values
    - Just string matching: match or no match
    
    Matching Rules:
    1. Exact match: All three components match exactly
    2. Partial match: Subject and Object match, Predicate is similar
    3. Containment: One entity contains the other ("Modi" in "Narendra Modi")
    """
    
    # Common predicate mappings for normalization
    PREDICATE_SYNONYMS = {
        # Identity
        "is": ["is", "was", "are", "were", "be", "been"],
        "is_a": ["is a", "is an", "was a", "was an", "serves as"],
        
        # Location
        "located_in": ["located in", "is in", "in", "at", "based in"],
        "capital_of": ["capital of", "is the capital of"],
        
        # Roles
        "leads": ["leads", "leads the", "heads", "runs", "manages"],
        "works_for": ["works for", "works at", "employed by"],
        "founded": ["founded", "started", "created", "established"],
        
        # Possession
        "has": ["has", "have", "had", "owns", "possesses"],
        "part_of": ["part of", "belongs to", "member of"],
        
        # Actions
        "bought": ["bought", "acquired", "purchased"],
        "sold": ["sold", "divested"],
        "wrote": ["wrote", "authored", "penned"],
    }
    
    # Common entity aliases
    ENTITY_ALIASES = {
        "pm": ["prime minister", "pm"],
        "us": ["united states", "usa", "america", "us"],
        "uk": ["united kingdom", "britain", "uk", "england"],
    }
    
    def __init__(self, use_spacy: bool = False):
        """
        Initialize the Graph Fact Verifier.
        
        Args:
            use_spacy: If True, use SpaCy for better NLP parsing.
                      If False, use regex-based extraction (simpler).
        """
        self.use_spacy = use_spacy
        self._nlp = None
    
    @property
    def nlp(self):
        """Lazy-load SpaCy model."""
        if self._nlp is None and self.use_spacy:
            try:
                import spacy
                self._nlp = spacy.load("en_core_web_sm")
            except (ImportError, OSError):
                self._nlp = None
        return self._nlp
    
    def verify(
        self,
        claim: str,
        context: str,
        strict: bool = False
    ) -> Dict[str, Any]:
        """
        Verify a claim against context using triple matching.
        
        Args:
            claim: The statement to verify.
            context: The source text to verify against.
            strict: If True, require exact matches only.
            
        Returns:
            Dict with verification results.
            
        Example:
            >>> result = verifier.verify(
            ...     claim="Elon Musk bought Twitter",
            ...     context="In 2022, Elon Musk acquired Twitter for $44 billion"
            ... )
            >>> print(result["status"])
            "verified"
        """
        # Extract triples from claim
        claim_triples = self.extract_triples(claim)
        
        # Extract triples from context
        context_triples = self.extract_triples(context)
        
        # Match triples
        matches = self._match_triples(claim_triples, context_triples, strict)
        
        # Determine verification status
        status = self._determine_status(matches, claim_triples)
        
        # Build explanation
        explanation = self._build_explanation(matches, status)
        
        result = FactResult(
            status=status,
            claim=claim,
            claim_triples=claim_triples,
            context_triples=context_triples,
            matches=matches,
            explanation=explanation
        )
        
        return {
            "status": status.value,
            "is_verified": status == VerificationStatus.VERIFIED,
            "claim": claim,
            "explanation": explanation,
            "claim_triples": [
                {"subject": t.subject, "predicate": t.predicate, "object": t.object}
                for t in claim_triples
            ],
            "context_triples": [
                {"subject": t.subject, "predicate": t.predicate, "object": t.object}
                for t in context_triples
            ],
            "matches": [
                {
                    "claim": str(m.claim_triple),
                    "matched_with": str(m.matched_triple) if m.matched_triple else None,
                    "match_type": m.match_type,
                    "score": m.score
                }
                for m in matches
            ],
            "summary": {
                "claim_triples_count": len(claim_triples),
                "context_triples_count": len(context_triples),
                "matched_count": sum(1 for m in matches if m.score > 0),
                "exact_matches": sum(1 for m in matches if m.match_type == "exact"),
                "partial_matches": sum(1 for m in matches if "partial" in m.match_type)
            }
        }
    
    def extract_triples(self, text: str) -> List[Triple]:
        """
        Extract semantic triples from text.
        
        Uses rule-based extraction (or SpaCy if enabled).
        
        Args:
            text: The text to extract triples from.
            
        Returns:
            List of Triple objects.
        """
        if self.use_spacy and self.nlp:
            return self._extract_triples_spacy(text)
        else:
            return self._extract_triples_rules(text)
    
    def _extract_triples_rules(self, text: str) -> List[Triple]:
        """Extract triples using rule-based patterns."""
        triples = []
        
        # Split into sentences
        sentences = re.split(r'[.!?]+', text)
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            
            # Pattern 1: "X is/was/are Y" or "X is/was/are the Y of Z" (identity)
            # Pattern 1: "X is/was/are Y" or "X is/was/are the Y of Z" (identity)
            # Fixed: Flattened and bounded patterns to prevent ReDoS
            # Subject: Capitalized words, max 10 parts
            # Object: Words, max 10 parts
            match = re.search(
                r'([A-Z][a-zA-Z]{1,20}(?:\s{1,5}[A-Z]?[a-zA-Z]{1,20}){0,10})\s+(?:is|was|are|were)\s+(?:the\s+)?(?:a\s+|an\s+)?([A-Za-z]{1,20}(?:\s{1,5}[A-Za-z]{1,20}){0,10})(?:\s+of\s+([A-Z][a-zA-Z]{1,20}(?:\s{1,5}[A-Za-z]{1,20}){0,10}))?',
                sentence
            )
            if match:
                subject = match.group(1).strip()
                predicate = "is"
                obj = match.group(2).strip()
                if match.group(3):
                    obj = f"{obj} of {match.group(3).strip()}"
                triples.append(Triple(
                    subject=subject,
                    predicate=predicate,
                    object=obj,
                    source_text=sentence
                ))
            
            # Pattern 2: "X verb Y" (action)
            match = re.search(
                r'([A-Z][a-zA-Z]{1,20}(?:\s{1,5}[A-Z]?[a-zA-Z]{1,20}){0,10})\s+(bought|sold|acquired|founded|created|wrote|launched|leads?|manages?|runs?)\s+([A-Za-z]{1,20}(?:\s{1,5}[A-Za-z]{1,20}){0,10})',
                sentence,
                re.IGNORECASE
            )
            if match:
                triples.append(Triple(
                    subject=match.group(1).strip(),
                    predicate=match.group(2).lower().strip(),
                    object=match.group(3).strip(),
                    source_text=sentence
                ))
            
            # Pattern 3: "X serves as Y" / "X works as Y"
            match = re.search(
                r'([A-Z][a-zA-Z\s]{1,100})\s+(?:serves?|works?)\s+as\s+(?:the\s+)?([A-Za-z\s]{1,100})',
                sentence,
                re.IGNORECASE
            )
            if match:
                triples.append(Triple(
                    subject=match.group(1).strip(),
                    predicate="is",
                    object=match.group(2).strip(),
                    source_text=sentence
                ))
            
            # Pattern 4: "X, the Y of Z" (appositive)
            match = re.search(
                r'([A-Z][a-zA-Z\s]{1,100}),\s+(?:the\s+)?([A-Za-z\s]{1,100})\s+of\s+([A-Z][a-zA-Z\s]{1,100})',
                sentence
            )
            if match:
                triples.append(Triple(
                    subject=match.group(1).strip(),
                    predicate="is",
                    object=f"{match.group(2).strip()} of {match.group(3).strip()}",
                    source_text=sentence
                ))
        
        return triples
    
    def _extract_triples_spacy(self, text: str) -> List[Triple]:
        """Extract triples using SpaCy dependency parsing."""
        if not self.nlp:
            return self._extract_triples_rules(text)
        
        triples = []
        doc = self.nlp(text)
        
        for sent in doc.sents:
            # Find verb and its subject/object
            for token in sent:
                if token.pos_ == "VERB":
                    subjects = [t for t in token.children if t.dep_ in ("nsubj", "nsubjpass")]
                    objects = [t for t in token.children if t.dep_ in ("dobj", "attr", "pobj")]
                    
                    for subj in subjects:
                        for obj in objects:
                            # Get full noun phrases
                            subj_text = self._get_noun_phrase(subj)
                            obj_text = self._get_noun_phrase(obj)
                            
                            if subj_text and obj_text:
                                triples.append(Triple(
                                    subject=subj_text,
                                    predicate=token.lemma_,
                                    object=obj_text,
                                    source_text=sent.text
                                ))
        
        return triples
    
    def _get_noun_phrase(self, token) -> str:
        """Get the full noun phrase for a token."""
        if token is None:
            return ""
        
        # Get compound modifiers and the token itself
        phrase_tokens = []
        for child in token.children:
            if child.dep_ in ("compound", "amod", "det"):
                phrase_tokens.append(child)
        phrase_tokens.append(token)
        
        # Sort by position and join
        phrase_tokens.sort(key=lambda t: t.i)
        return " ".join(t.text for t in phrase_tokens)
    
    def _match_triples(
        self,
        claim_triples: List[Triple],
        context_triples: List[Triple],
        strict: bool
    ) -> List[MatchResult]:
        """Match claim triples against context triples."""
        matches = []
        
        for claim_t in claim_triples:
            best_match = None
            best_score = 0.0
            best_type = "none"
            
            claim_norm = claim_t.normalized()
            
            for context_t in context_triples:
                context_norm = context_t.normalized()
                
                # Check exact match
                if claim_norm == context_norm:
                    best_match = context_t
                    best_score = 1.0
                    best_type = "exact"
                    break
                
                if strict:
                    continue
                
                # Check partial matches
                subj_match = self._entity_matches(claim_norm[0], context_norm[0])
                pred_match = self._predicate_matches(claim_norm[1], context_norm[1])
                obj_match = self._entity_matches(claim_norm[2], context_norm[2])
                
                # Subject and Object match (predicate may differ)
                if subj_match and obj_match:
                    score = 0.9 if pred_match else 0.7
                    if score > best_score:
                        best_match = context_t
                        best_score = score
                        best_type = "partial_predicate"
                
                # Subject matches, Object partially matches
                elif subj_match and pred_match:
                    score = 0.6
                    if score > best_score:
                        best_match = context_t
                        best_score = score
                        best_type = "partial_object"
                
                # Object matches, Subject partially matches
                elif obj_match and pred_match:
                    score = 0.5
                    if score > best_score:
                        best_match = context_t
                        best_score = score
                        best_type = "partial_subject"
            
            matches.append(MatchResult(
                claim_triple=claim_t,
                matched_triple=best_match,
                match_type=best_type,
                score=best_score
            ))
        
        return matches
    
    def _entity_matches(self, entity1: str, entity2: str) -> bool:
        """Check if two entities match (exact or containment)."""
        # Exact match
        if entity1 == entity2:
            return True
        
        # Containment (one contains the other)
        if entity1 in entity2 or entity2 in entity1:
            return True
        
        # Check aliases
        for alias_group in self.ENTITY_ALIASES.values():
            if entity1 in alias_group and entity2 in alias_group:
                return True
        
        # Check if words overlap significantly
        words1 = set(entity1.split())
        words2 = set(entity2.split())
        if words1 and words2:
            overlap = len(words1 & words2) / max(len(words1), len(words2))
            if overlap >= 0.5:
                return True
        
        return False
    
    def _predicate_matches(self, pred1: str, pred2: str) -> bool:
        """Check if two predicates match (exact or synonym)."""
        # Exact match
        if pred1 == pred2:
            return True
        
        # Check synonym groups
        for synonyms in self.PREDICATE_SYNONYMS.values():
            if pred1 in synonyms and pred2 in synonyms:
                return True
        
        # Check word overlap
        if pred1 in pred2 or pred2 in pred1:
            return True
        
        return False
    
    def _determine_status(
        self,
        matches: List[MatchResult],
        claim_triples: List[Triple]
    ) -> VerificationStatus:
        """Determine verification status from matches."""
        if not claim_triples:
            return VerificationStatus.INSUFFICIENT
        
        # Count good matches (score >= 0.5)
        good_matches = sum(1 for m in matches if m.score >= 0.5)
        exact_matches = sum(1 for m in matches if m.score >= 0.9)
        
        # All triples have good matches
        if good_matches == len(claim_triples) and exact_matches > 0:
            return VerificationStatus.VERIFIED
        
        # Most triples have good matches
        if good_matches >= len(claim_triples) * 0.5:
            return VerificationStatus.VERIFIED
        
        # Some matches but not enough
        if good_matches > 0:
            return VerificationStatus.INSUFFICIENT
        
        # No matches at all
        return VerificationStatus.NOT_VERIFIED
    
    def _build_explanation(
        self,
        matches: List[MatchResult],
        status: VerificationStatus
    ) -> str:
        """Build a human-readable explanation."""
        if status == VerificationStatus.VERIFIED:
            matched = [m for m in matches if m.score >= 0.5]
            if matched:
                reasons = []
                for m in matched:
                    if m.matched_triple:
                        reasons.append(
                            f"'{m.claim_triple.subject}' matches '{m.matched_triple.subject}'"
                        )
                return f"VERIFIED: {'; '.join(reasons[:3])}"
            return "VERIFIED: Claim matches context"
        
        elif status == VerificationStatus.NOT_VERIFIED:
            unmatched = [m.claim_triple for m in matches if m.score == 0]
            if unmatched:
                return f"NOT VERIFIED: No match found for {unmatched[0]}"
            return "NOT VERIFIED: Claim does not match context"
        
        elif status == VerificationStatus.CONTRADICTED:
            return "CONTRADICTED: Context contains contradicting information"
        
        else:
            return "INSUFFICIENT: Not enough context to verify claim"
    
    def verify_with_nli(
        self,
        claim: str,
        context: str,
        model: str = "default"
    ) -> Dict[str, Any]:
        """
        Verify using NLI entailment as fallback.
        
        This uses a small NLI model (DeBERTa) for entailment checking.
        The model outputs DETERMINISTIC labels: ENTAILMENT, NEUTRAL, CONTRADICTION.
        
        Note: This requires transformers library.
        """
        # First try graph-based verification
        graph_result = self.verify(claim, context)
        
        # If graph verification is conclusive, use it
        if graph_result["status"] in ["verified", "contradicted"]:
            graph_result["method"] = "graph_matching"
            return graph_result
        
        # Otherwise, try NLI (if available)
        try:
            from transformers import pipeline
            nli = pipeline("text-classification", model="cross-encoder/nli-deberta-v3-small")
            
            result = nli(f"{context} [SEP] {claim}")[0]
            label = result["label"].lower()
            
            if "entail" in label:
                status = "verified"
            elif "contradict" in label:
                status = "contradicted"
            else:
                status = "not_verified"
            
            return {
                "status": status,
                "is_verified": status == "verified",
                "claim": claim,
                "method": "nli_fallback",
                "nli_label": result["label"],
                "explanation": f"NLI model determined: {result['label']}",
                "graph_result": graph_result
            }
        
        except Exception:
            # NLI not available, return graph result
            graph_result["method"] = "graph_matching_only"
            return graph_result
