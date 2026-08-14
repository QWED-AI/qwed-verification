"""
Enterprise Fact Verification Engine.

Verifies factual claims against source context using deterministic methods:
1. Semantic Similarity - TF-IDF cosine similarity
2. Citation Extraction - finds supporting/refuting sentences
3. Keyword Overlap - lexical matching
4. Entity Matching - proper nouns, numbers, dates
5. Negation Detection - identifies conflicts

LLM fallback is advisory-only and never determines the final verdict.
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
import re
import math
import hashlib
import logging
from collections import Counter

from qwed_new.core.diagnostics import (
    AdvisoryCheck,
    DiagnosticResult,
    aggregate_batch_diagnostic,
)

from .verification_context import VerificationContextDocument

logger = logging.getLogger(__name__)

CONSTRAINT_FACT_BATCH_VERIFIED = "fact_verifier.batch_verified"
CONSTRAINT_FACT_BATCH_UNVERIFIABLE = "fact_verifier.batch_unverifiable"
CONSTRAINT_FACT_BATCH_BLOCKED = "fact_verifier.batch_blocked"
CONSTRAINT_FACT_EMPTY_BATCH = "fact_verifier.empty_batch"


@dataclass
class Citation:
    """A citation from the source context."""
    sentence: str
    relevance_score: float
    start_index: int
    end_index: int
    support_type: str  # "supports", "refutes", "neutral"


@dataclass
class FactVerificationResult:
    """Result of fact verification."""
    verdict: str  # "SUPPORTED", "REFUTED", "NEUTRAL", "INSUFFICIENT_EVIDENCE"
    confidence: float  # 0.0 to 1.0
    reasoning: str
    citations: List[Citation] = field(default_factory=list)
    methods_used: List[str] = field(default_factory=list)
    scores: Dict[str, float] = field(default_factory=dict)


class FactVerifier:
    """
    Engine 4: Enterprise Fact Verifier.
    
    Uses deterministic methods for fact verification:
    1. Semantic similarity (TF-IDF based, no ML model needed)
    2. Keyword extraction and matching
    3. Entity extraction (numbers, dates, proper nouns)
    4. Citation extraction with sentence segmentation
    
    The LLM is only consulted as a LAST RESORT when deterministic
    methods cannot provide a confident answer.

    Attributes:
        use_llm_fallback (bool): Whether to use LLM as last resort.
    """
    
    # Stopwords for TF-IDF
    STOPWORDS = {
        'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
        'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'dare',
        'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as',
        'into', 'through', 'during', 'before', 'after', 'above', 'below',
        'between', 'under', 'again', 'further', 'then', 'once', 'here',
        'there', 'when', 'where', 'why', 'how', 'all', 'each', 'few',
        'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not',
        'only', 'own', 'same', 'so', 'than', 'too', 'very', 'just',
        'and', 'but', 'if', 'or', 'because', 'until', 'while', 'although',
        'this', 'that', 'these', 'those', 'it', 'its', 'what', 'which',
        'who', 'whom', 'whose', 'i', 'you', 'he', 'she', 'we', 'they',
        'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'our', 'their'
    }
    
    # Negation words that flip meaning
    NEGATION_WORDS = {
        'not', 'no', 'never', 'none', 'nothing', 'nowhere', 'neither',
        'nobody', "n't", 'cannot', "can't", "won't", "wouldn't", "shouldn't",
        "couldn't", "didn't", "doesn't", "don't", "isn't", "aren't", "wasn't",
        "weren't", "hasn't", "haven't", "hadn't"
    }
    
    # Confirmation words
    CONFIRMATION_WORDS = {
        'yes', 'correct', 'true', 'right', 'indeed', 'certainly', 'definitely',
        'absolutely', 'confirmed', 'verified', 'proven', 'accurate', 'valid'
    }
    
    def __init__(self, use_llm_fallback: bool = True):
        """
        Initialize the Fact Verifier.
        
        Args:
            use_llm_fallback: Whether to use LLM as last resort (default: True).

        Example:
            >>> verifier = FactVerifier(use_llm_fallback=False)
        """
        self.use_llm_fallback = use_llm_fallback
        self._translator = None  # Lazy load
    
    def verify_fact(
        self, 
        claim: str, 
        context: str, 
        provider: Optional[str] = None,
        min_confidence: float = 0.7
    ) -> DiagnosticResult:
        """
        Verify a factual claim against a source context.

        LLM fallback is advisory-only — it populates advisory_checks and
        never overwrites the deterministic verdict (fixes #133).

        Args:
            claim: The statement to verify.
            context: The source text.
            provider: Optional LLM provider for advisory fallback.
            min_confidence: Minimum confidence for deterministic verdict.

        Returns:
            DiagnosticResult — VERIFIED for deterministic SUPPORTED/REFUTED,
            UNVERIFIABLE for NEUTRAL/INSUFFICIENT_EVIDENCE, BLOCKED on error.
        """
        if not claim or not context:
            return DiagnosticResult.unverifiable(
                "Empty claim or context provided",
                {"constraint_id": "fact_verifier.empty_input"}
            )

        methods_used = []
        scores = {}
        advisory_checks = []

        try:
            # Step 1: Segment context into sentences
            sentences = self._segment_sentences(context)

            # Step 2: Find relevant sentences (citations)
            citations = self._find_relevant_sentences(claim, sentences)

            # Step 3: Semantic similarity scoring
            semantic_score = self._calculate_semantic_similarity(claim, context)
            scores["semantic_similarity"] = semantic_score
            methods_used.append({"name": "semantic_similarity", "advisory_only": False})

            # Step 4: Keyword overlap analysis
            keyword_score, keyword_details = self._analyze_keyword_overlap(claim, context)
            scores["keyword_overlap"] = keyword_score
            methods_used.append({"name": "keyword_overlap", "advisory_only": False})

            # Step 5: Entity matching (numbers, dates, names)
            entity_match, entity_details = self._match_entities(claim, context)
            scores["entity_match"] = entity_match
            methods_used.append({"name": "entity_matching", "advisory_only": False})

            # Step 6: Negation detection
            has_negation, negation_details = self._detect_negation_conflict(claim, citations)
            scores["negation_conflict"] = 1.0 if has_negation else 0.0
            methods_used.append({"name": "negation_detection", "advisory_only": False})

            # Step 7: Calculate deterministic verdict
            verdict, confidence, reasoning = self._calculate_verdict(
                semantic_score=semantic_score,
                keyword_score=keyword_score,
                entity_match=entity_match,
                has_negation=has_negation,
                citations=citations,
                keyword_details=keyword_details,
                entity_details=entity_details,
                negation_details=negation_details
            )
        except Exception as exc:
            logger.exception("Fact verification pipeline failed")
            return DiagnosticResult.blocked(
                "Fact verification pipeline failed",
                {"constraint_id": "fact_verifier.execution_error", "error_type": type(exc).__name__},
            )

        # Step 8: LLM fallback is advisory-only (fixes #133), confidence-gated
        llm_advisory = None
        if confidence < min_confidence and self.use_llm_fallback and provider:
            methods_used.append({"name": "llm_fallback", "advisory_only": True})
            llm_result = self._llm_fallback(claim, context, provider)
            if llm_result:
                llm_advisory = AdvisoryCheck(
                    name="llm_fallback",
                    constraint_id="fact_verifier.llm_advisory_only",
                    details={
                        "llm_verdict": llm_result.get("verdict"),
                        "llm_confidence": llm_result.get("confidence"),
                        "llm_reasoning": llm_result.get("reasoning"),
                        "advisory_only": True,
                    }
                )
                advisory_checks.append(llm_advisory)

        developer_fields: Dict[str, Any] = {
            "methods_used": methods_used,
            "deterministic_confidence": round(confidence, 3),
            "deterministic_verdict": verdict,
            "evidence": reasoning,
            "citations": [
                {
                    "sentence": c.sentence,
                    "relevance_score": round(c.relevance_score, 3),
                    "support_type": c.support_type
                }
                for c in citations[:5]
            ],
            "scores": {k: round(v, 3) for k, v in scores.items()},
        }
        if advisory_checks:
            developer_fields["advisory_checks"] = advisory_checks

        # Map deterministic verdict to DiagnosticResult.
        # NOTE (#267): Heuristic analysis (TF-IDF cosine, keyword overlap,
        # entity matching, negation detection) cannot produce VERIFIED.
        # Two different claims with similar token distributions can yield
        # the same heuristic verdict — advisory-only per QWED fail-closed contract.
        if verdict == "SUPPORTED":
            developer_fields["constraint_id"] = "fact_verifier.heuristic_supported"
            advisory_checks.append(
                AdvisoryCheck(
                    name="heuristic_supported",
                    advisory_only=True,
                    constraint_id="fact_verifier.tfidf_cosine_similarity",
                    details={
                        "deterministic_verdict": verdict,
                        # Reuse deterministic_confidence computed once upstream —
                        # never re-round in detail blocks (avoids binary float drift).
                        "confidence": str(developer_fields["deterministic_confidence"]),
                        "reasoning": reasoning,
                        "citations": developer_fields["citations"],
                        "scores": developer_fields["scores"],
                    },
                )
            )
            developer_fields["advisory_checks"] = advisory_checks
            return DiagnosticResult.unverifiable(
                "Fact claim supported by heuristic analysis — not a deterministic proof",
                developer_fields,
            )

        if verdict == "REFUTED":
            developer_fields["constraint_id"] = "fact_verifier.deterministic_refuted"
            return DiagnosticResult.blocked(
                "Fact claim refuted by deterministic analysis — negation conflict detected",
                developer_fields,
            )

        developer_fields["constraint_id"] = "fact_verifier.inconclusive"
        return DiagnosticResult.unverifiable(
            "Fact claim could not be deterministically verified",
            developer_fields,
        )
    
    # =========================================================================
    # Sentence Segmentation
    # =========================================================================
    
    def _segment_sentences(self, text: str) -> List[Tuple[str, int, int]]:
        """
        Segment text into sentences with their positions.
        
        Returns:
            List of (sentence, start_index, end_index)
        """
        if len(text) > 100000:
            text = text[:100000]  # Hard cap to prevent ReDoS on massive inputs
            
        sentences = []
        current_pos = 0

        # Standard ReDoS-safe pattern for English sentences
        # The issue was \s+ which is unbounded. \s{1,50} limits backtracking.
        safe_pattern = r'(?<=[.!?])\s{1,50}(?=[A-Z])'
        
        parts = re.split(safe_pattern, text)
        
        for part in parts:
            part = part.strip()
            if part:
                # Find the part in text efficiently
                start = text.find(part, current_pos)
                if start == -1:
                    # Fallback if strip() messed up strict finding
                     start = current_pos
                end = start + len(part)
                sentences.append((part, start, end))
                current_pos = end
        
        return sentences
    
    # =========================================================================
    # Citation Extraction
    # =========================================================================
    
    def _find_relevant_sentences(
        self, 
        claim: str, 
        sentences: List[Tuple[str, int, int]]
    ) -> List[Citation]:
        """
        Find sentences most relevant to the claim.
        """
        citations = []
        claim_tokens = self._tokenize(claim)
        claim_keywords = claim_tokens - self.STOPWORDS
        
        for sentence, start, end in sentences:
            # Calculate relevance
            sentence_tokens = self._tokenize(sentence)
            sentence_keywords = sentence_tokens - self.STOPWORDS
            
            if not sentence_keywords:
                continue
            
            # Jaccard similarity
            intersection = claim_keywords & sentence_keywords
            union = claim_keywords | sentence_keywords
            relevance = len(intersection) / len(union) if union else 0
            
            if relevance > 0.1:  # Minimum threshold
                # Determine support type based on negation
                support_type = self._determine_support_type(claim, sentence)
                
                citations.append(Citation(
                    sentence=sentence,
                    relevance_score=relevance,
                    start_index=start,
                    end_index=end,
                    support_type=support_type
                ))
        
        # Sort by relevance
        citations.sort(key=lambda x: x.relevance_score, reverse=True)
        return citations
    
    def _determine_support_type(self, claim: str, sentence: str) -> str:
        """Determine if a sentence supports, refutes, or is neutral to the claim."""
        claim_lower = claim.lower()
        sentence_lower = sentence.lower()
        
        # Check for negation in sentence that contradicts claim
        claim_has_negation = any(neg in claim_lower for neg in self.NEGATION_WORDS)
        sentence_has_negation = any(neg in sentence_lower for neg in self.NEGATION_WORDS)
        
        # If negation status differs, likely refutes
        if claim_has_negation != sentence_has_negation:
            return "refutes"
        
        # High overlap without negation conflict = supports
        claim_tokens = self._tokenize(claim) - self.STOPWORDS
        sentence_tokens = self._tokenize(sentence) - self.STOPWORDS
        overlap = len(claim_tokens & sentence_tokens) / len(claim_tokens) if claim_tokens else 0
        
        if overlap > 0.5:
            return "supports"
        elif overlap > 0.2:
            return "neutral"
        else:
            return "neutral"
    
    # =========================================================================
    # Semantic Similarity (TF-IDF based, no ML model)
    # =========================================================================
    
    def _calculate_semantic_similarity(self, claim: str, context: str) -> float:
        """
        Calculate semantic similarity using TF-IDF cosine similarity.
        No external ML models needed.
        """
        # Tokenize
        claim_tokens = self._tokenize(claim)
        context_tokens = self._tokenize(context)
        
        # Build vocabulary
        all_tokens = claim_tokens | context_tokens
        
        # Calculate TF for claim
        claim_tf = Counter(claim_tokens)
        
        # Calculate TF for context
        context_tf = Counter(context_tokens)
        
        # Calculate IDF (simplified: based on presence in claim vs context)
        # This is a simplified IDF since we only have 2 documents
        
        # Calculate TF-IDF vectors
        claim_vector = []
        context_vector = []
        
        for token in all_tokens:
            if token in self.STOPWORDS:
                continue
            
            claim_vector.append(claim_tf.get(token, 0))
            context_vector.append(context_tf.get(token, 0))
        
        # Cosine similarity
        if not claim_vector or not context_vector:
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(claim_vector, context_vector))
        claim_magnitude = math.sqrt(sum(a * a for a in claim_vector))
        context_magnitude = math.sqrt(sum(b * b for b in context_vector))
        
        if claim_magnitude == 0 or context_magnitude == 0:
            return 0.0
        
        return dot_product / (claim_magnitude * context_magnitude)
    
    # =========================================================================
    # Keyword Analysis
    # =========================================================================
    
    def _analyze_keyword_overlap(self, claim: str, context: str) -> Tuple[float, Dict]:
        """
        Analyze keyword overlap between claim and context.
        """
        claim_tokens = self._tokenize(claim) - self.STOPWORDS
        context_tokens = self._tokenize(context) - self.STOPWORDS
        
        if not claim_tokens:
            return 0.0, {"matched": [], "missing": []}
        
        matched = claim_tokens & context_tokens
        missing = claim_tokens - context_tokens
        
        score = len(matched) / len(claim_tokens)
        
        return score, {
            "matched": list(matched),
            "missing": list(missing),
            "total_claim_keywords": len(claim_tokens)
        }
    
    # =========================================================================
    # Entity Matching
    # =========================================================================
    
    def _match_entities(self, claim: str, context: str) -> Tuple[float, Dict]:
        """
        Extract and match entities (numbers, dates, names).
        """
        # Extract numbers (Max 20 digits to avoid ReDoS)
        claim_numbers = set(re.findall(r'\b\d{1,20}(?:\.\d{1,10})?\b', claim))
        context_numbers = set(re.findall(r'\b\d{1,20}(?:\.\d{1,10})?\b', context))
        
        # Extract years (4-digit numbers starting with 1 or 2)
        claim_years = set(re.findall(r'\b[12]\d{3}\b', claim))
        context_years = set(re.findall(r'\b[12]\d{3}\b', context))
        
        # Extract potential proper nouns (capitalized words not at sentence start)
        claim_names = set(re.findall(r'(?<![.!?]\s)[A-Z][a-z]+', claim))
        context_names = set(re.findall(r'(?<![.!?]\s)[A-Z][a-z]+', context))
        
        # Calculate matches
        number_matches = claim_numbers & context_numbers
        year_matches = claim_years & context_years
        name_matches = claim_names & context_names
        
        # Calculate score
        total_entities = len(claim_numbers) + len(claim_years) + len(claim_names)
        matched_entities = len(number_matches) + len(year_matches) + len(name_matches)
        
        if total_entities == 0:
            score = 1.0  # No entities to match = neutral
        else:
            score = matched_entities / total_entities
        
        return score, {
            "numbers": {"in_claim": list(claim_numbers), "matched": list(number_matches)},
            "years": {"in_claim": list(claim_years), "matched": list(year_matches)},
            "names": {"in_claim": list(claim_names), "matched": list(name_matches)}
        }
    
    # =========================================================================
    # Negation Detection
    # =========================================================================
    
    def _detect_negation_conflict(
        self, 
        claim: str, 
        citations: List[Citation]
    ) -> Tuple[bool, Dict]:
        """
        Detect if there's a negation conflict between claim and citations.
        """
        claim_has_negation = any(
            neg in claim.lower() 
            for neg in self.NEGATION_WORDS
        )
        
        conflicts = []
        
        for citation in citations[:3]:  # Check top 3 citations
            sentence_has_negation = any(
                neg in citation.sentence.lower() 
                for neg in self.NEGATION_WORDS
            )
            
            if claim_has_negation != sentence_has_negation:
                conflicts.append({
                    "sentence": citation.sentence[:100],
                    "claim_negated": claim_has_negation,
                    "sentence_negated": sentence_has_negation
                })
        
        return len(conflicts) > 0, {"conflicts": conflicts}
    
    # =========================================================================
    # Verdict Calculation
    # =========================================================================
    
    def _calculate_verdict(
        self,
        semantic_score: float,
        keyword_score: float,
        entity_match: float,
        has_negation: bool,
        citations: List[Citation],
        keyword_details: Dict,
        entity_details: Dict,
        negation_details: Dict
    ) -> Tuple[str, float, str]:
        """
        Calculate final verdict based on all scores.
        """
        # Aggregate score (weighted)
        aggregate = (
            semantic_score * 0.3 +
            keyword_score * 0.3 +
            entity_match * 0.2 +
            (0.0 if has_negation else 0.2)
        )
        
        # Check citation support types
        support_citations = [c for c in citations if c.support_type == "supports"]
        refute_citations = [c for c in citations if c.support_type == "refutes"]
        
        # Build reasoning
        reasoning_parts = []
        
        if keyword_details.get("matched"):
            reasoning_parts.append(f"Keywords matched: {', '.join(keyword_details['matched'][:5])}")
        if keyword_details.get("missing"):
            reasoning_parts.append(f"Keywords not found: {', '.join(keyword_details['missing'][:3])}")
        
        entity_info = entity_details.get("numbers", {})
        if entity_info.get("matched"):
            reasoning_parts.append(f"Numbers matched: {', '.join(entity_info['matched'])}")
        
        if has_negation:
            reasoning_parts.append("Warning: Negation conflict detected")
        
        reasoning = ". ".join(reasoning_parts) if reasoning_parts else "Analysis complete."
        
        # Determine verdict
        if has_negation and len(refute_citations) > len(support_citations):
            verdict = "REFUTED"
            confidence = min(0.9, aggregate + 0.2)
        elif aggregate >= 0.7 and len(support_citations) >= len(refute_citations):
            verdict = "SUPPORTED"
            confidence = aggregate
        elif aggregate >= 0.4:
            verdict = "NEUTRAL"
            confidence = aggregate
        elif aggregate >= 0.2:
            verdict = "INSUFFICIENT_EVIDENCE"
            confidence = aggregate
        else:
            verdict = "INSUFFICIENT_EVIDENCE"
            confidence = aggregate
        
        return verdict, confidence, reasoning
    
    # =========================================================================
    # LLM Fallback (Last Resort)
    # =========================================================================
    
    def _llm_fallback(
        self, 
        claim: str, 
        context: str, 
        provider: str
    ) -> Optional[Dict]:
        """
        Use LLM as last resort when deterministic methods are insufficient.
        """
        try:
            if self._translator is None:
                from qwed_new.core.translator import TranslationLayer
                self._translator = TranslationLayer()
            
            return self._translator.verify_fact(claim, context, provider=provider)
        except Exception:
            return None
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    def _tokenize(self, text: str) -> set:
        """Tokenize text into lowercase words."""
        return set(re.findall(r'\b[a-zA-Z]+\b', text.lower()))

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="FactVerifier",
        )



# =============================================================================
# Batch Verification
# =============================================================================


class BatchFactVerifier:
    """
    Batch verification for multiple claims against a single context.

    Attributes:
        verifier (FactVerifier): The underlying verifier instance.
    """
    
    def __init__(self):
        """Initialize BatchFactVerifier."""
        self.verifier = FactVerifier()
    
    def verify_batch(
        self, 
        claims: List[str], 
        context: str,
        provider: Optional[str] = None
    ) -> DiagnosticResult:
        """
        Verify multiple claims against the same context.

        Returns a single :class:`DiagnosticResult`. Per-claim verdicts live in
        ``developer_fields.results`` (each a serialized per-claim
        DiagnosticResult) and ``developer_fields.summary``.

        The batch is authoritative (VERIFIED with ``proof_ref``) only when every
        claim is deterministically verified. A batch containing any refuted,
        blocked, or inconclusive claim returns BLOCKED/UNVERIFIABLE (non-
        authoritative, ``proof_ref`` None) so generic consumers that admit on
        ``is_authoritative`` can never accept a partially-proven batch.

        Args:
            claims: List of claims to verify.
            context: The source context text.
            provider: Optional LLM provider.

        Example:
            >>> batch = verifier.verify_batch(["Claim 1", "Claim 2"], "context")
            >>> print(batch.developer_fields["summary"]["verified"])
        """
        items: List[Dict[str, Any]] = []
        for claim in claims:
            result = self.verifier.verify_fact(claim, context, provider)
            serialized = result.to_dict()
            serialized["claim"] = claim
            items.append(serialized)

        # Bind the shared source context into the batch proof so the verdict can
        # be re-derived from the evidence (same claims against a different context
        # must not share a proof).
        extra_evidence: Dict[str, Any] = {}
        if isinstance(context, str):
            extra_evidence["context_sha256"] = hashlib.sha256(
                context.encode("utf-8")
            ).hexdigest()

        # NOTE: the VERIFIED branch of the shared aggregator is future-facing for
        # this engine — ``verify_fact`` maps heuristic SUPPORTED to UNVERIFIABLE
        # (#267), so a fact batch is currently never authoritative. The branch is
        # retained (mirroring ``stats_verifier.CONSTRAINT_STATS_VALID``) so a
        # future deterministic fact-proof path can produce an authoritative batch
        # without weakening the fail-closed contract.
        return aggregate_batch_diagnostic(
            items,
            claims,
            engine="FactVerifier",
            constraints={
                "verified": CONSTRAINT_FACT_BATCH_VERIFIED,
                "blocked": CONSTRAINT_FACT_BATCH_BLOCKED,
                "unverifiable": CONSTRAINT_FACT_BATCH_UNVERIFIABLE,
                "empty": CONSTRAINT_FACT_EMPTY_BATCH,
            },
            messages={
                "empty": "Batch fact verification failed: no claims were provided.",
                "blocked": (
                    "Batch fact verification flagged refuted or failed claims; "
                    "the batch is not admissible."
                ),
                "unverifiable": (
                    "Batch fact verification is inconclusive: some claims could "
                    "not be deterministically verified."
                ),
                "verified": "Batch fact verification succeeded: all claims were verified.",
            },
            extra_evidence=extra_evidence,
        )

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="BatchFactVerifier",
        )


