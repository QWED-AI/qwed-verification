"""
Enterprise Image Verification Engine.

Verifies claims about visual content using deterministic methods:
1. OCR - Extract text from images
2. Chart/Graph Analysis - Parse data visualizations
3. Color Analysis - Verify color-based claims
4. Object Detection (descriptive) - Basic shape/object identification
5. Multi-VLM Consensus - Cross-validate with multiple vision models

This is NOT a simple VLM passthrough. Deterministic methods are tried first,
and VLM is only used for claims that require semantic understanding.
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
import re
import struct
import hashlib

from qwed_new.core.diagnostics import (
    AdvisoryCheck,
    DiagnosticResult,
    aggregate_batch_diagnostic,
)

from .verification_context import VerificationContextDocument

_INCONCLUSIVE_MSG = "Image verification inconclusive"

_CONSTRAINT_IMAGE_BATCH_VERIFIED = "image_verifier.batch_verified"
_CONSTRAINT_IMAGE_BATCH_UNVERIFIABLE = "image_verifier.batch_unverifiable"
_CONSTRAINT_IMAGE_BATCH_BLOCKED = "image_verifier.batch_blocked"
_CONSTRAINT_IMAGE_EMPTY_BATCH = "image_verifier.empty_batch"

# Size claims (#320). A size claim is decided only when the whole claim is a
# plain statement of the image's width, height or both, such as "800x600",
# "the image is 800x600 pixels", "the width is 800" or "the image is 800
# pixels wide and 600 pixels tall", and every dimension it names is checked.
# Anything else is inconclusive: a negation ("not 800x600", "not HD"), a
# comparison, or a claim that says more than the dimensions ("this 800x600
# image shows ..."), which the dimensions cannot decide. "HD" is a convention,
# not a measurement, so it is not checked. A unit ("pixels", "px") is dropped
# before the claim is read, so "800 pixels" is 800.
_UNIT = re.compile(r" ?(?:px|pixels?)\b")
_NUM = r"(\d{1,10})"
_THE = r"(?:(?:the|this) )?"
_SUBJECT = r"(?:image|picture|photo)"
_IMAGE = _THE + _SUBJECT
_OF_IMAGE = _THE + r"(?:" + _SUBJECT + r"(?:'s)? )?"
_BY = _NUM + r" ?x ?" + _NUM
_SIZE_CLAIMS = (
    re.compile(_BY),
    re.compile(_IMAGE + r" (?:is|measures) " + _BY),
    re.compile(_OF_IMAGE + r"(?:dimensions|size|resolution) (?:is|are) " + _BY),
)
_SIDE_CLAIMS = (
    re.compile(_OF_IMAGE + r"(width|height)(?: is|:| of| =) ?" + _NUM),
    re.compile(_IMAGE + r" has a (width|height) of " + _NUM),
    re.compile(_IMAGE + r" is " + _NUM + r" (wide|tall|high)"),
    re.compile(_NUM + r" (wide|tall|high)"),
)
_SIDES = {"width": "width", "wide": "width", "height": "height", "tall": "height", "high": "height"}


def _claimed_size(claim: str) -> Optional[Dict[str, int]]:
    """The width and height a claim states, by side, when the whole claim is a
    plain statement of them (#320), or None."""
    text = _UNIT.sub("", " ".join(claim.lower().replace("\u00d7", "x").split()).removesuffix("."))
    for pattern in _SIZE_CLAIMS:
        match = pattern.fullmatch(text)
        if match:
            return {"width": int(match.group(1)), "height": int(match.group(2))}
    parts = text.split(" and ")
    if len(parts) > 2:
        return None
    sides: Dict[str, int] = {}
    for part in parts:
        side = _claimed_side(part)
        if side is None or side[0] in sides:
            return None
        sides[side[0]] = side[1]
    return sides


def _claimed_side(text: str) -> Optional[Tuple[str, int]]:
    """The side and length one clause states, such as "the width is 800"."""
    for pattern in _SIDE_CLAIMS:
        match = pattern.fullmatch(text)
        if match:
            word, number = sorted(match.groups(), key=str.isdigit)
            return _SIDES[word], int(number)
    return None


@dataclass
class ImageAnalysisResult:
    """Result of image analysis."""
    width: int = 0
    height: int = 0
    format: str = ""
    has_text: bool = False
    extracted_text: List[str] = field(default_factory=list)
    dominant_colors: List[str] = field(default_factory=list)
    detected_elements: List[str] = field(default_factory=list)


@dataclass
class ImageVerificationResult:
    """Result of image claim verification."""
    verdict: str  # "SUPPORTED", "REFUTED", "INCONCLUSIVE", "VLM_REQUIRED"
    confidence: float
    reasoning: str
    analysis: Dict[str, Any] = field(default_factory=dict)
    methods_used: List[str] = field(default_factory=list)


class ImageVerifier:
    """
    Engine 7: Enterprise Image Verifier.
    
    Uses deterministic methods for image claim verification:
    1. Image metadata extraction (dimensions, format)
    2. Text extraction (basic OCR patterns)
    3. Color analysis (dominant colors)
    4. Chart data extraction (for simple charts)
    
    VLM is only consulted for complex semantic claims.

    Attributes:
        vlm_provider: Vision-Language Model provider.
        use_vlm_fallback (bool): Whether to use VLM for complex claims.
    """
    
    # Common claim patterns we can verify deterministically
    NUMERIC_PATTERNS = [
        r'(\d+(?:\.\d+)?)\s*%',  # Percentages
        r'\$(\d+(?:,\d{3})*(?:\.\d{2})?)',  # Dollar amounts
        r'(\d+(?:,\d{3})*)',  # Numbers with commas
        r'(\d+(?:\.\d+)?)\s*(million|billion|trillion)',  # Large numbers
    ]
    
    # Color keywords
    COLOR_KEYWORDS = {
        'red', 'blue', 'green', 'yellow', 'orange', 'purple', 'pink',
        'black', 'white', 'gray', 'grey', 'brown', 'cyan', 'magenta'
    }
    
    def __init__(self, vlm_provider=None, use_vlm_fallback: bool = True):
        """
        Initialize the Image Verifier.
        
        Args:
            vlm_provider: Vision-Language Model provider for fallback.
            use_vlm_fallback: Whether to use VLM for complex claims.

        Example:
            >>> verifier = ImageVerifier(use_vlm_fallback=False)
        """
        self.vlm_provider = vlm_provider
        self.use_vlm_fallback = use_vlm_fallback
    
    def verify_image(
        self, 
        image_bytes: bytes, 
        claim: str,
        context: Optional[str] = None
    ) -> DiagnosticResult:
        """
        Verify a claim against an image.
        
        Args:
            image_bytes: Raw bytes of the image.
            claim: The statement to verify (e.g., "Sales increased in Q3").
            context: Optional additional context.
            
        Returns:
            DiagnosticResult with VERIFIED for deterministic paths,
            UNVERIFIABLE for VLM/advisory paths, BLOCKED for errors.

        Example:
            >>> with open("image.jpg", "rb") as f:
            ...     img_data = f.read()
            >>> result = verifier.verify_image(img_data, "The image is 800x600")
            >>> print(result.status)
        """
        return self._verify_claim(image_bytes, claim, None)

    def _verify_claim(self, image_bytes: bytes, claim: str, image_sha256: Optional[str]) -> DiagnosticResult:
        """verify_image, given the image's SHA-256 when the caller has it, as
        verify_batch does for all its claims on one image (#320)."""
        if not image_bytes or not claim:
            return DiagnosticResult.unverifiable(
                _INCONCLUSIVE_MSG,
                {"constraint_id": "image_verifier.empty_input"}
            )

        if len(claim) > 500:
            return DiagnosticResult.unverifiable(
                _INCONCLUSIVE_MSG,
                {"constraint_id": "image_verifier.claim_too_long"}
            )

        methods_used = ["metadata_extraction"]
        metadata = self._extract_metadata(image_bytes)
        analysis = {
            "metadata": {"width": metadata.width, "height": metadata.height, "format": metadata.format},
            "claim_type": self._classify_claim(claim),
        }

        result = self._run_deterministic_verification(image_bytes, claim, metadata, methods_used, analysis["claim_type"])
        if result.verdict == "VLM_REQUIRED":
            return self._build_vlm_result(image_bytes, claim, methods_used, analysis)

        if result.verdict == "SUPPORTED":
            # The claim and the image are bound into the proof, so the proof of
            # one claim or image cannot stand for another (#320).
            evidence = {
                "metadata": analysis["metadata"],
                "reasoning": result.reasoning,
                "claim": claim,
                "image_sha256": image_sha256 or hashlib.sha256(image_bytes).hexdigest(),
            }
            return DiagnosticResult.verified(
                "Image claim verified",
                {"constraint_id": "image_verifier.deterministic", "methods_used": methods_used, "analysis": analysis},
                evidence,
            )

        if result.verdict == "REFUTED":
            return DiagnosticResult.blocked(
                "Image claim refuted by deterministic metadata check",
                {
                    "constraint_id": "image_verifier.deterministic_refuted",
                    "methods_used": methods_used,
                    "analysis": analysis,
                    "reasoning": result.reasoning,
                },
            )

        return DiagnosticResult.unverifiable(
            _INCONCLUSIVE_MSG,
            {"constraint_id": "image_verifier.inconclusive", "methods_used": methods_used, "analysis": analysis}
        )

    def _run_deterministic_verification(
        self,
        image_bytes: bytes,
        claim: str,
        metadata: ImageAnalysisResult,
        methods_used: List[str],
        claim_type: str,
    ) -> ImageVerificationResult:
        if claim_type == "numeric":
            methods_used.append("numeric_extraction")
            return self._verify_numeric_claim(image_bytes, claim, metadata)
        if claim_type == "color":
            methods_used.append("color_analysis")
            return self._verify_color_claim(image_bytes, claim, metadata)
        if claim_type == "size":
            methods_used.append("size_verification")
            return self._verify_size_claim(claim, metadata)
        if claim_type == "text":
            methods_used.append("text_extraction")
            return self._verify_text_claim(image_bytes, claim, metadata)
        return ImageVerificationResult(
            verdict="VLM_REQUIRED", confidence=0.0, reasoning="Claim requires visual understanding"
        )

    def _build_vlm_result(
        self,
        image_bytes: bytes,
        claim: str,
        methods_used: List[str],
        analysis: Dict[str, Any],
    ) -> DiagnosticResult:
        advisory_checks = []
        if self.use_vlm_fallback and self.vlm_provider:
            methods_used.append("vlm_analysis")
            vlm_result = self._vlm_fallback(image_bytes, claim)
            if vlm_result:
                advisory_checks.append(AdvisoryCheck(
                    name="vlm_analysis",
                    constraint_id="image_verifier.vlm_advisory_only",
                    details={
                        "vlm_verdict": vlm_result.get("verdict", "INCONCLUSIVE"),
                        "vlm_confidence": vlm_result.get("confidence", 0.5),
                        "vlm_reasoning": vlm_result.get("reasoning", ""),
                    }
                ))
        return DiagnosticResult.unverifiable(
            "Image verification inconclusive — visual understanding requires model interpretation which is advisory only",
            {
                "constraint_id": "image_verifier.vlm_advisory_only",
                "advisory_checks": advisory_checks,
                "methods_used": methods_used,
                "analysis": analysis,
            }
        )
    
    # =========================================================================
    # Metadata Extraction
    # =========================================================================
    
    def _extract_metadata(self, image_bytes: bytes) -> ImageAnalysisResult:
        """
        Extract basic metadata from image bytes.
        Supports PNG, JPEG, GIF headers.
        """
        result = ImageAnalysisResult()
        
        if len(image_bytes) < 8:
            return result
        
        # Check PNG
        if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
            result.format = "PNG"
            # PNG IHDR chunk contains width and height
            if len(image_bytes) > 24:
                result.width = struct.unpack('>I', image_bytes[16:20])[0]
                result.height = struct.unpack('>I', image_bytes[20:24])[0]
        
        # Check JPEG
        elif image_bytes[:2] == b'\xff\xd8':
            result.format = "JPEG"
            # Parse JPEG for dimensions
            result.width, result.height = self._parse_jpeg_dimensions(image_bytes)
        
        # Check GIF
        elif image_bytes[:6] in (b'GIF87a', b'GIF89a'):
            result.format = "GIF"
            if len(image_bytes) > 10:
                result.width = struct.unpack('<H', image_bytes[6:8])[0]
                result.height = struct.unpack('<H', image_bytes[8:10])[0]
        
        # Check WebP
        elif image_bytes[:4] == b'RIFF' and image_bytes[8:12] == b'WEBP':
            result.format = "WEBP"
            # Basic WebP dimension parsing
            if len(image_bytes) > 30:
                result.width = struct.unpack('<H', image_bytes[26:28])[0] & 0x3FFF
                result.height = struct.unpack('<H', image_bytes[28:30])[0] & 0x3FFF
        
        else:
            result.format = "UNKNOWN"
        
        return result
    
    def _parse_jpeg_dimensions(self, data: bytes) -> Tuple[int, int]:
        """Parse JPEG dimensions from binary data."""
        i = 2  # Skip SOI marker
        while i < len(data) - 1:
            if data[i] != 0xFF:
                break
            marker = data[i + 1]
            
            # SOF0 or SOF2 (Start of Frame)
            if marker in (0xC0, 0xC2):
                if i + 9 < len(data):
                    height = struct.unpack('>H', data[i + 5:i + 7])[0]
                    width = struct.unpack('>H', data[i + 7:i + 9])[0]
                    return width, height
            
            # Skip to next marker
            if marker == 0xD8 or marker == 0xD9:  # SOI or EOI
                i += 2
            elif marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):  # RST
                i += 2
            else:
                if i + 4 > len(data):
                    break
                length = struct.unpack('>H', data[i + 2:i + 4])[0]
                i += 2 + length
        
        return 0, 0
    
    # =========================================================================
    # Claim Classification
    # =========================================================================
    
    def _classify_claim(self, claim: str) -> str:
        """
        Classify the type of claim to determine verification method.
        
        Priority: size > color > numeric > text > semantic
        """
        # A plain statement of the size, such as "800X600" or "the image is
        # 800 wide and 600 tall", is decided by _verify_size_claim (#320).
        if _claimed_size(claim) is not None:
            return "size"

        claim_lower = claim.lower()

        # Size claims - check dimension pattern first (e.g., "1x1", "800x600")
        # FIX: Bounded regex to prevent ReDoS
        if re.search(r'\d{1,10}\s{0,5}[×x]\s{0,5}\d{1,10}', claim):
            return "size"
        
        # Size claims - keyword based (check BEFORE numeric to catch "width is 1")
        if any(word in claim_lower for word in ['width', 'height', 'size', 'pixel', 'pixels', 'resolution', 'dimension']):
            return "size"
        
        # Color claims
        if any(color in claim_lower for color in self.COLOR_KEYWORDS):
            return "color"
        
        # Numeric claims (percentages, amounts, counts)
        if any(re.search(pattern, claim) for pattern in self.NUMERIC_PATTERNS):
            return "numeric"
        
        if any(word in claim_lower for word in ['percent', '%', 'increase', 'decrease', 'growth']):
            return "numeric"
        
        # Text claims
        if any(word in claim_lower for word in ['says', 'text', 'reads', 'written', 'title', 'label']):
            return "text"
        
        # Default: requires semantic understanding
        return "semantic"
    
    # =========================================================================
    # Verification Methods
    # =========================================================================
    
    def _verify_numeric_claim(
        self, 
        image_bytes: bytes, 
        claim: str,
        metadata: ImageAnalysisResult
    ) -> ImageVerificationResult:
        """
        Verify numeric claims (percentages, amounts, etc.).
        """
        # Extract numbers from claim
        claim_numbers = set()
        for pattern in self.NUMERIC_PATTERNS:
            matches = re.findall(pattern, claim)
            for match in matches:
                if isinstance(match, tuple):
                    claim_numbers.add(match[0])
                else:
                    claim_numbers.add(match)
        
        if not claim_numbers:
            return ImageVerificationResult(
                verdict="VLM_REQUIRED",
                confidence=0.0,
                reasoning="Could not extract numeric values from claim"
            )
        
        # For now, we cannot extract numbers from images without OCR
        # Return VLM_REQUIRED for actual verification
        return ImageVerificationResult(
            verdict="VLM_REQUIRED",
            confidence=0.0,
            reasoning=f"Found numbers in claim: {claim_numbers}. Image OCR required for verification."
        )
    
    def _verify_color_claim(
        self, 
        image_bytes: bytes, 
        claim: str,
        metadata: ImageAnalysisResult
    ) -> ImageVerificationResult:
        """
        Verify color-based claims.
        """
        # Extract colors mentioned in claim
        claim_lower = claim.lower()
        mentioned_colors = [c for c in self.COLOR_KEYWORDS if c in claim_lower]
        
        if not mentioned_colors:
            return ImageVerificationResult(
                verdict="VLM_REQUIRED",
                confidence=0.0,
                reasoning="No specific colors mentioned in claim"
            )
        
        # Basic color verification would require pixel sampling
        # For now, return VLM_REQUIRED for complex color claims
        return ImageVerificationResult(
            verdict="VLM_REQUIRED",
            confidence=0.0,
            reasoning=f"Colors in claim: {mentioned_colors}. Pixel analysis required."
        )
    
    def _verify_size_claim(
        self, 
        claim: str,
        metadata: ImageAnalysisResult
    ) -> ImageVerificationResult:
        """
        Verify size/dimension claims using extracted metadata (#320).

        Only a claim that is wholly a plain statement of the width, height or
        both is decided, and every dimension it names is checked (see
        _claimed_size). Anything else is inconclusive, as is a claim about an
        image whose dimensions could not be read.
        """
        claimed = _claimed_size(claim)
        if not claimed:
            return ImageVerificationResult(
                verdict="INCONCLUSIVE",
                confidence=0.5,
                reasoning=(
                    "Size claim format not recognized: only a plain statement of the width, "
                    "height or both, such as \"the image is 800x600 pixels\", is checked"
                ),
            )
        if metadata.width <= 0 or metadata.height <= 0:
            return ImageVerificationResult(
                verdict="INCONCLUSIVE",
                confidence=0.5,
                reasoning="The image's dimensions could not be read",
            )
        actual = {"width": metadata.width, "height": metadata.height}
        wrong = [f"{side} {value}, actual {actual[side]}" for side, value in claimed.items() if value != actual[side]]
        if wrong:
            return ImageVerificationResult(
                verdict="REFUTED",
                confidence=1.0,
                reasoning="Claimed " + "; ".join(wrong),
            )
        if len(claimed) == 2:
            reasoning = f"Dimensions match: {metadata.width}x{metadata.height}"
        else:
            ((side, value),) = claimed.items()
            reasoning = f"{side.capitalize()} matches: {value}px"
        return ImageVerificationResult(verdict="SUPPORTED", confidence=1.0, reasoning=reasoning)
    
    def _verify_text_claim(
        self, 
        image_bytes: bytes, 
        claim: str,
        metadata: ImageAnalysisResult
    ) -> ImageVerificationResult:
        """
        Verify text-based claims. 
        Would require OCR for actual implementation.
        """
        return ImageVerificationResult(
            verdict="VLM_REQUIRED",
            confidence=0.0,
            reasoning="Text extraction requires OCR capability"
        )
    
    # =========================================================================
    # VLM Fallback
    # =========================================================================
    
    def _vlm_fallback(self, image_bytes: bytes, claim: str) -> Optional[Dict]:
        """
        Use Vision-Language Model as fallback for complex claims.
        """
        if not self.vlm_provider:
            return None
        
        try:
            result = self.vlm_provider.verify_image(image_bytes, claim)
            return result
        except Exception:
            return None
    
    # =========================================================================
    # Batch Verification
    # =========================================================================
    
    def verify_batch(
        self, 
        image_bytes: bytes, 
        claims: List[str]
    ) -> DiagnosticResult:
        """
        Verify multiple claims against the same image.

        Returns a single :class:`DiagnosticResult`. Per-claim verdicts live in
        ``developer_fields.results`` (each a serialized per-claim
        DiagnosticResult) and ``developer_fields.summary``.

        The batch is authoritative (VERIFIED with ``proof_ref``) only when every
        claim is deterministically verified. A batch containing any refuted,
        blocked, or inconclusive claim returns BLOCKED/UNVERIFIABLE (non-
        authoritative, ``proof_ref`` None) so generic consumers that admit on
        ``is_authoritative`` can never accept a partially-proven batch.

        Args:
            image_bytes: The image data.
            claims: List of claims to verify.

        Example:
            >>> result = verifier.verify_batch(img_data, ["Claim 1", "Claim 2"])
            >>> print(result.developer_fields["summary"]["verified"])
        """
        # The image is hashed once, for the proof of each claim and the batch's.
        image_sha256 = hashlib.sha256(image_bytes).hexdigest() if image_bytes else None
        items: List[Dict[str, Any]] = []
        for claim in claims:
            result = self._verify_claim(image_bytes, claim, image_sha256)
            serialized = result.to_dict()
            serialized["claim"] = claim
            items.append(serialized)

        # Bind the shared image bytes into the batch proof so the verdict can be
        # re-derived from the evidence (same claims against a different image must
        # not share a proof).
        extra_evidence: Dict[str, Any] = {}
        if image_sha256:
            extra_evidence["image_sha256"] = image_sha256

        return aggregate_batch_diagnostic(
            items,
            claims,
            engine="ImageVerifier",
            constraints={
                "verified": _CONSTRAINT_IMAGE_BATCH_VERIFIED,
                "blocked": _CONSTRAINT_IMAGE_BATCH_BLOCKED,
                "unverifiable": _CONSTRAINT_IMAGE_BATCH_UNVERIFIABLE,
                "empty": _CONSTRAINT_IMAGE_EMPTY_BATCH,
            },
            messages={
                "empty": "Batch image verification failed: no claims were provided.",
                "blocked": (
                    "Batch image verification flagged refuted or failed claims; "
                    "the batch is not admissible."
                ),
                "unverifiable": (
                    "Batch image verification is inconclusive: some claims could "
                    "not be deterministically verified."
                ),
                "verified": "Batch image verification succeeded: all claims were verified.",
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
            verifier="ImageVerifier",
        )



# =============================================================================
# Multi-VLM Consensus Verifier
# =============================================================================


class MultiVLMVerifier:
    """
    Verifies image claims using multiple VLM providers for consensus.

    Attributes:
        providers (List[Any]): List of VLM provider instances.
        base_verifier (ImageVerifier): Base verifier for deterministic checks.
    """
    
    def __init__(self, providers: List[Any]):
        """
        Initialize with multiple VLM providers.
        
        Args:
            providers: List of VLM provider instances.

        Example:
            >>> verifier = MultiVLMVerifier([provider1, provider2])
        """
        self.providers = providers
        self.base_verifier = ImageVerifier(use_vlm_fallback=False)
    
    def verify_with_consensus(
        self, 
        image_bytes: bytes, 
        claim: str,
        min_agreement: int = 2
    ) -> DiagnosticResult:
        """
        Verify claim using multiple VLMs and calculate consensus.
        
        Args:
            image_bytes: The image to verify.
            claim: The claim to verify.
            min_agreement: Minimum number of VLMs that must agree.

        Returns:
            DiagnosticResult — UNVERIFIABLE with VLM advisory checks, never VERIFIED from VLM alone.
        """
        # First try deterministic methods
        base_result = self.base_verifier.verify_image(image_bytes, claim)

        if base_result.is_verified or base_result.status.value == "BLOCKED":
            return base_result

        # Need VLM consensus — advisory only
        vlm_results = []

        for provider in self.providers:
            try:
                result = provider.verify_image(image_bytes, claim)
                vlm_results.append(result)
            except Exception:
                pass

        advisory_checks = []
        if len(vlm_results) >= min_agreement:
            from collections import Counter
            verdicts = [r.get("verdict", "UNKNOWN") for r in vlm_results]
            verdict_counts = Counter(verdicts)
            most_common = verdict_counts.most_common(1)[0]
            consensus_verdict = most_common[0]
            agreement_count = most_common[1]

            if agreement_count >= min_agreement:
                advisory_checks.append(AdvisoryCheck(
                    name="multi_vlm_consensus",
                    constraint_id="multi_vlm_verifier.vlm_advisory_only",
                    details={
                        "consensus_verdict": consensus_verdict,
                        "agreement_count": agreement_count,
                        "total_vlms": len(vlm_results),
                        "min_agreement": min_agreement,
                        "agreement_met": True,
                    }
                ))

        return DiagnosticResult.unverifiable(
            "Image verification inconclusive — VLM consensus is advisory only",
            {
                "constraint_id": "multi_vlm_verifier.vlm_advisory_only",
                "advisory_checks": advisory_checks,
                "vlm_count": len(vlm_results),
            }
        )

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="MultiVLMVerifier",
        )


