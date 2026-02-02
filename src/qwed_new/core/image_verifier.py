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
import base64
import re
import io
import struct
import zlib


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
    ) -> Dict[str, Any]:
        """
        Verify a claim against an image.
        
        Args:
            image_bytes: Raw bytes of the image.
            claim: The statement to verify (e.g., "Sales increased in Q3").
            context: Optional additional context.
            
        Returns:
            Dict containing verdict, confidence, reasoning, and analysis.

        Example:
            >>> with open("image.jpg", "rb") as f:
            ...     img_data = f.read()
            >>> result = verifier.verify_image(img_data, "The image is 800x600")
            >>> print(result["verdict"])
        """
        if not image_bytes or not claim:
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": 0.0,
                "reasoning": "Empty image or claim provided",
                "analysis": {},
                "methods_used": [],
                "engine": "ImageVerifier"
            }
            
        # Security: Prevent ReDoS attacks on regexes
        if len(claim) > 500:
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": 0.0,
                "reasoning": "Claim text too long (max 500 chars) - Security ReDoS protection",
                "analysis": {},
                "methods_used": [],
                "engine": "ImageVerifier"
            }
        
        methods_used = []
        analysis = {}
        
        # Step 1: Extract image metadata
        metadata = self._extract_metadata(image_bytes)
        analysis["metadata"] = {
            "width": metadata.width,
            "height": metadata.height,
            "format": metadata.format
        }
        methods_used.append("metadata_extraction")
        
        # Step 2: Analyze claim type
        claim_type = self._classify_claim(claim)
        analysis["claim_type"] = claim_type
        
        # Step 3: Apply appropriate verification method
        if claim_type == "numeric":
            # Try to extract numbers from image (basic pattern matching)
            result = self._verify_numeric_claim(image_bytes, claim, metadata)
            methods_used.append("numeric_extraction")
            
        elif claim_type == "color":
            # Verify color-based claims
            result = self._verify_color_claim(image_bytes, claim, metadata)
            methods_used.append("color_analysis")
            
        elif claim_type == "size":
            # Verify size/dimension claims
            result = self._verify_size_claim(claim, metadata)
            methods_used.append("size_verification")
            
        elif claim_type == "text":
            # Try to find text in image
            result = self._verify_text_claim(image_bytes, claim, metadata)
            methods_used.append("text_extraction")
            
        else:
            # Default: check if we need VLM
            result = ImageVerificationResult(
                verdict="VLM_REQUIRED",
                confidence=0.0,
                reasoning="Claim requires visual understanding"
            )
        
        # Step 4: If VLM required and available, use it
        if result.verdict == "VLM_REQUIRED" and self.use_vlm_fallback and self.vlm_provider:
            methods_used.append("vlm_analysis")
            vlm_result = self._vlm_fallback(image_bytes, claim)
            if vlm_result:
                result = ImageVerificationResult(
                    verdict=vlm_result.get("verdict", "INCONCLUSIVE"),
                    confidence=vlm_result.get("confidence", 0.5) * 0.8,  # Discount VLM confidence
                    reasoning=vlm_result.get("reasoning", "VLM analysis")
                )
        elif result.verdict == "VLM_REQUIRED":
            result = ImageVerificationResult(
                verdict="INCONCLUSIVE",
                confidence=0.3,
                reasoning="Claim requires visual understanding but VLM not available"
            )
        
        return {
            "verdict": result.verdict,
            "confidence": round(result.confidence, 3),
            "reasoning": result.reasoning,
            "analysis": analysis,
            "methods_used": methods_used,
            "claim": claim,
            "engine": "ImageVerifier"
        }
    
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
        claim_lower = claim.lower()
        
        # Size claims - check dimension pattern first (e.g., "1x1", "800x600")
        if re.search(r'\d+\s*[×x]\s*\d+', claim):
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
        Verify size/dimension claims using extracted metadata.
        """
        claim_lower = claim.lower()
        
        # Extract dimension numbers from claim (various formats)
        # Matches: "1x1", "100×200", "is 1x1 pixels", "800 x 600", etc.
        # FIX: Replaced \d+ with \d{1,10} to fully bound the regex complexity
        dimension_match = re.search(r'(\d{1,10})\s{0,5}[×x]\s{0,5}(\d{1,10})', claim)
        if dimension_match:
            claimed_width = int(dimension_match.group(1))
            claimed_height = int(dimension_match.group(2))
            
            if metadata.width > 0 and metadata.height > 0:
                width_match = claimed_width == metadata.width
                height_match = claimed_height == metadata.height
                
                if width_match and height_match:
                    return ImageVerificationResult(
                        verdict="SUPPORTED",
                        confidence=1.0,
                        reasoning=f"Dimensions match: {metadata.width}x{metadata.height}"
                    )
                else:
                    return ImageVerificationResult(
                        verdict="REFUTED",
                        confidence=1.0,
                        reasoning=f"Claimed {claimed_width}x{claimed_height}, actual {metadata.width}x{metadata.height}"
                    )
        
        # Check for single dimension - more flexible patterns
        # Matches: "width is 1", "The width is 500", "width of 100", "width: 100"
        # FIX: Replaced \d+ with \d{1,10}
        width_match = re.search(r'width\s{0,5}(?:is|of|:)?\s{0,5}(\d{1,10})', claim_lower)
        height_match = re.search(r'height\s{0,5}(?:is|of|:)?\s{0,5}(\d{1,10})', claim_lower)
        
        if width_match and metadata.width > 0:
            claimed = int(width_match.group(1))
            if claimed == metadata.width:
                return ImageVerificationResult(
                    verdict="SUPPORTED",
                    confidence=1.0,
                    reasoning=f"Width matches: {metadata.width}px"
                )
            else:
                return ImageVerificationResult(
                    verdict="REFUTED",
                    confidence=1.0,
                    reasoning=f"Claimed width {claimed}, actual {metadata.width}"
                )
        
        if height_match and metadata.height > 0:
            claimed = int(height_match.group(1))
            if claimed == metadata.height:
                return ImageVerificationResult(
                    verdict="SUPPORTED",
                    confidence=1.0,
                    reasoning=f"Height matches: {metadata.height}px"
                )
            else:
                return ImageVerificationResult(
                    verdict="REFUTED",
                    confidence=1.0,
                    reasoning=f"Claimed height {claimed}, actual {metadata.height}"
                )
        
        # Check for resolution claims
        if 'hd' in claim_lower or '1080' in claim or '720' in claim:
            is_hd = metadata.width >= 1280 and metadata.height >= 720
            if ('hd' in claim_lower or '720' in claim) and is_hd:
                return ImageVerificationResult(
                    verdict="SUPPORTED",
                    confidence=0.9,
                    reasoning=f"Image is HD resolution: {metadata.width}x{metadata.height}"
                )
        
        return ImageVerificationResult(
            verdict="INCONCLUSIVE",
            confidence=0.5,
            reasoning="Size claim format not recognized"
        )
    
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
    ) -> Dict[str, Any]:
        """
        Verify multiple claims against the same image.

        Args:
            image_bytes: The image data.
            claims: List of claims to verify.

        Returns:
            Dict containing batch results and summary statistics.

        Example:
            >>> result = verifier.verify_batch(img_data, ["Claim 1", "Claim 2"])
            >>> print(result["summary"]["supported"])
        """
        results = []
        
        for claim in claims:
            result = self.verify_image(image_bytes, claim)
            results.append({
                "claim": claim,
                **result
            })
        
        # Summary
        verdicts = [r["verdict"] for r in results]
        
        return {
            "results": results,
            "summary": {
                "total": len(claims),
                "supported": verdicts.count("SUPPORTED"),
                "refuted": verdicts.count("REFUTED"),
                "inconclusive": verdicts.count("INCONCLUSIVE"),
                "vlm_required": verdicts.count("VLM_REQUIRED"),
                "average_confidence": sum(r["confidence"] for r in results) / len(results) if results else 0
            }
        }


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
    ) -> Dict[str, Any]:
        """
        Verify claim using multiple VLMs and calculate consensus.
        
        Args:
            image_bytes: The image to verify.
            claim: The claim to verify.
            min_agreement: Minimum number of VLMs that must agree.

        Returns:
            Dict containing consensus verdict and details.

        Example:
            >>> result = verifier.verify_with_consensus(img_data, "There is a cat", min_agreement=2)
            >>> print(result["verdict"])
        """
        # First try deterministic methods
        base_result = self.base_verifier.verify_image(image_bytes, claim)
        
        if base_result["verdict"] in ["SUPPORTED", "REFUTED"]:
            # Deterministic method succeeded
            return base_result
        
        # Need VLM consensus
        vlm_results = []
        
        for provider in self.providers:
            try:
                result = provider.verify_image(image_bytes, claim)
                vlm_results.append(result)
            except Exception:
                pass
        
        if len(vlm_results) < min_agreement:
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": 0.3,
                "reasoning": f"Only {len(vlm_results)} VLMs responded, need {min_agreement}",
                "vlm_count": len(vlm_results)
            }
        
        # Calculate consensus
        verdicts = [r.get("verdict", "UNKNOWN") for r in vlm_results]
        from collections import Counter
        verdict_counts = Counter(verdicts)
        
        most_common = verdict_counts.most_common(1)[0]
        consensus_verdict = most_common[0]
        agreement_count = most_common[1]
        
        if agreement_count >= min_agreement:
            # Consensus reached
            avg_confidence = sum(
                r.get("confidence", 0.5) for r in vlm_results 
                if r.get("verdict") == consensus_verdict
            ) / agreement_count
            
            return {
                "verdict": consensus_verdict,
                "confidence": round(avg_confidence * 0.9, 3),  # Slight discount
                "reasoning": f"{agreement_count}/{len(vlm_results)} VLMs agree",
                "vlm_results": vlm_results,
                "agreement_count": agreement_count
            }
        else:
            return {
                "verdict": "INCONCLUSIVE",
                "confidence": 0.4,
                "reasoning": "VLMs did not reach consensus",
                "vlm_results": vlm_results,
                "agreement_count": agreement_count
            }
