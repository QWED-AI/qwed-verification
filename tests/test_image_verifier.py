"""
Tests for Enterprise Image Verification Engine.

Tests metadata extraction, claim classification, size verification, and multi-VLM consensus.
"""

import pytest
from qwed_new.core.image_verifier import ImageVerifier, MultiVLMVerifier


# Sample image bytes for testing
# Minimal PNG (1x1 red pixel)
PNG_1X1 = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1 dimensions
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,  # bit depth, color type
    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,  # IDAT chunk
    0x54, 0x08, 0x99, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
    0x00, 0x00, 0x03, 0x00, 0x01, 0xBB, 0xF8, 0xC4,
    0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
    0x44, 0xAE, 0x42, 0x60, 0x82
])

# Minimal GIF (1x1)
GIF_1X1 = b'GIF89a\x01\x00\x01\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'


class TestImageVerifierBasics:
    """Test basic image verification."""
    
    @pytest.fixture
    def verifier(self):
        return ImageVerifier(use_vlm_fallback=False)
    
    def test_empty_image(self, verifier):
        """Test empty image."""
        result = verifier.verify_image(b"", "Some claim")
        assert result["verdict"] == "INCONCLUSIVE"
    
    def test_empty_claim(self, verifier):
        """Test empty claim."""
        result = verifier.verify_image(PNG_1X1, "")
        assert result["verdict"] == "INCONCLUSIVE"
    
    def test_returns_engine_name(self, verifier):
        """Test that engine name is returned."""
        result = verifier.verify_image(PNG_1X1, "Some claim")
        assert result["engine"] == "ImageVerifier"
    
    def test_methods_tracked(self, verifier):
        """Test that methods are tracked."""
        result = verifier.verify_image(PNG_1X1, "The image is 100x100")
        assert "methods_used" in result
        assert len(result["methods_used"]) > 0


class TestMetadataExtraction:
    """Test image metadata extraction."""
    
    @pytest.fixture
    def verifier(self):
        return ImageVerifier(use_vlm_fallback=False)
    
    def test_png_detection(self, verifier):
        """Test PNG format detection."""
        result = verifier.verify_image(PNG_1X1, "Test claim")
        assert result["analysis"]["metadata"]["format"] == "PNG"
    
    def test_png_dimensions(self, verifier):
        """Test PNG dimension extraction."""
        result = verifier.verify_image(PNG_1X1, "Test claim")
        assert result["analysis"]["metadata"]["width"] == 1
        assert result["analysis"]["metadata"]["height"] == 1
    
    def test_gif_detection(self, verifier):
        """Test GIF format detection."""
        result = verifier.verify_image(GIF_1X1, "Test claim")
        assert result["analysis"]["metadata"]["format"] == "GIF"
    
    def test_gif_dimensions(self, verifier):
        """Test GIF dimension extraction."""
        result = verifier.verify_image(GIF_1X1, "Test claim")
        assert result["analysis"]["metadata"]["width"] == 1
        assert result["analysis"]["metadata"]["height"] == 1
    
    def test_unknown_format(self, verifier):
        """Test unknown format handling."""
        result = verifier.verify_image(b"not an image", "Test claim")
        assert result["analysis"]["metadata"]["format"] == "UNKNOWN"


class TestClaimClassification:
    """Test claim type classification."""
    
    @pytest.fixture
    def verifier(self):
        return ImageVerifier(use_vlm_fallback=False)
    
    def test_numeric_claim(self, verifier):
        """Test numeric claim classification."""
        result = verifier.verify_image(PNG_1X1, "Sales increased by 25%")
        assert result["analysis"]["claim_type"] == "numeric"
    
    def test_color_claim(self, verifier):
        """Test color claim classification."""
        result = verifier.verify_image(PNG_1X1, "The background is blue")
        assert result["analysis"]["claim_type"] == "color"
    
    def test_size_claim(self, verifier):
        """Test size claim classification."""
        result = verifier.verify_image(PNG_1X1, "The image width is 800 pixels")
        assert result["analysis"]["claim_type"] == "size"
    
    def test_text_claim(self, verifier):
        """Test text claim classification."""
        result = verifier.verify_image(PNG_1X1, "The title says 'Hello World'")
        assert result["analysis"]["claim_type"] == "text"
    
    def test_semantic_claim(self, verifier):
        """Test semantic claim classification."""
        result = verifier.verify_image(PNG_1X1, "There is a dog in the picture")
        assert result["analysis"]["claim_type"] == "semantic"


class TestSizeVerification:
    """Test size/dimension verification."""
    
    @pytest.fixture
    def verifier(self):
        return ImageVerifier(use_vlm_fallback=False)
    
    def test_correct_dimensions(self, verifier):
        """Test correct dimension claim."""
        result = verifier.verify_image(PNG_1X1, "The image is 1x1 pixels")
        assert result["verdict"] == "SUPPORTED"
        assert result["confidence"] == 1.0
    
    def test_incorrect_dimensions(self, verifier):
        """Test incorrect dimension claim."""
        result = verifier.verify_image(PNG_1X1, "The image is 100x100 pixels")
        assert result["verdict"] == "REFUTED"
        assert result["confidence"] == 1.0
    
    def test_correct_width(self, verifier):
        """Test correct width claim."""
        result = verifier.verify_image(PNG_1X1, "The width is 1")
        assert result["verdict"] == "SUPPORTED"
    
    def test_incorrect_width(self, verifier):
        """Test incorrect width claim."""
        result = verifier.verify_image(PNG_1X1, "The width is 500")
        assert result["verdict"] == "REFUTED"


class TestVLMFallback:
    """Test VLM fallback behavior."""
    
    @pytest.fixture
    def verifier(self):
        return ImageVerifier(use_vlm_fallback=False)
    
    def test_vlm_required_for_semantic(self, verifier):
        """Test that semantic claims go to VLM."""
        result = verifier.verify_image(PNG_1X1, "The person is smiling")
        # Without VLM, should be INCONCLUSIVE
        assert result["verdict"] in ["INCONCLUSIVE", "VLM_REQUIRED"]
    
    def test_vlm_required_for_text(self, verifier):
        """Test that text claims require VLM/OCR."""
        result = verifier.verify_image(PNG_1X1, "The text says 'Hello'")
        assert result["verdict"] in ["INCONCLUSIVE", "VLM_REQUIRED"]


class TestBatchVerification:
    """Test batch image verification."""
    
    def test_batch_verification(self):
        """Test verifying multiple claims."""
        verifier = ImageVerifier(use_vlm_fallback=False)
        
        claims = [
            "The image is 1x1 pixels",
            "The background is blue",
            "There is a tree"
        ]
        
        result = verifier.verify_batch(PNG_1X1, claims)
        
        assert len(result["results"]) == 3
        assert result["summary"]["total"] == 3
        assert "supported" in result["summary"]
        assert "average_confidence" in result["summary"]


class TestMultiVLMVerifier:
    """Test multi-VLM consensus verification."""
    
    def test_initialization(self):
        """Test multi-VLM verifier initialization."""
        verifier = MultiVLMVerifier([])
        assert verifier is not None
    
    def test_no_providers(self):
        """Test with no VLM providers."""
        verifier = MultiVLMVerifier([])
        
        # Should fall back to deterministic for size claims
        result = verifier.verify_with_consensus(PNG_1X1, "The image is 1x1")
        assert result["verdict"] == "SUPPORTED"
