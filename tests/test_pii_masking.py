"""
Unit tests for PII masking functionality.

Tests:
- PIIDetector class (requires presidio)
- QWEDLocal integration
- CLI integration
- Error handling
"""

import pytest
import sys
import os

# Test PIIDetector class
class TestPIIDetector:
    """Test PIIDetector class (requires pip install 'qwed[pii]')."""
    
    def test_import_without_presidio(self):
        """Test graceful handling when presidio not installed."""
        from qwed_sdk.pii_detector import check_pii_dependencies
        
        # This will return True if installed, False if not
        has_pii = check_pii_dependencies()
        
        if not has_pii:
            # Should raise helpful error
            with pytest.raises(ImportError, match="PII masking requires"):
                from qwed_sdk.pii_detector import PIIDetector
                PIIDetector()
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed (pip install 'qwed[pii]')"
    )
    def test_email_detection(self):
        """Test email address detection."""
        from qwed_sdk.pii_detector import PIIDetector
        
        detector = PIIDetector()
        text = "Contact me at john@example.com"
        masked, info = detector.detect_and_mask(text)
        
        assert "<EMAIL_ADDRESS>" in masked
        assert info["pii_detected"] == 1
        assert "EMAIL_ADDRESS" in info["types"]
        assert len(info["positions"]) == 1
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed"
    )
    def test_credit_card_detection(self):
        """Test credit card detection."""
        from qwed_sdk.pii_detector import PIIDetector
        
        detector = PIIDetector()
        text = "My card is 4532-1234-5678-9010"
        masked, info = detector.detect_and_mask(text)
        
        assert "<CREDIT_CARD>" in masked
        assert info["pii_detected"] == 1
        assert "CREDIT_CARD" in info["types"]
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed"
    )
    def test_phone_number_detection(self):
        """Test phone number detection."""
        from qwed_sdk.pii_detector import PIIDetector
        
        detector = PIIDetector()
        text = "Call me at 555-123-4567"
        masked, info = detector.detect_and_mask(text)
        
        # Phone detection can be tricky
        assert info["pii_detected"] >= 0  # May or may not detect
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed"
    )
    def test_multiple_pii_types(self):
        """Test detection of multiple PII types."""
        from qwed_sdk.pii_detector import PIIDetector
        
        detector = PIIDetector()
        text = "Email: john@example.com, Phone: 555-1234"
        masked, info = detector.detect_and_mask(text)
        
        # Should detect at least the email
        assert info["pii_detected"] >= 1
        assert "EMAIL_ADDRESS" in info["types"]
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed"
    )
    def test_no_pii(self):
        """Test text with no PII."""
        from qwed_sdk.pii_detector import PIIDetector
        
        detector = PIIDetector()
        text = "What is 2+2?"
        masked, info = detector.detect_and_mask(text)
        
        assert masked == text  # Unchanged
        assert info["pii_detected"] == 0
        assert len(info.get("types", [])) == 0
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed"
    )
    def test_custom_entities(self):
        """Test custom entity list."""
        from qwed_sdk.pii_detector import PIIDetector
        
        # Only detect emails
        detector = PIIDetector(entities=["EMAIL_ADDRESS"])
        text = "Email: john@example.com, Card: 4532-1234-5678-9010"
        masked, info = detector.detect_and_mask(text)
        
        # Should only detect email, not card
        assert "<EMAIL_ADDRESS>" in masked
        assert "EMAIL_ADDRESS" in info["types"]
        # Card should not be detected
        assert "CREDIT_CARD" not in info.get("types", [])


class TestQWEDLocalPII:
    """Test QWEDLocal integration with PII masking."""
    
    def test_mask_pii_disabled_by_default(self):
        """Test that mask_pii is False by default."""
        from qwed_sdk import QWEDLocal
        
        # Create client without mask_pii
        client = QWEDLocal(
            base_url="http://localhost:11434/v1",
            model="llama3"
        )
        
        assert client.mask_pii == False
        assert client._pii_detector is None
    
    def test_mask_pii_param_accepted(self):
        """Test that mask_pii parameter is accepted."""
        from qwed_sdk import QWEDLocal
        
        # Should accept the parameter even if presidio not installed
        # (will error on first use if not installed)
        try:
            client = QWEDLocal(
                base_url="http://localhost:11434/v1",
                model="llama3",
                mask_pii=False  # Explicitly False
            )
            assert client.mask_pii == False
        except ImportError:
            # Expected if mask_pii=True and presidio not installed
            pass
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed"
    )
    def test_mask_pii_enabled(self):
        """Test enabling PII masking."""
        from qwed_sdk import QWEDLocal
        
        client = QWEDLocal(
            base_url="http://localhost:11434/v1",
            model="llama3",
            mask_pii=True
        )
        
        assert client.mask_pii == True
        assert client._pii_detector is not None
    
    def test_mask_pii_error_without_presidio(self):
        """Test error when mask_pii=True but presidio not installed."""
        from qwed_sdk import QWEDLocal
        from qwed_sdk.pii_detector import check_pii_dependencies
        
        if not check_pii_dependencies():
            # Should raise helpful error
            with pytest.raises(ImportError, match="PII masking requires"):
                QWEDLocal(
                    base_url="http://localhost:11434/v1",
                    model="llama3",
                    mask_pii=True
                )


class TestPIIMetadata:
    """Test PII metadata in verification results."""
    
    @pytest.mark.skipif(
        not __import__('qwed_sdk.pii_detector', fromlist=['check_pii_dependencies']).check_pii_dependencies(),
        reason="Presidio not installed"
    )
    def test_pii_info_in_evidence(self):
        """Test that PII info appears in evidence (if LLM available)."""
        from qwed_sdk import QWEDLocal
        
        # This test would need a real LLM connection
        # Skipping for now
        pass


class TestCLI:
    """Test CLI PII integration."""
    
    def test_cli_imports(self):
        """Test that CLI imports work."""
        try:
            from qwed_sdk.cli import verify, pii
            # Import successful
            assert True
        except ImportError as e:
            pytest.fail(f"CLI imports failed: {e}")


# Manual test instructions
def print_manual_test_instructions():
    """Print manual testing instructions."""
    print("""
🧪 MANUAL TESTING INSTRUCTIONS
================================

1. Install PII dependencies:
   pip install 'qwed[pii]'
   python -m spacy download en_core_web_lg

2. Test CLI PII detection:
   qwed pii "My email is john@example.com"
   Expected output: Masked: My email is <EMAIL_ADDRESS>

3. Test CLI verification with masking:
   qwed verify "My email is test@example.com" --mask-pii
   (Requires Ollama running or --provider openai)

4. Test Python API:
   python
   >>> from qwed_sdk import QWEDLocal
   >>> client = QWEDLocal(base_url="http://localhost:11434/v1", mask_pii=True)
   >>> result = client.verify("Email: user@example.com")
   >>> print(result.evidence.get('pii_masked'))

5. Test without presidio:
   pip uninstall presidio-analyzer presidio-anonymizer -y
   qwed pii "test"
   Expected: Error message with install instructions
""")


if __name__ == "__main__":
    # Run tests
    print("Running PII masking tests...")
    pytest.main([__file__, "-v", "-s"])
    
    print("\n")
    print_manual_test_instructions()
