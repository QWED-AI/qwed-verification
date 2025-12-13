from typing import Dict, Any
from qwed_new.providers.base import LLMProvider

class ImageVerifier:
    """
    Engine 7: Image Verifier.
    Verifies claims about visual content (charts, diagrams, etc.) using VLM capabilities.
    """
    
    def __init__(self, provider: LLMProvider):
        self.provider = provider
        
    def verify_image(self, image_bytes: bytes, claim: str) -> Dict[str, Any]:
        """
        Verify a claim against an image.
        
        Args:
            image_bytes: Raw bytes of the image.
            claim: The statement to verify (e.g., "Sales increased in Q3").
            
        Returns:
            Dict containing 'verdict', 'reasoning', and 'confidence'.
        """
        # 1. Delegate to Provider (Model-Agnostic)
        result = self.provider.verify_image(image_bytes, claim)
        
        # 2. Add metadata
        result["engine"] = "ImageVerifier"
        result["claim"] = claim
        
        return result
