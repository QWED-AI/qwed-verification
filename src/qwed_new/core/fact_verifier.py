from typing import Optional
from qwed_new.core.translator import TranslationLayer

class FactVerifier:
    """
    Engine 4: Fact Verifier.
    Verifies claims against a provided text context using citation-based checking.
    """
    
    def __init__(self):
        self.translator = TranslationLayer()
        
    def verify_fact(self, claim: str, context: str, provider: Optional[str] = None) -> dict:
        """
        Verifies a factual claim against a context.
        
        Args:
            claim: The statement to verify (e.g., "The policy covers water damage").
            context: The source text (e.g., "Policy Document...").
            provider: Optional LLM provider.
            
        Returns:
            dict: {
                "verdict": "SUPPORTED" | "REFUTED" | "NEUTRAL",
                "reasoning": str,
                "citations": list[str]
            }
        """
        # Delegate to the LLM Provider via TranslationLayer
        return self.translator.verify_fact(claim, context, provider=provider)
