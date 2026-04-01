"""
QWED LlamaIndex Integration

Provides seamless integration with LlamaIndex for automatic verification
of LLM outputs, including Fact Checking against retrieved context.

Usage:
    from qwed_sdk.integrations.llamaindex import QWEDQueryEngine

    # Wrap any query engine
    verified_engine = QWEDQueryEngine(base_engine)
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass
import re

# Import QWED client
try:
    from qwed_sdk import QWEDClient
except ImportError:
    from ..client import QWEDClient

LLAMAINDEX_AVAILABLE = True

@dataclass
class VerifiedResponse:
    """Response with verification metadata."""
    response: str
    verified: bool
    status: str
    confidence: float = 1.0
    source_nodes: List[Any] = None
    
    def __str__(self):
        return self.response

class QWEDQueryEngine:
    """
    Wrapper that adds verification to any LlamaIndex query engine.
    
    Features:
    - Math Verification: Checks calculations
    - Fact Guard: Verifies answers against retrieved source nodes (NLI)
    """
    
    def __init__(
        self,
        query_engine: Any,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        verify_math: bool = True,
        verify_facts: bool = True,
    ):
        self.query_engine = query_engine
        self.client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
        self.verify_math = verify_math
        self.verify_facts = verify_facts
    
    def query(self, query: str, **kwargs) -> VerifiedResponse:
        """Query and verify the response."""
        # Get response from base engine
        response = self.query_engine.query(query, **kwargs)
        response_text = str(response)
        source_nodes = getattr(response, "source_nodes", [])
        
        # Verify the response
        verification = self._verify_response(response_text, query, source_nodes)
        
        return VerifiedResponse(
            response=response_text,
            verified=verification["verified"],
            status=verification["status"],
            confidence=verification.get("confidence", 1.0),
            source_nodes=source_nodes,
        )
    
    def _verify_response(self, response: str, query: str, source_nodes: List[Any]) -> Dict[str, Any]:
        """Verify report based on content and context."""
        try:
            # 1. Math Verification
            if self.verify_math and self._contains_math(response):
                result = self.client.verify_math(response)
                # verify_math usually returns a full result object, we extract dict
                if hasattr(result, "dict"): result = result.dict()
                return result
            
            # 2. Fact Guard (RAG Verification)
            if self.verify_facts and source_nodes:
                # Extract context from nodes
                context_text = "\n".join([n.node.get_content() for n in source_nodes])
                
                # Check if response is supported by context
                # "Fact Guard" (TF-IDF + NLI)
                result = self.client.verify_fact(claim=response, context=context_text)
                if hasattr(result, "dict"): result = result.dict()
                return result
            
            return {"verified": True, "status": "PASSED (No claims verified)"}
            
        except Exception as e:
            return {"verified": False, "status": f"ERROR: {str(e)}"}
    
    def _contains_math(self, text: str) -> bool:
        """Simple heuristic to check if text contains math."""
        # Detect digits and math operators
        return bool(re.search(r'\d', text) and re.search(r'[+\-*/=]', text))

__all__ = ["QWEDQueryEngine", "VerifiedResponse"]
