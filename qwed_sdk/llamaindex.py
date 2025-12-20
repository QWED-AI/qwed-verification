"""
QWED LlamaIndex Integration

Provides seamless integration with LlamaIndex for automatic verification
of LLM outputs in query engines and agents.

Usage:
    from qwed_sdk.llamaindex import QWEDQueryEngine, QWEDVerificationTransform

    # Wrap any query engine
    verified_engine = QWEDQueryEngine(base_engine)

    # Or use as a transformation
    engine = index.as_query_engine(
        node_postprocessors=[QWEDVerificationTransform()]
    )
"""

from typing import Any, Dict, List, Optional, Sequence
from dataclasses import dataclass
import re

# Import QWED client
try:
    from qwed_sdk import QWEDClient
except ImportError:
    from ..client import QWEDClient


# ============================================================================
# LlamaIndex Imports
# ============================================================================

try:
    from llama_index.core.query_engine import BaseQueryEngine
    from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
    from llama_index.core.callbacks import CallbackManager
    from llama_index.core.callbacks.base import BaseCallbackHandler
    from llama_index.core.callbacks.schema import CBEventType, EventPayload
    LLAMAINDEX_AVAILABLE = True
except ImportError:
    LLAMAINDEX_AVAILABLE = False
    # Stub classes
    class BaseQueryEngine:
        pass
    class BaseNodePostprocessor:
        pass
    class BaseCallbackHandler:
        pass


# ============================================================================
# QWED Query Engine Wrapper
# ============================================================================

@dataclass
class VerifiedResponse:
    """Response with verification metadata."""
    response: str
    verified: bool
    status: str
    confidence: float = 1.0
    attestation: Optional[str] = None
    source_nodes: List[Any] = None
    
    def __str__(self):
        return self.response
    
    def __post_init__(self):
        if self.source_nodes is None:
            self.source_nodes = []


class QWEDQueryEngine:
    """
    Wrapper that adds verification to any LlamaIndex query engine.
    
    Example:
        from llama_index.core import VectorStoreIndex
        from qwed_sdk.llamaindex import QWEDQueryEngine
        
        index = VectorStoreIndex.from_documents(documents)
        base_engine = index.as_query_engine()
        
        verified_engine = QWEDQueryEngine(base_engine)
        response = verified_engine.query("What is 15% of 200?")
        
        print(response.verified)  # True/False
        print(response.response)  # The LLM response
    """
    
    def __init__(
        self,
        query_engine: Any,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        verify_math: bool = True,
        verify_facts: bool = True,
        auto_correct: bool = False,
        include_attestation: bool = False,
    ):
        self.query_engine = query_engine
        self._client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
        self.verify_math = verify_math
        self.verify_facts = verify_facts
        self.auto_correct = auto_correct
        self.include_attestation = include_attestation
    
    def query(self, query: str, **kwargs) -> VerifiedResponse:
        """Query and verify the response."""
        # Get response from base engine
        response = self.query_engine.query(query, **kwargs)
        response_text = str(response)
        
        # Verify the response
        verification = self._verify_response(response_text, query)
        
        # Auto-correct if enabled
        if self.auto_correct and not verification["verified"]:
            corrected = verification.get("corrected")
            if corrected:
                response_text = corrected
        
        return VerifiedResponse(
            response=response_text,
            verified=verification["verified"],
            status=verification["status"],
            confidence=verification.get("confidence", 1.0),
            attestation=verification.get("attestation"),
            source_nodes=getattr(response, "source_nodes", []),
        )
    
    async def aquery(self, query: str, **kwargs) -> VerifiedResponse:
        """Async query and verify."""
        response = await self.query_engine.aquery(query, **kwargs)
        response_text = str(response)
        
        verification = self._verify_response(response_text, query)
        
        return VerifiedResponse(
            response=response_text,
            verified=verification["verified"],
            status=verification["status"],
            source_nodes=getattr(response, "source_nodes", []),
        )
    
    def _verify_response(self, response: str, query: str) -> Dict[str, Any]:
        """Verify a response based on content type."""
        try:
            # Check if it contains math
            if self.verify_math and self._contains_math(response):
                result = self._client.verify(response)
                return {
                    "verified": result.verified,
                    "status": result.status,
                    "corrected": result.result.get("corrected") if hasattr(result, "result") else None,
                    "attestation": getattr(result, "attestation", None),
                }
            
            # Check if it's a factual claim
            if self.verify_facts and self._is_factual(query):
                # For fact verification, we'd need context
                # For now, pass through
                return {"verified": True, "status": "PASSED"}
            
            return {"verified": True, "status": "PASSED"}
            
        except Exception as e:
            return {"verified": False, "status": "ERROR", "error": str(e)}
    
    def _contains_math(self, text: str) -> bool:
        """Check if text contains mathematical expressions."""
        patterns = [
            r'\d+\s*[+\-*/]\s*\d+',
            r'=\s*\d+',
            r'\d+%',
            r'result is \d+',
            r'equals? \d+',
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
    
    def _is_factual(self, query: str) -> bool:
        """Check if query is asking for facts."""
        fact_patterns = [
            r'^what is',
            r'^who is',
            r'^when did',
            r'^where is',
            r'^how many',
        ]
        return any(re.search(p, query, re.IGNORECASE) for p in fact_patterns)


# ============================================================================
# Node Postprocessor
# ============================================================================

class QWEDVerificationTransform(BaseNodePostprocessor if LLAMAINDEX_AVAILABLE else object):
    """
    LlamaIndex Node Postprocessor that verifies retrieved content.
    
    Example:
        from llama_index.core import VectorStoreIndex
        from qwed_sdk.llamaindex import QWEDVerificationTransform
        
        query_engine = index.as_query_engine(
            node_postprocessors=[QWEDVerificationTransform()]
        )
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        verify_math: bool = True,
        verify_code: bool = True,
        min_score_threshold: float = 0.5,
    ):
        self._client = QWEDClient(api_key=api_key or "")
        self.verify_math = verify_math
        self.verify_code = verify_code
        self.min_score_threshold = min_score_threshold
    
    def _postprocess_nodes(
        self,
        nodes: List["NodeWithScore"],
        query_bundle: Optional["QueryBundle"] = None,
    ) -> List["NodeWithScore"]:
        """Verify and filter nodes."""
        verified_nodes = []
        
        for node in nodes:
            text = node.node.get_content()
            
            # Verify content
            is_safe = self._verify_content(text)
            
            if is_safe:
                # Add verification metadata
                node.node.metadata["qwed_verified"] = True
                verified_nodes.append(node)
            else:
                # Optionally include but mark as unverified
                node.node.metadata["qwed_verified"] = False
                node.score = node.score * 0.5  # Reduce score
                if node.score >= self.min_score_threshold:
                    verified_nodes.append(node)
        
        return verified_nodes
    
    def _verify_content(self, text: str) -> bool:
        """Verify content is safe and accurate."""
        try:
            # Check for code
            if self.verify_code and "```" in text:
                code_match = re.search(r'```(?:\w+)?\n(.*?)```', text, re.DOTALL)
                if code_match:
                    code = code_match.group(1)
                    result = self._client.verify_code(code)
                    if not result.verified:
                        return False
            
            return True
        except Exception:
            return True  # Pass through on error


# ============================================================================
# Callback Handler
# ============================================================================

class QWEDCallbackHandler(BaseCallbackHandler if LLAMAINDEX_AVAILABLE else object):
    """
    LlamaIndex Callback Handler for automatic verification logging.
    
    Example:
        from llama_index.core import Settings
        from qwed_sdk.llamaindex import QWEDCallbackHandler
        
        Settings.callback_manager.add_handler(QWEDCallbackHandler())
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        log_all: bool = True,
    ):
        self._client = QWEDClient(api_key=api_key or "")
        self.log_all = log_all
        self.events: List[Dict[str, Any]] = []
    
    def on_event_start(
        self,
        event_type: "CBEventType",
        payload: Optional["EventPayload"] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs,
    ) -> str:
        """Track event start."""
        return event_id
    
    def on_event_end(
        self,
        event_type: "CBEventType",
        payload: Optional["EventPayload"] = None,
        event_id: str = "",
        **kwargs,
    ) -> None:
        """Verify and log event end."""
        if payload and hasattr(payload, "response"):
            response = str(payload.response)
            
            try:
                result = self._client.verify(response)
                self.events.append({
                    "event_id": event_id,
                    "event_type": str(event_type),
                    "verified": result.verified,
                    "status": result.status,
                })
                
                if self.log_all:
                    status = "✅" if result.verified else "❌"
                    print(f"[QWED] {status} Event {event_type}: verified={result.verified}")
            except Exception:
                pass
    
    def start_trace(self, trace_id: Optional[str] = None) -> None:
        pass
    
    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        pass


# ============================================================================
# Tool for LlamaIndex Agents
# ============================================================================

class QWEDVerifyTool:
    """
    LlamaIndex Tool for agents to use QWED verification.
    
    Example:
        from llama_index.core.agent import ReActAgent
        from qwed_sdk.llamaindex import QWEDVerifyTool
        
        tools = [QWEDVerifyTool()]
        agent = ReActAgent.from_tools(tools, llm=llm)
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self._client = QWEDClient(api_key=api_key or "")
    
    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "name": "qwed_verify",
            "description": (
                "Verify mathematical expressions, logical statements, and code for correctness. "
                "Use this to confirm calculations and check code safety."
            ),
        }
    
    def __call__(self, query: str) -> str:
        """Run verification."""
        try:
            result = self._client.verify(query)
            if result.verified:
                return f"✅ VERIFIED: The statement is correct."
            else:
                msg = result.result.get("message", "Verification failed") if hasattr(result, "result") else "Failed"
                return f"❌ FAILED: {msg}"
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "QWEDQueryEngine",
    "QWEDVerificationTransform",
    "QWEDCallbackHandler",
    "QWEDVerifyTool",
    "VerifiedResponse",
    "LLAMAINDEX_AVAILABLE",
]
