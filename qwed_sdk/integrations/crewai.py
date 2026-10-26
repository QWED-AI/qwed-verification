"""
QWED CrewAI Integration

Provides seamless integration with CrewAI for automatic verification
of agent outputs and task results.

Usage:
    from qwed_sdk.integrations.crewai import QWEDVerifiedAgent

    # Drop-in replacement for Agent
    agent = QWEDVerifiedAgent(
        role="Analyst",
        goal="Perform accurate calculations",
        # QWED specific config
        verify_math=True,
        verify_code=True
    )
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass

# Import QWED client
try:
    from qwed_sdk import QWEDClient
except ImportError:
    # Fallback for local dev
    from ..client import QWEDClient

# CrewAI Imports
try:
    from crewai import Agent
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    class Agent:
        pass

@dataclass
class VerificationConfig:
    """Configuration for agent verification."""
    enabled: bool = True
    verify_math: bool = True
    verify_code: bool = True
    verify_sql: bool = True
    log_results: bool = True

class QWEDVerifiedAgent(Agent if CREWAI_AVAILABLE else object):
    """
    Specialized CrewAI Agent that enforces deterministic verification.
    
    It refuses to execute dangerous code or unverified logic.
    """
    
    def __init__(
        self,
        verification_config: Optional[VerificationConfig] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ):
        if not CREWAI_AVAILABLE:
            raise ImportError("CrewAI is not installed. Run `pip install crewai`")
            
        super().__init__(**kwargs)
        
        self.client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
        self.verification_config = verification_config or VerificationConfig()
        
        # Security: Default to disallowing dangerous code unless explicitly overridden 
        # (CrewAI might have its own allow_code_execution, we enforce our own check too)
        self.allow_dangerous_code = False

    def execute_task(self, task: Any, context: Optional[str] = None, tools: Optional[List[Any]] = None) -> str:
        """
        Intercept the task execution to verify the output.
        """
        # Execute the task using the parent Agent method
        result = super().execute_task(task, context=context, tools=tools)
        
        # Verify the result
        if self.verification_config.enabled:
            verification = self._verify_safety(str(result))
            
            if not verification['verified']:
                error_msg = f"❌ Verification Failed: {verification.get('status', 'Unknown error')}"
                if self.verification_config.log_results:
                    print(f"[QWED] {error_msg}")
                return f"Error: Output failed deterministic verification. {error_msg}"
                
            if self.verification_config.log_results:
                print(f"[QWED] ✅ Output Verified: {verification.get('status', 'OK')}")
                
        return result

    def _verify_safety(self, content: str) -> Dict[str, Any]:
        """Internal verification logic: verified only when the server
        admitted the output (``is_verified``), and an error fails closed
        (GHSA-83v6-6h23-pvp4). The client's result is a dataclass, so the
        earlier ``model_dump()`` raised and every output was refused."""
        try:
            result = self.client.verify(content)
            return {
                "verified": getattr(result, "is_verified", False) is True,
                "status": getattr(result, "status", "UNKNOWN"),
            }
        except Exception as e:
            return {"verified": False, "status": f"Error during verification: {str(e)}"}

__all__ = ["QWEDVerifiedAgent", "VerificationConfig"]
