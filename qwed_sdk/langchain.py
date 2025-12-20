"""
QWED LangChain Integration

Provides seamless integration with LangChain for automatic verification
of LLM outputs in chains and agents.

Usage:
    from qwed_sdk.langchain import QWEDTool, QWEDVerificationCallback

    # As a Tool
    agent = initialize_agent(tools=[QWEDTool()], llm=llm)

    # As a Callback (auto-verify all outputs)
    chain = LLMChain(llm=llm, callbacks=[QWEDVerificationCallback()])
"""

from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
import json

# Import QWED client
try:
    from qwed_sdk import QWEDClient, QWEDAsyncClient
except ImportError:
    from ..client import QWEDClient, QWEDAsyncClient


# ============================================================================
# LangChain Tool
# ============================================================================

try:
    from langchain.tools import BaseTool
    from langchain.callbacks.base import BaseCallbackHandler
    from langchain.schema import LLMResult, AgentAction, AgentFinish
    from langchain.schema.messages import BaseMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    # Stub classes for type hints
    class BaseTool:
        pass
    class BaseCallbackHandler:
        pass


class QWEDTool(BaseTool if LANGCHAIN_AVAILABLE else object):
    """
    LangChain Tool that verifies mathematical and logical claims.
    
    Use in agents to give them deterministic verification capabilities.
    
    Example:
        from langchain.agents import initialize_agent
        from qwed_sdk.langchain import QWEDTool
        
        agent = initialize_agent(
            tools=[QWEDTool()],
            llm=ChatOpenAI(),
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        )
        
        result = agent.run("Verify: Is 2+2 equal to 5?")
    """
    
    name: str = "qwed_verify"
    description: str = (
        "Deterministically verify mathematical expressions, logical statements, "
        "and factual claims. Use this tool when you need to confirm the correctness "
        "of a calculation or logical reasoning. Input should be the expression or "
        "claim to verify."
    )
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ):
        if LANGCHAIN_AVAILABLE:
            super().__init__(**kwargs)
        self._client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
    
    def _run(self, query: str) -> str:
        """Synchronous verification."""
        try:
            result = self._client.verify(query)
            
            if result.verified:
                return f"✅ VERIFIED: {result.result.get('message', 'Correct')}"
            else:
                correction = result.result.get('corrected', '')
                if correction:
                    return f"❌ INCORRECT: {result.result.get('message', '')}. Correct answer: {correction}"
                return f"❌ FAILED: {result.result.get('message', 'Verification failed')}"
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"
    
    async def _arun(self, query: str) -> str:
        """Async verification (uses sync under the hood)."""
        return self._run(query)


class QWEDMathTool(QWEDTool):
    """Specialized tool for mathematical verification."""
    
    name: str = "qwed_math"
    description: str = (
        "Verify mathematical expressions and calculations with 100% accuracy. "
        "Input should be a mathematical expression like '2+2=4' or 'sqrt(16)=4'."
    )
    
    def _run(self, expression: str) -> str:
        try:
            result = self._client.verify_math(expression)
            if result.verified:
                return f"✅ VERIFIED: {expression} is correct"
            else:
                return f"❌ INCORRECT: {result.result.get('message', 'Invalid')}"
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


class QWEDLogicTool(QWEDTool):
    """Specialized tool for logical verification."""
    
    name: str = "qwed_logic"
    description: str = (
        "Verify logical constraints and find satisfying assignments. "
        "Input should be in QWED-Logic DSL format: (AND (GT x 5) (LT y 10))"
    )
    
    def _run(self, query: str) -> str:
        try:
            result = self._client.verify_logic(query)
            if result.verified:
                model = result.result.get('model', {})
                return f"✅ SAT: Satisfying assignment: {model}"
            else:
                return f"❌ UNSAT: No valid assignment exists"
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


class QWEDCodeTool(QWEDTool):
    """Specialized tool for code security verification."""
    
    name: str = "qwed_code"
    description: str = (
        "Check code for security vulnerabilities. "
        "Input should be Python or JavaScript code to analyze."
    )
    
    def _run(self, code: str) -> str:
        try:
            result = self._client.verify_code(code)
            if result.verified:
                return "✅ SAFE: No security issues detected"
            else:
                vulns = result.result.get('vulnerabilities', [])
                issues = [f"- {v['severity']}: {v['message']}" for v in vulns[:5]]
                return f"⚠️ SECURITY ISSUES:\n" + "\n".join(issues)
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


# ============================================================================
# LangChain Callback Handler
# ============================================================================

class QWEDVerificationCallback(BaseCallbackHandler if LANGCHAIN_AVAILABLE else object):
    """
    LangChain Callback that automatically verifies all LLM outputs.
    
    Attaches verification results to each generation.
    
    Example:
        from langchain.llms import OpenAI
        from langchain.chains import LLMChain
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(
            verify_math=True,
            verify_code=True,
            block_on_failure=False
        )
        
        chain = LLMChain(
            llm=OpenAI(),
            prompt=prompt,
            callbacks=[callback]
        )
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        verify_math: bool = True,
        verify_code: bool = True,
        verify_sql: bool = True,
        block_on_failure: bool = False,
        log_results: bool = True,
    ):
        self._client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
        self.verify_math = verify_math
        self.verify_code = verify_code
        self.verify_sql = verify_sql
        self.block_on_failure = block_on_failure
        self.log_results = log_results
        
        # Track verifications
        self.verification_results: List[Dict[str, Any]] = []
    
    def on_llm_end(self, response: "LLMResult", **kwargs) -> None:
        """Called after LLM generates output."""
        for generation_list in response.generations:
            for generation in generation_list:
                text = generation.text
                self._verify_output(text)
    
    def on_chain_end(self, outputs: Dict[str, Any], **kwargs) -> None:
        """Called after chain completes."""
        for key, value in outputs.items():
            if isinstance(value, str):
                self._verify_output(value)
    
    def on_agent_finish(self, finish: "AgentFinish", **kwargs) -> None:
        """Called when agent completes."""
        if isinstance(finish.return_values, dict):
            output = finish.return_values.get("output", "")
            if output:
                self._verify_output(output)
    
    def _verify_output(self, text: str) -> Dict[str, Any]:
        """Verify an output and record the result."""
        results = {
            "text": text[:100] + "..." if len(text) > 100 else text,
            "verifications": []
        }
        
        # Auto-detect and verify mathematical content
        if self.verify_math and self._contains_math(text):
            try:
                result = self._client.verify(text)
                results["verifications"].append({
                    "type": "math",
                    "verified": result.verified,
                    "status": result.status
                })
            except Exception:
                pass
        
        # Detect and verify code blocks
        if self.verify_code and self._contains_code(text):
            try:
                code = self._extract_code(text)
                if code:
                    result = self._client.verify_code(code)
                    results["verifications"].append({
                        "type": "code",
                        "verified": result.verified,
                        "vulnerabilities": len(result.result.get("vulnerabilities", []))
                    })
            except Exception:
                pass
        
        # Detect and verify SQL
        if self.verify_sql and self._contains_sql(text):
            try:
                sql = self._extract_sql(text)
                if sql:
                    result = self._client.verify_sql(sql, "")
                    results["verifications"].append({
                        "type": "sql",
                        "verified": result.verified
                    })
            except Exception:
                pass
        
        self.verification_results.append(results)
        
        if self.log_results and results["verifications"]:
            self._log_results(results)
        
        return results
    
    def _contains_math(self, text: str) -> bool:
        """Check if text contains mathematical content."""
        import re
        math_patterns = [
            r'\d+\s*[+\-*/]\s*\d+',  # Basic arithmetic
            r'=\s*\d+',              # Equations
            r'\d+%',                 # Percentages
            r'sqrt|sin|cos|tan',    # Functions
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in math_patterns)
    
    def _contains_code(self, text: str) -> bool:
        """Check if text contains code."""
        code_markers = ['```', 'def ', 'class ', 'import ', 'function ']
        return any(marker in text for marker in code_markers)
    
    def _contains_sql(self, text: str) -> bool:
        """Check if text contains SQL."""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE TABLE']
        return any(kw in text.upper() for kw in sql_keywords)
    
    def _extract_code(self, text: str) -> Optional[str]:
        """Extract code block from text."""
        import re
        match = re.search(r'```(?:\w+)?\n(.*?)```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None
    
    def _extract_sql(self, text: str) -> Optional[str]:
        """Extract SQL from text."""
        import re
        match = re.search(r'(SELECT|INSERT|UPDATE|DELETE|CREATE)\s+.*?(?:;|$)', 
                          text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(0).strip()
        return None
    
    def _log_results(self, results: Dict[str, Any]) -> None:
        """Log verification results."""
        for v in results["verifications"]:
            status = "✅" if v.get("verified") else "❌"
            print(f"[QWED] {status} {v['type'].upper()}: verified={v.get('verified')}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all verifications."""
        total = len(self.verification_results)
        verified = sum(
            1 for r in self.verification_results 
            if all(v.get("verified", False) for v in r.get("verifications", []))
        )
        return {
            "total_outputs": total,
            "verified": verified,
            "verification_rate": verified / total if total > 0 else 0
        }


# ============================================================================
# LangChain Chain Wrapper
# ============================================================================

class QWEDVerifiedChain:
    """
    Wrapper that adds verification to any LangChain chain.
    
    Example:
        from langchain.chains import LLMChain
        from qwed_sdk.langchain import QWEDVerifiedChain
        
        base_chain = LLMChain(llm=llm, prompt=prompt)
        verified_chain = QWEDVerifiedChain(base_chain)
        
        result = verified_chain.run("Calculate 15% of 200")
        print(result.verified)  # True/False
        print(result.output)    # The LLM output
    """
    
    def __init__(
        self,
        chain: Any,
        api_key: Optional[str] = None,
        auto_correct: bool = False,
    ):
        self.chain = chain
        self._client = QWEDClient(api_key=api_key or "")
        self.auto_correct = auto_correct
    
    def run(self, *args, **kwargs) -> "VerifiedOutput":
        """Run chain and verify output."""
        output = self.chain.run(*args, **kwargs)
        
        verification = self._client.verify(output)
        
        if self.auto_correct and not verification.verified:
            corrected = verification.result.get("corrected")
            if corrected:
                output = corrected
        
        return VerifiedOutput(
            output=output,
            verified=verification.verified,
            status=verification.status,
            attestation=getattr(verification, 'attestation', None)
        )
    
    async def arun(self, *args, **kwargs) -> "VerifiedOutput":
        """Async run chain and verify output."""
        output = await self.chain.arun(*args, **kwargs)
        verification = self._client.verify(output)
        
        return VerifiedOutput(
            output=output,
            verified=verification.verified,
            status=verification.status,
            attestation=getattr(verification, 'attestation', None)
        )


@dataclass
class VerifiedOutput:
    """Output with verification metadata."""
    output: str
    verified: bool
    status: str
    attestation: Optional[str] = None
    
    def __str__(self):
        return self.output


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "QWEDTool",
    "QWEDMathTool",
    "QWEDLogicTool",
    "QWEDCodeTool",
    "QWEDVerificationCallback",
    "QWEDVerifiedChain",
    "VerifiedOutput",
    "LANGCHAIN_AVAILABLE",
]
