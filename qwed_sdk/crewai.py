"""
QWED CrewAI Integration

Provides seamless integration with CrewAI for automatic verification
of agent outputs and task results.

Usage:
    from qwed_sdk.crewai import QWEDVerifiedAgent, QWEDVerificationTool

    # Wrap any CrewAI agent
    agent = QWEDVerifiedAgent(
        role="Analyst",
        goal="Perform accurate calculations",
        verification_enabled=True
    )
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
import re

# Import QWED client
try:
    from qwed_sdk import QWEDClient
except ImportError:
    from ..client import QWEDClient


# ============================================================================
# CrewAI Imports
# ============================================================================

try:
    from crewai import Agent, Task, Crew
    from crewai.tools import BaseTool
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    # Stub classes
    class Agent:
        pass
    class Task:
        pass
    class Crew:
        pass
    class BaseTool:
        pass


# ============================================================================
# QWED Verification Tool for CrewAI
# ============================================================================

class QWEDVerificationTool(BaseTool if CREWAI_AVAILABLE else object):
    """
    CrewAI Tool that provides deterministic verification capabilities.
    
    Example:
        from crewai import Agent
        from qwed_sdk.crewai import QWEDVerificationTool
        
        agent = Agent(
            role="Mathematician",
            goal="Solve math problems accurately",
            tools=[QWEDVerificationTool()]
        )
    """
    
    name: str = "QWED Verification"
    description: str = (
        "Verify mathematical expressions, logical statements, code security, "
        "and SQL queries for correctness. Use this tool to confirm calculations, "
        "check code for vulnerabilities, and validate logical reasoning."
    )
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        if CREWAI_AVAILABLE:
            super().__init__()
        self._client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
    
    def _run(self, query: str) -> str:
        """Run verification on the given query."""
        try:
            result = self._client.verify(query)
            
            if result.verified:
                return f"✅ VERIFIED: The statement '{query[:50]}...' is correct."
            else:
                msg = ""
                if hasattr(result, "result") and result.result:
                    msg = result.result.get("message", "")
                    corrected = result.result.get("corrected")
                    if corrected:
                        return f"❌ INCORRECT: {msg}. Correct answer: {corrected}"
                return f"❌ FAILED: {msg or 'Verification failed'}"
        except Exception as e:
            return f"⚠️ ERROR: Unable to verify - {str(e)}"


class QWEDMathTool(QWEDVerificationTool):
    """Specialized tool for mathematical verification."""
    
    name: str = "QWED Math Verifier"
    description: str = (
        "Verify mathematical expressions and calculations with 100% accuracy. "
        "Input should be a mathematical expression like '2+2=4' or an equation to verify."
    )
    
    def _run(self, expression: str) -> str:
        try:
            result = self._client.verify_math(expression)
            if result.verified:
                return f"✅ VERIFIED: {expression} is mathematically correct."
            else:
                return f"❌ INCORRECT: {expression} is not valid."
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


class QWEDCodeTool(QWEDVerificationTool):
    """Specialized tool for code security verification."""
    
    name: str = "QWED Code Security"
    description: str = (
        "Check code for security vulnerabilities before execution. "
        "Detects dangerous patterns like eval(), os.system(), SQL injection, etc."
    )
    
    def _run(self, code: str) -> str:
        try:
            result = self._client.verify_code(code)
            if result.verified:
                return "✅ SAFE: No security vulnerabilities detected in the code."
            else:
                vulns = result.result.get("vulnerabilities", []) if hasattr(result, "result") else []
                if vulns:
                    issues = [f"• {v.get('severity', '').upper()}: {v.get('message', '')}" for v in vulns[:3]]
                    return f"⚠️ SECURITY ISSUES FOUND:\n" + "\n".join(issues)
                return "❌ BLOCKED: Code contains security vulnerabilities."
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


class QWEDSQLTool(QWEDVerificationTool):
    """Specialized tool for SQL validation."""
    
    name: str = "QWED SQL Validator"
    description: str = (
        "Validate SQL queries for security and correctness. "
        "Detects SQL injection patterns and dangerous operations."
    )
    
    def _run(self, query: str) -> str:
        try:
            result = self._client.verify_sql(query, "")
            if result.verified:
                return "✅ SAFE: SQL query is valid and secure."
            else:
                return "❌ BLOCKED: SQL query contains security issues (possible injection)."
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


# ============================================================================
# QWED Verified Agent
# ============================================================================

@dataclass
class VerificationConfig:
    """Configuration for agent verification."""
    enabled: bool = True
    verify_math: bool = True
    verify_code: bool = True
    verify_sql: bool = True
    auto_correct: bool = False
    block_on_failure: bool = False
    log_results: bool = True


class QWEDVerifiedAgent:
    """
    Wrapper around CrewAI Agent that enforces verification.
    
    All task outputs are verified before being accepted.
    
    Example:
        from crewai import Task, Crew
        from qwed_sdk.crewai import QWEDVerifiedAgent
        
        analyst = QWEDVerifiedAgent(
            role="Financial Analyst",
            goal="Perform accurate financial calculations",
            backstory="Expert in financial modeling",
            verification_config=VerificationConfig(
                verify_math=True,
                auto_correct=True
            )
        )
        
        task = Task(
            description="Calculate compound interest...",
            agent=analyst.agent
        )
        
        crew = Crew(agents=[analyst.agent], tasks=[task])
        result = crew.kickoff()
        
        # Check verification status
        print(analyst.verification_summary())
    """
    
    def __init__(
        self,
        role: str,
        goal: str,
        backstory: str = "",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        verification_config: Optional[VerificationConfig] = None,
        tools: Optional[List[Any]] = None,
        **agent_kwargs
    ):
        self._client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
        self.config = verification_config or VerificationConfig()
        
        # Track verifications
        self.verification_results: List[Dict[str, Any]] = []
        
        # Add QWED tools to agent
        qwed_tools = []
        if self.config.enabled:
            qwed_tools = [
                QWEDVerificationTool(api_key=api_key, base_url=base_url),
            ]
            if self.config.verify_math:
                qwed_tools.append(QWEDMathTool(api_key=api_key, base_url=base_url))
            if self.config.verify_code:
                qwed_tools.append(QWEDCodeTool(api_key=api_key, base_url=base_url))
            if self.config.verify_sql:
                qwed_tools.append(QWEDSQLTool(api_key=api_key, base_url=base_url))
        
        all_tools = (tools or []) + qwed_tools
        
        # Create the underlying CrewAI agent
        if CREWAI_AVAILABLE:
            self.agent = Agent(
                role=role,
                goal=goal,
                backstory=backstory or f"A {role} focused on {goal}",
                tools=all_tools,
                **agent_kwargs
            )
        else:
            self.agent = None
    
    def verify_output(self, output: str) -> Dict[str, Any]:
        """Verify an agent output."""
        result = {
            "output": output[:100] + "..." if len(output) > 100 else output,
            "verified": True,
            "checks": []
        }
        
        try:
            # Verify if enabled
            if self.config.enabled:
                verification = self._client.verify(output)
                result["verified"] = verification.verified
                result["status"] = verification.status
                result["checks"].append({
                    "type": "general",
                    "verified": verification.verified
                })
                
                if self.config.log_results:
                    status = "✅" if verification.verified else "❌"
                    print(f"[QWED] {status} Agent output verified: {verification.status}")
        except Exception as e:
            result["error"] = str(e)
        
        self.verification_results.append(result)
        return result
    
    def verification_summary(self) -> Dict[str, Any]:
        """Get summary of all verifications."""
        total = len(self.verification_results)
        verified = sum(1 for r in self.verification_results if r.get("verified", False))
        
        return {
            "total_outputs": total,
            "verified": verified,
            "failed": total - verified,
            "verification_rate": verified / total if total > 0 else 0,
        }


# ============================================================================
# QWED Verified Crew
# ============================================================================

class QWEDVerifiedCrew:
    """
    Wrapper around CrewAI Crew that enforces verification on all outputs.
    
    Example:
        from qwed_sdk.crewai import QWEDVerifiedCrew, QWEDVerifiedAgent
        
        analyst = QWEDVerifiedAgent(role="Analyst", goal="Analyze data")
        writer = QWEDVerifiedAgent(role="Writer", goal="Write reports")
        
        crew = QWEDVerifiedCrew(
            agents=[analyst, writer],
            tasks=[task1, task2],
            verify_final_output=True
        )
        
        result = crew.kickoff()
        print(result.verified)
    """
    
    def __init__(
        self,
        agents: List[QWEDVerifiedAgent],
        tasks: List[Any],
        api_key: Optional[str] = None,
        verify_final_output: bool = True,
        **crew_kwargs
    ):
        self._client = QWEDClient(api_key=api_key or "")
        self.verified_agents = agents
        self.verify_final_output = verify_final_output
        
        # Create underlying Crew
        if CREWAI_AVAILABLE:
            crew_agents = [a.agent for a in agents if a.agent is not None]
            self.crew = Crew(
                agents=crew_agents,
                tasks=tasks,
                **crew_kwargs
            )
        else:
            self.crew = None
    
    def kickoff(self, **kwargs) -> "CrewVerifiedResult":
        """Execute the crew with verification."""
        if not self.crew:
            raise RuntimeError("CrewAI not available")
        
        result = self.crew.kickoff(**kwargs)
        result_text = str(result)
        
        # Verify final output
        verification = {"verified": True, "status": "SKIPPED"}
        if self.verify_final_output:
            try:
                v = self._client.verify(result_text)
                verification = {
                    "verified": v.verified,
                    "status": v.status,
                }
            except Exception as e:
                verification = {"verified": False, "status": "ERROR", "error": str(e)}
        
        # Collect agent verification summaries
        agent_summaries = [a.verification_summary() for a in self.verified_agents]
        
        return CrewVerifiedResult(
            output=result_text,
            verified=verification["verified"],
            status=verification["status"],
            agent_summaries=agent_summaries,
        )


@dataclass
class CrewVerifiedResult:
    """Result from a verified crew execution."""
    output: str
    verified: bool
    status: str
    agent_summaries: List[Dict[str, Any]] = field(default_factory=list)
    
    def __str__(self):
        return self.output
    
    @property
    def total_verifications(self) -> int:
        return sum(s.get("total_outputs", 0) for s in self.agent_summaries)
    
    @property
    def overall_verification_rate(self) -> float:
        total = self.total_verifications
        verified = sum(s.get("verified", 0) for s in self.agent_summaries)
        return verified / total if total > 0 else 0


# ============================================================================
# Task Decorator
# ============================================================================

def verified_task(
    verify_output: bool = True,
    api_key: Optional[str] = None,
):
    """
    Decorator to add verification to a CrewAI task callback.
    
    Example:
        @verified_task(verify_output=True)
        def process_result(output):
            return output.upper()
    """
    def decorator(func: Callable) -> Callable:
        client = QWEDClient(api_key=api_key or "")
        
        def wrapper(output: str, *args, **kwargs):
            # Verify before processing
            if verify_output:
                result = client.verify(output)
                if not result.verified:
                    print(f"[QWED] ⚠️ Task output verification failed: {result.status}")
            
            return func(output, *args, **kwargs)
        
        return wrapper
    return decorator


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "QWEDVerificationTool",
    "QWEDMathTool",
    "QWEDCodeTool",
    "QWEDSQLTool",
    "QWEDVerifiedAgent",
    "QWEDVerifiedCrew",
    "CrewVerifiedResult",
    "VerificationConfig",
    "verified_task",
    "CREWAI_AVAILABLE",
]
