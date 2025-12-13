"""
Control Plane: The Kernel Entry Point.

This module orchestrates the entire request lifecycle:
Request -> Policy Check -> Routing -> Translation -> Verification -> Response
"""

import time
import logging
from typing import Dict, Any, Optional
from qwed_new.core.router import Router
from qwed_new.core.policy import PolicyEngine
from qwed_new.core.translator import TranslationLayer
from qwed_new.core.verifier import VerificationEngine
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.observability import metrics_collector
from qwed_new.core.security import EnhancedSecurityGateway
from qwed_new.core.output_sanitizer import OutputSanitizer

logger = logging.getLogger(__name__)

class ControlPlane:
    """
    The QWED Kernel.
    """
    def __init__(self):
        self.router = Router()
        self.policy = PolicyEngine()
        self.translator = TranslationLayer()
        self.math_verifier = VerificationEngine()
        # Use new DSL-based Logic Verifier
        self.logic_verifier = DSLLogicVerifier()
        
        # Enterprise security components
        self.security_gateway = EnhancedSecurityGateway()
        self.output_sanitizer = OutputSanitizer()
        
    async def process_natural_language(
        self, 
        query: str, 
        organization_id: Optional[int] = None,
        preferred_provider: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main entry point for natural language verification.
        """
        start_time = time.time()
        
        # 0. Enhanced Security Check (OWASP LLM01:2025 - Prompt Injection)
        is_safe, security_reason = self.security_gateway.detect_advanced_injection(query)
        if not is_safe:
            logger.warning(f"Security block for org {organization_id}: {security_reason}")
            return {
                "status": "BLOCKED",
                "error": f"Security violation: {security_reason}",
                "latency_ms": (time.time() - start_time) * 1000
            }
        
        # 1. Policy Enforcement (Rate Limits & Business Rules)
        allowed, reason = self.policy.check_policy(query, organization_id=organization_id)
        if not allowed:
            return {
                "status": "BLOCKED",
                "error": reason,
                "latency_ms": (time.time() - start_time) * 1000
            }
            
        # 2. Routing (Select Provider)
        provider = self.router.route(query, preferred_provider)
        
        try:
            # 3. Translation (LLM Call)
            # Note: We currently assume it's a math query for the main endpoint.
            # Future: Router should also classify intent (Math vs Logic vs Fact).
            task: MathVerificationTask = self.translator.translate(query, provider=provider)
            
            # 3.5. Query Classification - Detect trivial/non-math expressions
            # If LLM returned a trivial expression (like "0" or "2+2"), it's likely not math
            if task.expression in ["0", "1", "2+2", "1+1"] or task.reasoning.lower().startswith("this is not a math"):
                return {
                    "status": "NOT_MATH_QUERY",
                    "error": "This doesn't appear to be a mathematical question. Please ask a calculation or formula-based question.",
                    "suggestion": "Try queries like: 'What is 15% of 200?' or 'Calculate compound interest...'",
                    "latency_ms": (time.time() - start_time) * 1000
                }
            
            # 3.6. Confidence Check - Ensure this is actually a math query
            if task.confidence < 0.5:  # Low confidence = not a math query
                return {
                    "status": "NOT_MATH_QUERY",
                    "error": "This doesn't appear to be a math question",
                    "confidence": task.confidence,
                    "latency_ms": (time.time() - start_time) * 1000
                }
            
            # 4. Verification (Deterministic Engine)
            verification_result = self.math_verifier.verify_math(
                expression=task.expression,
                expected_value=task.claimed_answer
            )
            
            # 5. Response Construction
            response = {
                "status": verification_result["status"],
                "final_answer": verification_result.get("calculated_value"),
                "user_query": query,
                "translation": task.dict(),
                "verification": verification_result,
                "provider_used": provider,
                "latency_ms": (time.time() - start_time) * 1000
            }
            
            # 6. Output Sanitization (OWASP LLM02:2025 - Insecure Output Handling)
            response = self.output_sanitizer.sanitize_output(
                result=response,
                output_type="math",
                organization_id=organization_id
            )
            # (Simple pass-through for now, but place is reserved)
            
            # 7. Track Metrics
            if organization_id:
                metrics_collector.track_request(
                    organization_id=organization_id,
                    status=response["status"],
                    latency_ms=response["latency_ms"],
                    provider=provider
                )
            
            return response
            
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e),
                "latency_ms": (time.time() - start_time) * 1000
            }

    async def process_logic_query(
        self,
        query: str,
        organization_id: Optional[int] = None,
        preferred_provider: Optional[str] = None,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """
        Entry point for logic puzzles using QWED-DSL pipeline.
        """
        start_time = time.time()

        # 0. Enhanced Security Check
        is_safe, security_reason = self.security_gateway.detect_advanced_injection(query)
        if not is_safe:
            logger.warning(f"Security block (logic) for org {organization_id}: {security_reason}")
            result = {
                "status": "BLOCKED",
                "error": f"Security violation: {security_reason}",
                "latency_ms": (time.time() - start_time) * 1000
            }
            if organization_id:
                metrics_collector.track_request(organization_id, "BLOCKED", result["latency_ms"])
            return result

        # 1. Policy
        allowed, reason = self.policy.check_policy(query, organization_id=organization_id)
        if not allowed:
            result = {"status": "BLOCKED", "error": reason, "latency_ms": (time.time() - start_time) * 1000}
            if organization_id:
                metrics_collector.track_request(organization_id, "BLOCKED", result["latency_ms"])
            return result

        # 2. Routing
        provider = self.router.route(query, preferred_provider)

        # 3. DSL Logic Pipeline
        try:
            # Full Pipeline: NL -> DSL -> Verification
            # DSLLogicVerifier handles the translation internally via Azure/Anthropic
            result = self.logic_verifier.verify_from_natural_language(
                query=query,
                provider=provider
            )
            
            response = {
                "status": result.status,
                "model": result.model,
                "dsl_code": result.dsl_code, # Expose DSL for transparency
                "error": result.error,
                "provider_used": provider,
                "latency_ms": (time.time() - start_time) * 1000
            }
            
            # Sanitize Output
            response = self.output_sanitizer.sanitize_output(
                result=response,
                output_type="logic",
                organization_id=organization_id
            )
            
            if organization_id:
                metrics_collector.track_request(
                    organization_id=organization_id,
                    status=response["status"],
                    latency_ms=response["latency_ms"],
                    provider=provider
                )
            
            return response
                    
        except Exception as e:
            return {
                "status": "ERROR",
                "error": f"Pipeline failure: {str(e)}",
                "latency_ms": (time.time() - start_time) * 1000
            }

