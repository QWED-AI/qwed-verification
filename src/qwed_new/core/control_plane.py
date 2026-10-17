"""
Control Plane: The Kernel Entry Point.

This module orchestrates the entire request lifecycle:
Request -> Policy Check -> Routing -> Translation -> Verification -> Response
"""

import asyncio
import concurrent.futures
import functools
import hashlib
import os
import time
import logging
from typing import Dict, Any, Optional
from qwed_new.core.router import Router
from qwed_new.core.policy import PolicyEngine
from qwed_new.core.translator import TranslationLayer
from qwed_new.core.verifier import VerificationEngine, DISPROVEN_STATUS
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.observability import metrics_collector
from qwed_new.core.security import EnhancedSecurityGateway, redact_pii
from qwed_new.core.output_sanitizer import OutputSanitizer
from qwed_new.core.diagnostics import DiagnosticResult, admission_decision, enforce_trust_decision
from qwed_new.core.attestation import create_verification_attestation, AttestationStatus

logger = logging.getLogger(__name__)

# A provider (LLM) call does blocking network I/O. It runs in a worker thread
# under a wall-clock bound so a slow or hung upstream cannot tie up the shared
# event loop and stall every co-tenant's request (#390).
_PROVIDER_CALL_TIMEOUT_SECONDS = float(os.environ.get("QWED_PROVIDER_TIMEOUT", "30"))


async def _run_provider_call(func, *args, **kwargs):
    """Run a blocking provider call off the event loop, bounded by a timeout."""
    return await asyncio.wait_for(
        asyncio.to_thread(func, *args, **kwargs),
        timeout=_PROVIDER_CALL_TIMEOUT_SECONDS,
    )


# z3py's default context is not thread safe, and its objects must be created and
# freed on the same thread. A single-worker executor keeps every z3 solve on one
# dedicated thread: off the event loop, never concurrent with another solve, and
# never finalising z3 objects on a foreign thread. Only the fast solve runs here
# (the provider translation runs concurrently via _run_provider_call), so the
# queue stays short.
_Z3_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="qwed-z3")
_Z3_CALL_TIMEOUT_SECONDS = float(os.environ.get("QWED_Z3_TIMEOUT", "15"))


async def _run_z3_call(func, *args, **kwargs):
    """Run a z3 solve on the single z3 thread, bounded by a timeout."""
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(_Z3_EXECUTOR, functools.partial(func, *args, **kwargs)),
        timeout=_Z3_CALL_TIMEOUT_SECONDS,
    )


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

    @staticmethod
    def _build_math_trust_boundary(
        provider: str,
        verification_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Describe exactly what the math pipeline did and did not prove."""
        expression_status = verification_result.get("status")
        deterministic_evaluation = expression_status in {"VERIFIED", DISPROVEN_STATUS}
        return {
            "query_interpretation_source": "llm_translation",
            "query_semantics_verified": False,
            "verification_scope": "translated_expression_only",
            "deterministic_expression_evaluation": deterministic_evaluation,
            "formal_proof": False,
            "translation_claim_self_consistent": verification_result.get("is_correct"),
            "provider_used": provider,
        }

    @staticmethod
    def _determine_math_response_status(verification_result: Dict[str, Any]) -> str:
        """Avoid representing translated-query evaluation as a proven user-query verdict."""
        expression_status = verification_result.get("status")
        if expression_status in {"VERIFIED", DISPROVEN_STATUS}:
            return "INCONCLUSIVE"
        if expression_status == "SYNTAX_ERROR":
            return "ERROR"
        return expression_status or "ERROR"
        
    @staticmethod
    def _math_diagnostic(expression: str, verification_result: Dict[str, Any]) -> tuple:
        """Build the decided DiagnosticResult for a VERIFIED / DISPROVEN math
        result, with the evidence string its attestation must bind to.

        A proven-false claim (#437) is VERIFIED with is_valid False, so
        admission is DENY; it is never reported as UNVERIFIABLE.
        """
        legacy_status = verification_result["status"]
        evidence = {
            "expression": expression,
            "calculated_value": verification_result.get("calculated_value"),
            "claimed_value": verification_result.get("claimed_value"),
            "diff": verification_result.get("diff"),
            "precision_mode": verification_result.get("precision_mode"),
            "status": legacy_status,
        }
        if legacy_status == "VERIFIED":
            dr = DiagnosticResult.verified(
                "Expression verified successfully",
                developer_fields={**verification_result, "is_valid": True},
                evidence=evidence,
                proof_data=str(evidence),
            )
        else:
            dr = DiagnosticResult.disproven(
                "Claimed value is proven false",
                developer_fields=verification_result,
                evidence=evidence,
                proof_data=str(evidence),
            )
        return dr, str(evidence)

    def _enforce_math_verdict(
        self,
        expression: str,
        verification_result: Dict[str, Any],
        trust_boundary: Dict[str, Any],
    ) -> DiagnosticResult:
        """Turn the engine result into an enforced DiagnosticResult.

        Attestation is always required — advisory mode was a temporary
        migration measure (#265). Decided verdicts (VERIFIED / DISPROVEN) are
        signed; anything else goes through the fail-closed legacy mapping.
        """
        if verification_result.get("status", "ERROR") not in ("VERIFIED", DISPROVEN_STATUS):
            # from_legacy_dict raises only for VERIFIED / DISPROVEN without
            # proof_ref, which never reach this branch.
            dr = DiagnosticResult.from_legacy_dict(verification_result, engine="math")
            return enforce_trust_decision(
                dr,
                require_attestation=True,
                query=expression,  # #279 — consistent log-side hash attribution to expression
            )

        dr, proof_data = self._math_diagnostic(expression, verification_result)
        # (#279) Attest the translated formula — not the natural-language
        # query — so qwed.query_hash binds to the expression the deterministic
        # engine actually verified, not the user's prose.
        att_result = create_verification_attestation(
            status="VERIFIED",
            verified=dr.developer_fields.get("is_valid") is True,
            engine="math",
            query=expression,
            confidence=1.0,
            proof_data=proof_data,
        )
        if att_result.status is not AttestationStatus.ISSUED:
            logger.warning(
                "trust_boundary.attestation_failed query_hash=%s status=%s",
                hashlib.sha256(expression.encode()).hexdigest()[:16] if expression else "unknown",
                att_result.status.value,
            )
            trust_boundary["attestation_error"] = att_result.error_code
            return DiagnosticResult.blocked(
                "Attestation unavailable — cannot sign VERIFIED result",
                developer_fields={"constraint_id": "api.attestation.signing_error"},
            )
        return enforce_trust_decision(
            dr,
            require_attestation=True,
            attestation_token=att_result.token,
            query=expression,  # #279 — must match qwed.query_hash in the attestation
        )

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
                "error": f"Security Policy Violation: {security_reason}",
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
            task: MathVerificationTask = await _run_provider_call(
                self.translator.translate, query, provider=provider
            )
            
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
            trust_boundary = self._build_math_trust_boundary(provider, verification_result)

            # 4.5 Trust Boundary Enforcement (Issue #191 / #265)
            enforced = self._enforce_math_verdict(task.expression, verification_result, trust_boundary)
            trust_boundary["trust_enforced"] = enforced.status.value
            trust_boundary["attestation_policy"] = "mandatory"
            response_status = enforced.status.value
            trust_boundary["overall_status"] = enforced.status.value

            # 5. Response Construction
            # Admission is a separate decision from the verdict (QWED #15):
            # VERIFIED alone does not mean the claim holds.
            response = {
                "status": response_status,
                "final_answer": verification_result.get("calculated_value"),
                "user_query": query,
                "translation": task.dict(),
                "verification": verification_result,
                "trust_boundary": trust_boundary,
                "provider_used": provider,
                "latency_ms": (time.time() - start_time) * 1000
            }
            
            # 6. Output Sanitization (OWASP LLM02:2025 - Insecure Output Handling)
            response = self.output_sanitizer.sanitize_output(
                result=response,
                output_type="math",
                organization_id=organization_id
            )
            # The sanitizer may reject the translated expression and set status
            # to ERROR; the verdict must not outlive that rejection.
            if response.get("status") != enforced.status.value:
                enforced = DiagnosticResult.blocked(
                    "Output sanitization rejected the translated expression",
                    developer_fields={"constraint_id": "control_plane.output_sanitization"},
                )
            # The enforced verdict travels with the response so API consumers
            # (e.g. /verify/natural_language) use it instead of re-deriving it
            # from the legacy engine dict.
            response["diagnostic"] = self.output_sanitizer.sanitize_output(
                result=enforced.to_dict(),
                output_type="diagnostic",
                organization_id=organization_id,
            )
            response["admission"] = admission_decision(enforced).value
            
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
                "error": f"Security Policy Violation: {security_reason}",
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
        last_known_provider = provider

        # 3. DSL Logic Pipeline
        try:
            # Full Pipeline: NL -> DSL -> Verification
            # DSLLogicVerifier handles the translation internally via Azure/Anthropic
            # Provider translation runs off the loop and concurrently; the z3
            # solve runs on the single z3 thread. So the loop is never blocked,
            # logic requests translate in parallel, and z3 stays thread-safe.
            dsl_code, variables, resolved_provider, error = await _run_provider_call(
                self.logic_verifier.translate_to_dsl, query, provider
            )
            if error is not None:
                result = error
            else:
                result = await _run_z3_call(self.logic_verifier.verify_from_dsl, dsl_code, variables)
                result.provider_used = resolved_provider
                if not result.dsl_code:
                    result.dsl_code = dsl_code
            resolved_provider = result.provider_used or provider
            last_known_provider = resolved_provider
            
            response = {
                "status": result.status,
                "model": result.model,
                "dsl_code": result.dsl_code, # Expose DSL for transparency
                "error": result.error,
                "provider_used": resolved_provider,
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
                    provider=resolved_provider
                )
            
            return response
                    
        except Exception as e:
            # Log detailed error server-side, with PII redaction
            logger.error(
                f"Logic pipeline failure for org {organization_id}: {redact_pii(str(e))}",
                exc_info=False
            )
            return {
                "status": "ERROR",
                "error": "Internal pipeline error",
                "provider_used": last_known_provider,
                "latency_ms": (time.time() - start_time) * 1000
            }

