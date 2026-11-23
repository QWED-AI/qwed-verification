"""
Control Plane: The Kernel Entry Point.

This module orchestrates the entire request lifecycle:
Request -> Policy Check -> Routing -> Translation -> Verification -> Response
"""

import asyncio
import hashlib
import math
import os
import time
import logging
from typing import Dict, Any, Optional, Tuple
from qwed_new.core.router import Router
from qwed_new.core.policy import PolicyEngine
from qwed_new.core.translation_record import (
    RAW_LLM_OUTPUT_KEY,
    Translation,
    audit_record,
    translation_in,
    translation_of,
)
from qwed_new.core.translator import TranslationLayer
from qwed_new.core.verifier import VerificationEngine, DISPROVEN_STATUS
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.observability import metrics_collector
from qwed_new.core.security import EnhancedSecurityGateway, redact_pii
from qwed_new.core.output_sanitizer import OutputSanitizer
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    admission_decision,
    claim_verified,
    enforce_trust_decision,
)
from qwed_new.core.attestation import create_verification_attestation, AttestationStatus
from qwed_new.core.failure_cause import (
    INPUT_REFUSED,
    POLICY_BLOCKED,
    TRANSLATION_FAILED,
    LandedTranslations,
    deadline_after,
    diagnostic_for,
    diagnostic_for_exception,
    message_for,
    message_of,
)
# Every z3 solve runs on the one z3 thread, which the consensus Z3 engine
# shares (#659); the provider translation runs concurrently via
# _run_provider_call.
from qwed_new.core.z3_thread import run_z3_call as _run_z3_call

logger = logging.getLogger(__name__)

# A provider (LLM) call does blocking network I/O. It runs in a worker thread
# under a wall-clock bound so a slow or hung upstream cannot tie up the shared
# event loop and stall every co-tenant's request (#390). The bound is
# QWED_PROVIDER_TIMEOUT where set, otherwise the default.
_DEFAULT_PROVIDER_CALL_TIMEOUT_SECONDS = 30.0


def _provider_timeout_seconds(raw: str | None) -> float:
    """The provider call's bound, from ``raw`` (QWED_PROVIDER_TIMEOUT), or
    the default where it is not set. A value that is not a finite number of
    seconds above zero is refused when the module loads, before any request
    (#519): infinity or NaN bounds nothing, and no deadline can be read
    against it; zero or less would end every call at once. A fraction of a
    second is a valid bound."""
    if raw is None:
        return _DEFAULT_PROVIDER_CALL_TIMEOUT_SECONDS
    try:
        seconds = float(raw)
    except ValueError:
        seconds = math.nan
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"QWED_PROVIDER_TIMEOUT must be a finite number of seconds above zero, not {raw!r}")
    return seconds


_PROVIDER_CALL_TIMEOUT_SECONDS = _provider_timeout_seconds(os.environ.get("QWED_PROVIDER_TIMEOUT"))

# An error after the model answered (#519): the engine, the solver, the
# attestation, the sanitiser or the metrics failed, not the translation, so
# it names no translation cause. BLOCKED on both control-plane routes.
PIPELINE_ERROR = "control_plane.pipeline_error"
_PIPELINE_ERROR_MESSAGE = "Internal pipeline error"


def _logic_failure(
    error: BaseException,
    translated: bool,
    translation: Translation | None,
    translation_model: str | None,
    answered: LandedTranslations,
    answered_by: int,
) -> dict[str, Any]:
    """The error, cause, model and audit record of a /verify/logic request
    that raised (#519). ``translated`` is set once the bridge returned, and
    ``answered`` holds what the bridge handed over as soon as the model
    answered, each noted with when it landed; ``answered_by`` is the
    provider deadline. Where the bridge did not return its translation, the
    first entry is the model's answer, kept for the row (#578) even when it
    came after the deadline.

    A provider call out of time before the model answered is a failed
    translation, named as on /verify/natural_language; one that expires in
    the DSL step, after the model answered, is not. Which it was is read
    as at the deadline: the worker thread runs on after it, and an answer
    that lands late does not change the cause. Any other error is the
    pipeline's own, BLOCKED: one escaping the bridge is not the model's,
    since the bridge names every provider error, and the solver and every
    later step come after the translation. The answer kept and the in-time
    check come from one read, so they cannot disagree."""
    landed, in_time = answered.read(answered_by)
    if translation is None and landed:
        translation = landed[0]
        translation_model = translation.translation_model
    if not (translated or in_time) and isinstance(error, (TimeoutError, asyncio.TimeoutError)):
        fields = {"error": message_of(error, TRANSLATION_FAILED), "constraint_id": TRANSLATION_FAILED}
    else:
        fields = {"error": _PIPELINE_ERROR_MESSAGE, "constraint_id": PIPELINE_ERROR}
    return {**fields, "translation_model": translation_model, RAW_LLM_OUTPUT_KEY: audit_record([translation])}


async def _run_provider_call(func, *args, **kwargs):
    """Run a blocking provider call off the event loop, bounded by a timeout."""
    return await asyncio.wait_for(
        asyncio.to_thread(func, *args, **kwargs),
        timeout=_PROVIDER_CALL_TIMEOUT_SECONDS,
    )


def natural_language_admission(diagnostic: DiagnosticResult) -> AdmissionDecision:
    """Admission for a verdict reached through an LLM translation.

    The engine decided only the translated expression; nothing proves that
    expression means what the user asked. The verdict is kept as produced
    (QWED #15), but it is admitted for the user's query only when its
    developer fields record that the query semantics were verified.
    """
    if diagnostic.developer_fields.get("query_semantics_verified") is not True:
        return AdmissionDecision.BLOCKED
    return admission_decision(diagnostic)


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
        translation_model: Optional[str] = None,
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
            # The configured model that translated, never trusted (#585).
            "translation_model": translation_model,
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
        admission is DENY; it is never reported as UNVERIFIABLE. An
        expression that holds gets no is_valid: it proves the model's
        translation, not the user's claim, so nothing in the result may read
        as a valid claim (#630), as for a satisfiable logic result.
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
                developer_fields=verification_result,
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

        The engine checked only the LLM's translated expression, never the
        user's question, so the verdict carries that expression and its scope:
        a consumer reading only the diagnostic cannot mistake it for proof of
        the question itself.
        """
        # The provider and model that translated travel with the verdict,
        # so the route's response and audit row name them (#585). They
        # admit nothing.
        provenance = {
            key: trust_boundary[key]
            for key in ("provider_used", "translation_model")
            if key in trust_boundary
        }
        verification_result = {
            **verification_result,
            **provenance,
            "translated_expression": expression,
            "verification_scope": "translated_expression_only",
            "query_semantics_verified": False,
        }
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
            # claim_verified (#577): false here even when the expression
            # holds, as the expression is the model's translation of the
            # question. The route's own token says the same.
            verified=claim_verified(dr),
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

    def _translate_math(
        self, query: str, provider: Optional[str]
    ) -> Tuple[MathVerificationTask, Translation]:
        """Translate, then record the translation and name the model, on one
        worker thread: under auto-shift the model is the side that answered
        this thread's call (#585, #578)."""
        task = self.translator.translate(query, provider=provider)
        return task, translation_of(self.translator, "math", task, provider)

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
            # The screen's reason names the pattern it matched: the log
            # keeps it, the caller reads the cause's own message (#519).
            message = message_for(INPUT_REFUSED)
            return {
                "status": "BLOCKED",
                "error": message,
                **self._stopped(diagnostic_for(INPUT_REFUSED, message), organization_id),
                "latency_ms": (time.time() - start_time) * 1000
            }
        
        # 1. Policy Enforcement (Rate Limits & Business Rules)
        allowed, reason = self.policy.check_policy(query, organization_id=organization_id)
        if not allowed:
            return {
                "status": "BLOCKED",
                "error": reason,
                **self._stopped(diagnostic_for(POLICY_BLOCKED, reason), organization_id),
                "latency_ms": (time.time() - start_time) * 1000
            }
            
        # 2. Routing (Select Provider)
        provider = self.router.route(query, preferred_provider)
        # The audit record, once the model has returned (#578): an error
        # after that point keeps it.
        raw_llm_output = None
        # Set once the model has answered: an error after that is no
        # translation cause (#519).
        translated = False
        
        try:
            # 3. Translation (LLM Call)
            # Note: We currently assume it's a math query for the main endpoint.
            # Future: Router should also classify intent (Math vs Logic vs Fact).
            task, translation = await _run_provider_call(
                self._translate_math, query, provider
            )
            translated = True
            translation_model = translation.translation_model
            # What the model returned, for the audit row only (#578). It is
            # set on the response after sanitising, which escapes text, and
            # no route returns this dict.
            raw_llm_output = audit_record([translation])
            # A query the model calls not maths was still decided by a
            # translation, so the result names it (#585).
            not_math = {
                "status": "NOT_MATH_QUERY",
                "provider_used": provider,
                "translation_model": translation_model,
                RAW_LLM_OUTPUT_KEY: raw_llm_output,
            }
            
            # 3.5. Query Classification - Detect trivial/non-math expressions
            # If LLM returned a trivial expression (like "0" or "2+2"), it's likely not math
            if task.expression in ["0", "1", "2+2", "1+1"] or task.reasoning.lower().startswith("this is not a math"):
                return {
                    **not_math,
                    "error": "This doesn't appear to be a mathematical question. Please ask a calculation or formula-based question.",
                    "suggestion": "Try queries like: 'What is 15% of 200?' or 'Calculate compound interest...'",
                    "latency_ms": (time.time() - start_time) * 1000
                }
            
            # 3.6. Confidence Check - Ensure this is actually a math query
            if task.confidence < 0.5:  # Low confidence = not a math query
                return {
                    **not_math,
                    "error": "This doesn't appear to be a math question",
                    "confidence": task.confidence,
                    "latency_ms": (time.time() - start_time) * 1000
                }
            
            # 4. Verification (Deterministic Engine)
            verification_result = self.math_verifier.verify_math(
                expression=task.expression,
                expected_value=task.claimed_answer
            )
            trust_boundary = self._build_math_trust_boundary(
                provider, verification_result, translation_model
            )

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
                "translation_model": translation_model,
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
            response["admission"] = natural_language_admission(enforced).value
            response[RAW_LLM_OUTPUT_KEY] = raw_llm_output
            
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
            if raw_llm_output is None:
                # Output the safety check refused is kept too (#578).
                raw_llm_output = audit_record([translation_in(e)])
            # One verdict for the cause (#519). Before the model answered, no
            # provider, a failed translation or a provider call out of time is
            # UNVERIFIABLE, a refused text BLOCKED, each named. After it, the
            # engine, the attestation, the sanitiser or the metrics failed:
            # BLOCKED, as on /verify/logic.
            if translated:
                stopped = DiagnosticResult.blocked(
                    _PIPELINE_ERROR_MESSAGE, developer_fields={"constraint_id": PIPELINE_ERROR}
                )
            else:
                stopped = diagnostic_for_exception(e)
            return {
                "status": "ERROR",
                "error": str(e),
                **self._stopped(stopped, organization_id),
                RAW_LLM_OUTPUT_KEY: raw_llm_output,
                "latency_ms": (time.time() - start_time) * 1000
            }

    def _stopped(self, diagnostic: DiagnosticResult, organization_id: int | None) -> dict[str, Any]:
        """The verdict of a request stopped before any engine decided it
        (#519): a refusal, a policy block, no provider, a failed translation,
        or an error after the translation. The routes report this diagnostic
        as they report a decided one, so a cause reads the same on every
        route, and its admission is never ADMIT."""
        return {
            "diagnostic": self.output_sanitizer.sanitize_output(
                result=diagnostic.to_dict(),
                output_type="diagnostic",
                organization_id=organization_id,
            ),
            "admission": natural_language_admission(diagnostic).value,
        }

    def _logic_solve(self, dsl_code: str, variables: Any, claim_dsl: Optional[str]) -> tuple:
        """The z3 call for a logic translation (#631), as (function, args):
        prove the claim from the constraints, or, with no claim, check the
        constraints alone, which proves nothing however satisfiable."""
        if claim_dsl is None:
            return self.logic_verifier.verify_from_dsl, (dsl_code, variables)
        return self.logic_verifier.prove_from_dsl, (dsl_code, claim_dsl, variables)

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
                # The log keeps the screen's reason, as above (#519).
                "error": message_for(INPUT_REFUSED),
                "constraint_id": INPUT_REFUSED,  # #519: the same cause as on every route
                "latency_ms": (time.time() - start_time) * 1000
            }
            if organization_id:
                metrics_collector.track_request(organization_id, "BLOCKED", result["latency_ms"])
            return result

        # 1. Policy
        allowed, reason = self.policy.check_policy(query, organization_id=organization_id)
        if not allowed:
            result = {
                "status": "BLOCKED", "error": reason, "constraint_id": POLICY_BLOCKED,
                "latency_ms": (time.time() - start_time) * 1000,
            }
            if organization_id:
                metrics_collector.track_request(organization_id, "BLOCKED", result["latency_ms"])
            return result

        # 2. Routing
        provider = self.router.route(query, preferred_provider)
        last_known_provider = provider
        last_known_model = None
        # What the model returned, once it has (#578): an error after that
        # point keeps it.
        translation = None
        # Set once the provider call has returned (#519). The bridge names
        # every provider error itself, so the one translation cause named
        # here is the call running out of time before the model answered.
        translated = False
        # The bridge's translation, handed over as soon as the model has
        # answered: the provider deadline also covers the DSL step, and one
        # that expires there comes after the answer (#519, #578). Each is
        # noted with when it landed, so one that lands after the deadline
        # counts as late.
        answered = LandedTranslations()
        answered_by = deadline_after(_PROVIDER_CALL_TIMEOUT_SECONDS)

        # 3. DSL Logic Pipeline
        try:
            # Full Pipeline: NL -> DSL -> Verification
            # DSLLogicVerifier handles the translation internally via Azure/Anthropic
            # Provider translation runs off the loop and concurrently; the z3
            # solve runs on the single z3 thread. So the loop is never blocked,
            # logic requests translate in parallel, and z3 stays thread-safe.
            (
                dsl_code, variables, resolved_provider, error, claim_dsl, translation_model, translation,
            ) = await _run_provider_call(
                self.logic_verifier.translate_to_dsl, query, provider, on_translation=answered.append
            )
            translated = True
            last_known_model = translation_model
            if error is not None:
                result = error
            else:
                solve, args = self._logic_solve(dsl_code, variables, claim_dsl)
                result = await _run_z3_call(solve, *args)
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
                "translation_model": translation_model,
                "latency_ms": (time.time() - start_time) * 1000
            }
            constraint_id = getattr(result, "constraint_id", None)
            if constraint_id:
                response["constraint_id"] = constraint_id
            # The sorts Z3 decided the declared variables as: part of the
            # statement the verdict is about, beside the DSL.
            declarations = getattr(result, "declarations", None)
            if declarations:
                response["declarations"] = declarations

            # Sanitize Output
            response = self.output_sanitizer.sanitize_output(
                result=response,
                output_type="logic",
                organization_id=organization_id
            )
            # What the model returned, unsanitised, for the audit row only
            # (#578): logic_diagnostic keeps it out of the result.
            response[RAW_LLM_OUTPUT_KEY] = audit_record([translation])
            
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
                **_logic_failure(e, translated, translation, last_known_model, answered, answered_by),
                "provider_used": last_known_provider,
                "latency_ms": (time.time() - start_time) * 1000
            }

