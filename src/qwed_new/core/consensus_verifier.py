"""
Enterprise Consensus Verifier: Multi-Engine Verification Orchestrator.

Consensus is advisory only (#633): every engine decides a model's translation
of the question, and the question states no claim of the caller's, so engines
that agree have not verified anything. A consensus result is UNVERIFIABLE or
BLOCKED, never VERIFIED, in every mode, and carries ``advisory_only``.

Enhanced Features:
1. Async parallel execution
2. Circuit breaker for failing engines
3. Engine health monitoring
4. Adaptive timeouts
5. Weighted consensus
"""

from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal
import time
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError

# #340: hard per-engine wall-clock budget for the synchronous execution
# paths (the async path enforces the same bound via asyncio.wait_for).
_ENGINE_TIMEOUT_SECONDS = 30

# #352: breaker-rejected engines surface this verbatim in their BLOCKED result
_CIRCUIT_OPEN_ERROR = "Engine excluded by open circuit breaker"
import threading

from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus
from qwed_new.core.translation_record import Translation, audit_record, translation_in, translation_of
from qwed_new.core.z3_thread import run_z3_call_blocking
from qwed_new.core.failure_cause import (
    CAUSES,
    INPUT_REFUSED,
    NO_PROVIDER,
    TRANSLATION_CAUSES,
    TRANSLATION_FAILED,
    LandedTranslations,
    cause_of,
    deadline_after,
    diagnostic_for,
    message_of,
    now_ns,
)
from qwed_new.providers.base import TranslationRefused

from .verification_context import VerificationContextDocument


logger = logging.getLogger(__name__)
SECURE_EXECUTION_REQUIRED = "SECURE_EXECUTION_REQUIRED"
_NONE_CONSENSUS_KEY = object()
# The agreement status of a result only one engine verified (#320): one engine
# is not a consensus, so the result is BLOCKED.
NO_INDEPENDENT_VERIFICATION = "no_independent_verification"
# Every engine stopped before it decided anything, for one translation cause
# (#519: no provider, or a failed translation): UNVERIFIABLE, with the cause.
NOT_TRANSLATED = "not_translated"
# The message of a consensus whose engines agree (#633).
ADVISORY_MESSAGE = (
    "Consensus verification is advisory only: engines that agree on the model's "
    "translation of the question have not verified a claim"
)
# The statuses a consensus result may have (#633).
_ADVISORY_STATUSES = (DiagnosticStatus.UNVERIFIABLE, DiagnosticStatus.BLOCKED)


def advisory(result: DiagnosticResult) -> DiagnosticResult:
    """``result`` as the consensus route returns it (#633): marked
    ``advisory_only``, and UNVERIFIABLE unless it is UNVERIFIABLE or BLOCKED.

    ``ConsensusResult.to_diagnostic_result`` never returns VERIFIED; this
    holds the route to that whatever verifier produced the result, so no
    status reaches the response, the attestation or the audit row as
    VERIFIED. A result that is let through keeps its message and fields.
    """
    fields = {**result.developer_fields, "advisory_only": True}
    if isinstance(result.status, DiagnosticStatus) and result.status in _ADVISORY_STATUSES:
        return result.with_audit_record(result.raw_llm_output, developer_fields=fields)
    # Whatever the result said of the question's meaning, nothing here
    # checked it.
    fields.pop("query_semantics_verified", None)
    return DiagnosticResult.unverifiable(ADVISORY_MESSAGE, developer_fields=fields).with_audit_record(
        result.raw_llm_output
    )


def stopped_diagnostic(result: Any) -> DiagnosticResult | None:
    """The verdict of a consensus that stopped before any engine decided
    (all engines blocked, or a named cause: #519), else None. A named cause
    has its one verdict, as on every route: no provider or a failed
    translation is UNVERIFIABLE, a refused question BLOCKED. It reads the
    result's fields, so any result with them will do."""
    fields = {
        "agreement_status": result.agreement_status,
        "confidence": result.confidence,
        "engines_used": result.engines_used,
    }
    cause = getattr(result, "cause", None)
    if isinstance(cause, str) and cause in CAUSES:
        message = getattr(result, "cause_message", None)
        return diagnostic_for(cause, message if isinstance(message, str) else None, fields)
    if result.agreement_status == "blocked":
        return DiagnosticResult.blocked("Consensus verification: all engines blocked", developer_fields=fields)
    return None


def _cause_fields(exc: BaseException, translated: bool) -> dict[str, str | None]:
    """The named cause an engine's exception stands for (#519), with the
    message a caller may see for it, as EngineResult fields. Only the
    translation step names one: once the model has answered, an error is
    the engine's, the code check's or the sandbox's, and has no cause, so
    the engine stays BLOCKED, as before."""
    if translated:
        return {"cause": None, "cause_message": None}
    cause = cause_of(exc)
    return {"cause": cause, "cause_message": message_of(exc, cause)}


def _first(translations: List[Translation]) -> Optional[Translation]:
    """The translation an engine asked for, or None when it got none."""
    return translations[0] if translations else None


def _keep_refused(error: BaseException, translations: Optional[List[Translation]], engine: str) -> None:
    """Add the output the safety check refused, where ``error`` carries it,
    to ``translations``: the audit row keeps it (#578)."""
    refused = translation_in(error)
    if refused is not None and translations is not None:
        translations.append(refused.for_engine(engine))


class _EngineCall:
    """A translating engine, with the list of translations this request
    owns (#578). The engine adds its translation as soon as the model
    returns, so a timeout or failure branch can still keep it. The list
    notes when each translation landed, and the call when the engine
    started, so a timeout reads both as at its deadline (#519)."""

    def __init__(self, method: Callable[[str, List[Translation]], "EngineResult"]):
        self.method = method
        self.translations: LandedTranslations = LandedTranslations()
        self.started_ns: int | None = None

    def __call__(self, query: str) -> "EngineResult":
        self.started_ns = now_ns()
        return self.method(query, self.translations)

    def started_before(self, deadline_ns: int) -> bool:
        """Whether the engine had started by ``deadline_ns``."""
        started = self.started_ns
        return started is not None and started < deadline_ns


def _snapshot(call: Any) -> Optional[Translation]:
    """The translation an engine call holds now, for a result built without
    it (a timeout or failure). A copy, so a worker that finishes later
    cannot change the result. None for an engine that does not translate."""
    if isinstance(call, _EngineCall):
        return _first(list(call.translations))
    return None


def _timed_out(call: Any, deadline_ns: int) -> dict[str, Any]:
    """The fields of an engine that ran out of time at ``deadline_ns``: its
    translation, where it had one, and its cause (#519). A translating
    engine that had started by the deadline and had no translation by it
    was still waiting for the model, so it is a failed translation, as a
    provider call out of time is on every route. An engine that had its
    translation, and so stopped after it, names no cause, nor does one that
    does not translate, nor one that had not started (queued behind other
    work, it asked the model nothing): each stays BLOCKED, as before.

    Both are read as at the deadline, from when the engine started and when
    its translation landed, not from whether a cancel still reached it: the
    worker runs on after the deadline, and what it does then, starting or
    translating, does not change the cause, though a late translation is
    kept for the audit row (#578). The translation and the in-time check
    come from one read, so they cannot disagree."""
    if not isinstance(call, _EngineCall):
        return {"translation": None}
    kept, in_time = call.translations.read(deadline_ns)
    translation = _first(kept)
    if call.started_before(deadline_ns) and not in_time:
        return {
            "translation": translation,
            "cause": TRANSLATION_FAILED,
            "cause_message": message_of(TimeoutError(), TRANSLATION_FAILED),
        }
    return {"translation": translation}


def chain_record(chain: Any) -> Optional[str]:
    """The audit record (#578) of the translations in a verification chain,
    or None when no engine had one. An entry that is not an EngineResult
    carries none."""
    return audit_record(
        result.translation
        for result in chain
        if isinstance(result, EngineResult) and isinstance(result.translation, Translation)
    )


class VerificationMode(str, Enum):
    """Verification depth modes."""
    SINGLE = "single"      # Fast, single engine
    HIGH = "high"          # 2 engines
    MAXIMUM = "maximum"    # 3+ engines


class EngineState(str, Enum):
    """Engine health state."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OPEN = "open"  # Circuit breaker open


@dataclass
class EngineResult:
    """Result from a single verification engine."""
    engine_name: str
    method: str
    result: Any
    confidence: float  # 0.0 to 1.0 — advisory only
    latency_ms: float
    success: bool
    error: Optional[str] = None
    status: Optional[str] = None  # DiagnosticStatus value — preserves status through consensus
    # What the model translated the query into for this engine, with the
    # provider and model (#578, #585); None when the engine had no translation.
    # Left out of repr: it is the model's unsanitised output.
    translation: Optional[Translation] = field(default=None, repr=False)
    # Why the engine stopped before deciding, where a named cause did (#519:
    # failure_cause), with the message a caller may see for it.
    cause: str | None = None
    cause_message: str | None = None

    def provenance(self) -> Dict[str, Optional[str]]:
        """The provider and model whose translation this engine decided on,
        both None when it had none."""
        if self.translation is None:
            return {"provider_used": None, "translation_model": None}
        return self.translation.provenance()


@dataclass
class ConsensusResult:
    """Result from multi-engine consensus verification."""
    final_answer: Any
    confidence: float
    engines_used: int
    agreement_status: str  # "unanimous", "majority", "split", "no_consensus"
    verification_chain: List[EngineResult]
    total_latency_ms: float
    parallel_execution: bool = False
    status: Optional[DiagnosticStatus] = None  # from _calculate_consensus
    # Always None: consensus is advisory and proves nothing (#633). Kept so
    # code that reads them keeps working.
    proof_ref: Optional[str] = None
    verified_evidence: Optional[Dict[str, Any]] = None
    # The named cause the consensus stopped for, where one did (#519): a
    # refused question, or every engine stopped for the same translation
    # cause. ``cause_message`` is the message a caller may see for it.
    cause: str | None = None
    cause_message: str | None = None

    def raw_llm_output(self) -> Optional[str]:
        """Every engine's translation, as the audit record (#578), or None
        when no engine had one."""
        return chain_record(self.verification_chain)

    def stopped_diagnostic(self) -> DiagnosticResult | None:
        """See ``stopped_diagnostic``."""
        return stopped_diagnostic(self)

    def to_diagnostic_result(self) -> DiagnosticResult:
        """Convert this ConsensusResult to a DiagnosticResult.

        This is the canonical path for the /verify/consensus endpoint —
        the conversion logic lives here so the endpoint is a thin wrapper.
        The result is UNVERIFIABLE or BLOCKED, never VERIFIED, and carries
        ``advisory_only`` (#633): a status that says VERIFIED, from a
        result built by hand, is read as UNVERIFIABLE.
        """
        developer_fields: Dict[str, Any] = {
            "agreement_status": self.agreement_status,
            "confidence": self.confidence,
            "engines_used": self.engines_used,
            "advisory_only": True,
        }
        if self.cause in CAUSES:
            return diagnostic_for(self.cause, self.cause_message, developer_fields)
        status_val = self.status.value if isinstance(self.status, DiagnosticStatus) else str(self.status)
        if status_val == DiagnosticStatus.VERIFIED.value:
            status_val = DiagnosticStatus.UNVERIFIABLE.value
        if status_val == DiagnosticStatus.BLOCKED.value:
            if self.agreement_status == NO_INDEPENDENT_VERIFICATION:
                return DiagnosticResult.blocked(
                    "Consensus verification: blocked, as one engine is not a consensus "
                    "and no other engine verified the answer",
                    developer_fields={**developer_fields, "constraint_id": "consensus.no_independent_verification"},
                )
            return DiagnosticResult.blocked(
                "Consensus verification: blocked",
                developer_fields=developer_fields,
            )
        else:
            return DiagnosticResult.unverifiable(
                self._unverifiable_message(status_val),
                developer_fields=developer_fields,
            )

    def _unverifiable_message(self, status_val: str) -> str:
        """The message of a consensus that is not VERIFIED or BLOCKED."""
        blocked_count = sum(1 for r in self.verification_chain if r.status in ("BLOCKED", DiagnosticStatus.BLOCKED.value))
        if self.agreement_status == "majority":
            return "Consensus verification: majority agreement"
        if self.agreement_status == "split":
            return "Consensus verification: no agreement"
        if self.agreement_status == "no_results":
            return "Consensus verification: no engine results available"
        if self.agreement_status == "all_failed":
            return "Consensus verification: all engines failed"
        if self.agreement_status == "no_answer":
            return "Consensus verification: no engine computed an answer"
        if status_val == DiagnosticStatus.UNVERIFIABLE.value and blocked_count > 0:
            return "Consensus verification: incomplete — some engines blocked"
        if status_val == DiagnosticStatus.UNVERIFIABLE.value:
            return ADVISORY_MESSAGE
        return "Consensus verification: no agreement"


@dataclass
class EngineHealth:
    """Health metrics for an engine."""
    name: str
    state: EngineState = EngineState.HEALTHY
    consecutive_failures: int = 0
    total_calls: int = 0
    total_failures: int = 0
    avg_latency_ms: float = 0.0
    last_failure_time: Optional[float] = None
    circuit_open_until: Optional[float] = None


class CircuitBreaker:
    """
    Circuit breaker pattern for engine reliability.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: After threshold failures, block requests for recovery_time
    - HALF_OPEN: After recovery_time, allow one test request

    Attributes:
        failure_threshold (int): Number of failures before opening circuit.
        recovery_time (float): Seconds to wait before attempting recovery.
        success_threshold (int): Number of successes to close circuit.
    """
    
    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_time_seconds: float = 30.0,
        success_threshold: int = 2
    ):
        """
        Initialize Circuit Breaker.

        Args:
            failure_threshold: Consecutive failures to trigger open state.
            recovery_time_seconds: Seconds to wait in open state.
            success_threshold: Consecutive successes to recover from degraded.
        """
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time_seconds
        self.success_threshold = success_threshold
        
        self._engines: Dict[str, EngineHealth] = {}
        self._lock = threading.RLock()
    
    def get_health(self, engine_name: str) -> EngineHealth:
        """
        Get or create engine health record.

        Args:
            engine_name: Name of the engine.

        Returns:
            EngineHealth object.
        """
        with self._lock:
            if engine_name not in self._engines:
                self._engines[engine_name] = EngineHealth(name=engine_name)
            return self._engines[engine_name]
    
    def is_available(self, engine_name: str) -> bool:
        """
        Check if engine is available for requests.

        Args:
            engine_name: Name of the engine.

        Returns:
            bool: True if engine can accept requests.
        """
        with self._lock:
            health = self.get_health(engine_name)
            
            if health.state == EngineState.HEALTHY:
                return True
            
            if health.state == EngineState.OPEN:
                # Check if recovery time has passed
                if health.circuit_open_until and time.time() > health.circuit_open_until:
                    # Transition to half-open (allow test request)
                    health.state = EngineState.DEGRADED
                    return True
                return False
            
            # DEGRADED state - allow requests
            return True
    
    def record_success(self, engine_name: str, latency_ms: float):
        """
        Record successful request.

        Args:
            engine_name: Name of the engine.
            latency_ms: Request latency in milliseconds.
        """
        with self._lock:
            health = self.get_health(engine_name)
            health.total_calls += 1
            health.consecutive_failures = 0
            
            # Update average latency
            if health.avg_latency_ms == 0:
                health.avg_latency_ms = latency_ms
            else:
                health.avg_latency_ms = (health.avg_latency_ms * 0.9 + latency_ms * 0.1)
            
            # If degraded, check if we should transition to healthy
            if health.state == EngineState.DEGRADED:
                health.state = EngineState.HEALTHY
    
    def record_failure(self, engine_name: str):
        """
        Record failed request.

        Args:
            engine_name: Name of the engine.
        """
        with self._lock:
            health = self.get_health(engine_name)
            health.total_calls += 1
            health.total_failures += 1
            health.consecutive_failures += 1
            health.last_failure_time = time.time()
            
            # Check if circuit should open
            if health.consecutive_failures >= self.failure_threshold:
                health.state = EngineState.OPEN
                health.circuit_open_until = time.time() + self.recovery_time
    
    def get_all_health(self) -> Dict[str, Dict[str, Any]]:
        """
        Get health status for all engines.

        Returns:
            Dict mapping engine names to health statistics.
        """
        with self._lock:
            return {
                name: {
                    "state": health.state.value,
                    "failures": health.total_failures,
                    "calls": health.total_calls,
                    "avg_latency_ms": round(health.avg_latency_ms, 2),
                    "failure_rate": round(health.total_failures / max(health.total_calls, 1), 3)
                }
                for name, health in self._engines.items()
            }

    def reset(self):
        """Reset all tracked engine health states in a thread-safe manner."""
        with self._lock:
            self._engines.clear()




class ConsensusVerifier:
    """
    Enterprise Consensus Verification Orchestrator.
    
    Advisory only (#633): its results are UNVERIFIABLE or BLOCKED, never
    VERIFIED, however many engines agree.

    Features:
    - Parallel async execution of multiple engines
    - Circuit breaker for failing engines
    - Engine health monitoring
    - Adaptive timeouts
    - Weighted consensus calculation

    Attributes:
        max_workers (int): Maximum number of parallel worker threads.
        circuit_breaker (CircuitBreaker): Circuit breaker instance.
    """
    
    # Default timeouts per engine (ms)
    DEFAULT_TIMEOUTS = {
        "SymPy": 5000,
        "Python": 10000,
        "Z3": 5000,
        "Stats": 10000,
        "Image": 15000
    }
    
    # Engine reliability weights
    ENGINE_WEIGHTS = {
        "SymPy": 1.0,      # Deterministic math is most reliable
        "Z3": 0.995,       # Formal logic solver
        "Python": 0.99,    # Code execution
        "Stats": 0.98,     # Statistical analysis
        "Image": 0.80      # VLM-dependent
    }
    
    # Engines that decide whether a claim holds rather than compute a value
    # (#659). One that proves the claim counts as an engine that verified,
    # but its verdict is not an answer, so it does not vote on the answer.
    CLAIM_ENGINES = frozenset({"Z3"})

    def __init__(
        self,
        max_workers: int = 4,
        enable_circuit_breaker: bool = True
    ):
        """
        Initialize Consensus Verifier.
        
        Args:
            max_workers: Max parallel engine threads.
            enable_circuit_breaker: Enable circuit breaker pattern.

        Example:
            >>> verifier = ConsensusVerifier(max_workers=8)
        """
        self.max_workers = max_workers
        self.circuit_breaker = CircuitBreaker() if enable_circuit_breaker else None
        
        # Lazy-loaded engines
        self._math_verifier = None
        self._logic_verifier = None
        self._code_verifier = None
        self._secure_executor = None
        self._stats_verifier = None
        self._translator = None
        self._reasoning_verifier = None
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
    
    # Lazy loading properties
    @property
    def math_verifier(self):
        if self._math_verifier is None:
            from qwed_new.core.verifier import VerificationEngine
            self._math_verifier = VerificationEngine()
        return self._math_verifier

    @property
    def translator(self):
        if self._translator is None:
            from qwed_new.core.translator import TranslationLayer
            self._translator = TranslationLayer()
        return self._translator
    
    @property
    def logic_verifier(self):
        """The DSL bridge the Z3 engine translates and proves with, as the
        control plane's logic route does (#659)."""
        if self._logic_verifier is None:
            from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
            self._logic_verifier = DSLLogicVerifier()
        return self._logic_verifier
    
    @property
    def code_verifier(self):
        if self._code_verifier is None:
            from qwed_new.core.code_verifier import CodeVerifier
            from qwed_new.core.secure_code_executor import SANDBOX_BOUND_NAMES
            # The code runs in the sandbox, with its names bound (GHSA-7xrf).
            self._code_verifier = CodeVerifier(bound_names=SANDBOX_BOUND_NAMES)
        return self._code_verifier

    @property
    def secure_executor(self):
        if self._secure_executor is None:
            from qwed_new.core.secure_code_executor import SecureCodeExecutor
            self._secure_executor = SecureCodeExecutor()
        return self._secure_executor
    
    @property
    def stats_verifier(self):
        if self._stats_verifier is None:
            from qwed_new.core.stats_verifier import StatsVerifier
            self._stats_verifier = StatsVerifier()
        return self._stats_verifier
    
    @property
    def reasoning_verifier(self):
        if self._reasoning_verifier is None:
            from qwed_new.core.reasoning_verifier import ReasoningVerifier
            self._reasoning_verifier = ReasoningVerifier()
        return self._reasoning_verifier
    
    # =========================================================================
    # Synchronous Verification
    # =========================================================================
    
    def verify_with_consensus(
        self,
        query: str,
        mode: VerificationMode = VerificationMode.SINGLE,
        min_confidence: float = 0.95,
        parallel: bool = True
    ) -> ConsensusResult:
        """
        Verify query using multiple engines.
        
        Args:
            query: The query to verify.
            mode: Verification depth (SINGLE, HIGH, MAXIMUM).
            min_confidence: Minimum required confidence.
            parallel: Use parallel execution.
            
        Returns:
            ConsensusResult with answer and confidence.

        Example:
            >>> result = verifier.verify_with_consensus("2+2", mode=VerificationMode.HIGH)
            >>> print(result.final_answer)
        """
        start_time = time.time()
        refused = self._refused(query, start_time)
        if refused:
            return refused
        
        # Determine engines to use
        engine_methods = self._select_engines(query, mode)
        
        # Execute verification
        if parallel and len(engine_methods) > 1:
            results = self._execute_parallel(query, engine_methods)
        else:
            results = self._execute_sequential(query, engine_methods)
        
        # Calculate consensus
        consensus = self._calculate_consensus(results)
        total_latency = (time.time() - start_time) * 1000
        
        return ConsensusResult(
            final_answer=consensus["answer"],
            confidence=consensus["confidence"],
            engines_used=len(results),
            agreement_status=consensus["status"],
            verification_chain=results,
            total_latency_ms=total_latency,
            parallel_execution=parallel and len(engine_methods) > 1,
            status=consensus.get("diagnostic_status"),
            cause=consensus.get("cause"),
            cause_message=consensus.get("cause_message"),
        )
    
    # =========================================================================
    # Async Verification
    # =========================================================================
    
    async def verify_async(
        self,
        query: str,
        mode: VerificationMode = VerificationMode.SINGLE,
        timeout_seconds: float = 30.0
    ) -> ConsensusResult:
        """
        Async verification using multiple engines in parallel.

        Args:
            query: The query to verify.
            mode: Verification depth.
            timeout_seconds: Max time for ALL engines (one aggregate deadline).

        Returns:
            ConsensusResult object.

        Example:
            >>> result = await verifier.verify_async("2+2")
        """
        start_time = time.time()
        # Off the event loop: on a long question the check takes tens of
        # milliseconds, which would stall every request on this worker (#340).
        refused = await asyncio.to_thread(self._refused, query, start_time)
        if refused:
            return refused
        engine_methods = self._select_engines(query, mode)

        results = []
        mono_start_ns = time.monotonic_ns()
        deadline_ns = mono_start_ns + int(timeout_seconds * 1_000_000_000)

        # #352: a DEDICATED per-call executor sized to the engine list.
        # Every engine starts immediately (nothing ever queues), so a hung
        # engine can neither poison a pool shared with other requests nor
        # starve a sibling — the root cause the started-Event patches were
        # working around. Cooperative cancellation remains issue #353.
        pool = ThreadPoolExecutor(max_workers=max(1, len(engine_methods)))
        try:
            loop = asyncio.get_running_loop()
            tasks = []
            for engine_name, method in engine_methods:
                if self._is_engine_available(engine_name):
                    tasks.append(
                        (engine_name, loop.run_in_executor(pool, method, query), method)
                    )
                else:
                    # #352 review: a breaker-rejected engine must surface as
                    # an explicit, auditable BLOCKED result (QWED_RULES:
                    # degraded results stay explicit) — and WITHOUT extending
                    # breaker state, since a skipped request is not a new
                    # failure.
                    results.append(self._blocked_engine_result(
                        engine_name, "circuit_open",
                        _CIRCUIT_OPEN_ERROR,
                        record=False,
                    ))
            try:
                results.extend(await self._collect_engine_results(tasks, deadline_ns, mono_start_ns))
            except Exception:
                # Partial engine results are still usable for consensus
                # calculation.
                logger.exception("Unexpected async aggregation failure")
                results.append(EngineResult(
                    engine_name="consensus_orchestrator",
                    method="async_aggregation",
                    result=None,
                    confidence=0.0,
                    latency_ms=(time.time() - start_time) * 1000,
                    success=False,
                    error="async aggregation failed",
                    status="BLOCKED",
                ))
        finally:
            # discard the pool: queued work is cancelled, running threads
            # finish naturally but can never affect later requests
            pool.shutdown(wait=False, cancel_futures=True)

        consensus = self._calculate_consensus(results)
        total_latency = (time.time() - start_time) * 1000

        return ConsensusResult(
            final_answer=consensus["answer"],
            confidence=consensus["confidence"],
            engines_used=len(results),
            agreement_status=consensus["status"],
            verification_chain=results,
            total_latency_ms=total_latency,
            parallel_execution=True,
            status=consensus.get("diagnostic_status"),
            cause=consensus.get("cause"),
            cause_message=consensus.get("cause_message"),
        )

    def _refused(self, query: str, start_time: float) -> Optional[ConsensusResult]:
        """BLOCKED, with no answer, for a question the translation gate
        refuses (#632), else None.

        It is checked once, before any engine is dispatched, so the refusal
        does not depend on which engines run or on their breakers: no engine
        answers a refused question (Stats needs no model and would), and none
        records it as a failure.
        """
        from qwed_new.core.translator import TranslationLayer
        try:
            TranslationLayer().screen_question(query)
        except TranslationRefused as refused:
            return ConsensusResult(
                final_answer=None,
                confidence=0.0,
                engines_used=0,
                agreement_status="blocked",
                verification_chain=[],
                total_latency_ms=(time.time() - start_time) * 1000,
                status=DiagnosticStatus.BLOCKED,
                # The same cause as on every route (#519).
                cause=INPUT_REFUSED,
                cause_message=str(refused),
            )
        return None

    def _select_engines(self, query: str, mode: VerificationMode) -> List[Tuple[str, Callable]]:
        """Select engines based on mode and query type."""
        engines = []
        
        # Always include math
        engines.append(("SymPy", _EngineCall(self._verify_with_math)))
        
        if mode in [VerificationMode.HIGH, VerificationMode.MAXIMUM]:
            engines.append(("Python", _EngineCall(self._verify_with_code)))
        
        if mode == VerificationMode.MAXIMUM:
            engines.append(("Z3", _EngineCall(self._verify_with_logic)))
            
            # Add stats for statistical queries
            query_lower = query.lower()
            if any(kw in query_lower for kw in ["average", "mean", "median", "variance"]):
                engines.append(("Stats", self._verify_with_stats))
        
        return engines
    
    def _is_engine_available(self, engine_name: str) -> bool:
        """Check if engine is available (circuit breaker)."""
        if self.circuit_breaker:
            return self.circuit_breaker.is_available(engine_name)
        return True
    
    async def _collect_engine_results(self, tasks, deadline_ns: int, mono_start_ns: int) -> list:
        """Await engine tasks under ONE aggregate deadline (#352 review:
        sequential per-engine waits stack N x 30s and exceed the API's
        overall limit; the pool is sized to the engine list, so every task
        starts immediately and nothing queues)."""
        results = []
        for engine_name, task, call in tasks:
            result, failure, timed_out = await self._await_engine(task, deadline_ns)
            if failure is not None:
                # Engine exception: static result message (QWED str(exc)
                # advisory), full detail in the server log.
                logger.exception(
                    "Engine %s failed during async collection", engine_name,
                    exc_info=failure,
                )
                results.append(self._blocked_engine_result(
                    engine_name, "engine_error", "Engine execution failed",
                    latency_ms=(time.monotonic_ns() - mono_start_ns) // 1_000_000,
                    translation=_snapshot(call),
                ))
                continue
            if timed_out:
                # The pool is sized to the engine list, so an unfinished task
                # at expiry was genuinely running past its budget — record it
                # with the breaker.
                results.append(self._blocked_engine_result(
                    engine_name, "timeout", "Timeout",
                    latency_ms=(time.monotonic_ns() - mono_start_ns) // 1_000_000,
                    **_timed_out(call, deadline_ns),
                ))
                continue
            self._record_engine_result(engine_name, result)
            results.append(result)
        return results

    async def _await_engine(self, task, deadline_ns: int):
        """Await one engine task. Returns (result, failure, timed_out)."""
        remaining_s = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining_s > 0:
            try:
                return await asyncio.wait_for(task, timeout=remaining_s), None, False
            except asyncio.TimeoutError:
                return None, None, True
            except Exception as exc:
                return None, exc, False
        # Deadline already spent when we reach this task (the per-call pool
        # is sized to the engine list, so this task was RUNNING, not queued).
        if not task.done():
            # One loop tick lets a completion callback queued by a worker
            # that finished just before the deadline land — harvest it
            # instead of recording a false breaker penalty (Sentry on
            # PR #352).
            await asyncio.sleep(0)
        if not task.done() and (task.cancel() or task.cancelled()):
            return None, None, True
        # asyncio.Future.cancel() returns False ONLY when the task is already
        # done (unlike the wrapped concurrent.futures.Future, which reports
        # False for running workers). So past this point the task is always
        # finished: either it completed before the deadline-spent branch ran,
        # or it landed in the race window between the done() check and the
        # cancel request — either way it is harvested, never misclassified as
        # a timeout against a healthy engine, and exception() can never hit a
        # running future.
        if task.cancelled():
            return None, None, True
        exc = task.exception()
        if exc is None:
            # finished inside the window — harvest, never waste it
            return task.result(), None, False
        return None, exc, False

    def _record_engine_result(self, engine_name: str, result: EngineResult, answered: bool = True):
        """Record result with circuit breaker.

        The breaker measures engine health, not verdicts (#642), and every
        tenant shares it. An engine that answered within its time budget is
        healthy, whatever the answer: a wrong claim, an unsatisfiable model
        or a question it cannot use is about the question. Only an engine
        that did not answer, a timeout or an exception it did not handle
        (``answered=False``, from _blocked_engine_result), is a failure.
        """
        if self.circuit_breaker:
            if answered:
                self.circuit_breaker.record_success(engine_name, result.latency_ms)
            else:
                self.circuit_breaker.record_failure(engine_name)
    
    # =========================================================================
    # Execution Methods
    # =========================================================================
    
    def _blocked_engine_result(
        self,
        engine_name: str,
        method: str,
        error: str,
        latency_ms: float = 0,
        record: bool = True,
        translation: Optional[Translation] = None,
        cause: str | None = None,
        cause_message: str | None = None,
    ) -> EngineResult:
        """Build a BLOCKED EngineResult and record it with the circuit breaker.

        #340: hung engines never complete, so without recording here the
        breaker never opens and every tenant's consensus requests keep
        degrading until restart. ``translation`` is what the model returned
        before the engine stopped, where it had (#578); ``cause`` is the
        named cause it stopped for, where it is one (#519).
        """
        blocked = EngineResult(
            engine_name=engine_name,
            method=method,
            result=None,
            confidence=0.0,
            latency_ms=latency_ms,
            success=False,
            error=error,
            status="BLOCKED",
            translation=translation,
            cause=cause,
            cause_message=cause_message,
        )
        if record:
            self._record_engine_result(engine_name, blocked, answered=False)
        return blocked

    def _execute_parallel(self, query: str, engines: List[Tuple[str, Callable]]) -> List[EngineResult]:
        """Execute engines in parallel using thread pool."""
        results = []
        futures = {}
        calls = dict(engines)
        
        for engine_name, method in engines:
            if self._is_engine_available(engine_name):
                future = self._executor.submit(method, query)
                futures[future] = engine_name
            else:
                # #352 review: circuit-open engines must stay explicit — a
                # silent skip could let a remaining engine produce VERIFIED
                # from incomplete evidence.
                results.append(self._blocked_engine_result(
                    engine_name, "circuit_open",
                    _CIRCUIT_OPEN_ERROR,
                    record=False,
                ))
        
        # #340: as_completed raises TimeoutError FROM the for statement —
        # outside the inner try, so it escaped as an uncaught HTTP 500 after
        # blocking the caller for the full timeout. Catch it, cancel the
        # not-yet-started futures, and degrade to partial BLOCKED results.
        deadline_ns = deadline_after(_ENGINE_TIMEOUT_SECONDS)
        try:
            for future in as_completed(futures, timeout=_ENGINE_TIMEOUT_SECONDS):
                engine_name = futures[future]
                try:
                    # as_completed only yields DONE futures, so result() never
                    # times out here — the aggregate timeout surfaces from the
                    # for statement and is caught by the outer handler below
                    # (Sentry on PR #352: no dead inner timeout handler).
                    result = future.result()
                    self._record_engine_result(engine_name, result)
                    results.append(result)
                except Exception as e:
                    results.append(self._blocked_engine_result(
                        engine_name, "parallel_execution", str(e),
                        translation=_snapshot(calls[engine_name]),
                    ))
        except FutureTimeoutError:
            for future, engine_name in futures.items():
                # a started thread cannot be force-killed in Python; cancel
                # reaches only the not-yet-started futures
                future.cancel()
                if engine_name not in {r.engine_name for r in results}:
                    results.append(self._blocked_engine_result(
                        engine_name, "parallel_timeout",
                        f"Engine timed out after {_ENGINE_TIMEOUT_SECONDS}s",
                        **_timed_out(calls[engine_name], deadline_ns),
                    ))
        
        return results
    
    def _execute_sequential(self, query: str, engines: List[Tuple[str, Callable]]) -> List[EngineResult]:
        """Execute engines sequentially."""
        results = []
        
        # #340: NEVER run an engine inline on the caller's thread — a
        # synchronous engine call blocks the event loop for its full
        # duration (unbounded for LLM round trips + sympy evaluation).
        # Submit to the pool and wait with a hard per-engine timeout.
        for engine_name, method in engines:
            if self._is_engine_available(engine_name):
                future = self._executor.submit(method, query)
                deadline_ns = deadline_after(_ENGINE_TIMEOUT_SECONDS)
                try:
                    result = future.result(timeout=_ENGINE_TIMEOUT_SECONDS)
                    self._record_engine_result(engine_name, result)
                    results.append(result)
                except FutureTimeoutError:
                    future.cancel()
                    results.append(self._blocked_engine_result(
                        engine_name, "sequential_timeout",
                        f"Engine timed out after {_ENGINE_TIMEOUT_SECONDS}s",
                        **_timed_out(method, deadline_ns),
                    ))
                except Exception as e:
                    results.append(self._blocked_engine_result(
                        engine_name, "sequential_execution", str(e),
                        translation=_snapshot(method),
                    ))
            else:
                results.append(self._blocked_engine_result(
                    engine_name, "circuit_open",
                    _CIRCUIT_OPEN_ERROR,
                    record=False,
                ))
        
        return results
    
    # =========================================================================
    # Engine Methods
    # =========================================================================
    
    def _verify_with_math(self, query: str, translations: Optional[List[Translation]] = None) -> EngineResult:
        """Verify using SymPy math engine."""
        start = time.time()
        translations = [] if translations is None else translations
        translated = False
        try:
            expression, expected = self._parse_math_query(query, translations)
            translated = True
            result = self.math_verifier.verify_math(expression, expected)
            latency = (time.time() - start) * 1000
            is_correct = result.get("is_correct", False)

            return EngineResult(
                engine_name="SymPy",
                translation=_first(translations),
                method="symbolic_math",
                result=result.get("calculated_value"),
                confidence=1.0 if is_correct else 0.0,
                latency_ms=latency,
                success=is_correct,
                status="VERIFIED" if is_correct else "UNVERIFIABLE",
            )
        except Exception as e:
            # A failed translation or engine error: blocked, not fabricated.
            return EngineResult(
                engine_name="SymPy",
                translation=_first(translations),
                method="symbolic_math",
                result=None,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                success=False,
                error=str(e),
                status="BLOCKED",
                **_cause_fields(e, translated),
            )
    
    def _verify_with_code(self, query: str, translations: Optional[List[Translation]] = None) -> EngineResult:
        """Verify by executing Python code in the secure Docker sandbox."""
        start = time.time()
        translations = [] if translations is None else translations
        translated = False
        try:
            code = self._generate_verification_code(query, translations)
            translated = True

            safety_result = self.code_verifier.verify_code(code)
            if not safety_result.is_verified or safety_result.developer_fields.get("is_valid") is not True:
                return EngineResult(
                    engine_name="Python", method="code_execution",
                    translation=_first(translations),
                    result=None, confidence=0.0,
                    latency_ms=(time.time() - start) * 1000, success=False,
                    error=safety_result.agent_message,
                    status="BLOCKED",
                )

            success, error, output = self.secure_executor.execute(code, {})
            if not success:
                if error == "SECURE_RUNTIME_UNAVAILABLE":
                    error = SECURE_EXECUTION_REQUIRED
                return EngineResult(
                    engine_name="Python", method="code_execution",
                    translation=_first(translations),
                    result=None, confidence=0.0,
                    latency_ms=(time.time() - start) * 1000, success=False,
                    error=error, status="BLOCKED",
                )

            # Code execution is advisory-only — the code ran without runtime
            # errors, but executing an expression is not proving its result
            # matches an expected answer or satisfies the query's semantics.
            # Empirical runtime success disproves (by crashing); it cannot prove (#269).
            return EngineResult(
                engine_name="Python", method="code_execution",
                translation=_first(translations),
                result=output, confidence=0.99,
                latency_ms=(time.time() - start) * 1000, success=True,
                status="UNVERIFIABLE",
            )
        except Exception as e:
            return EngineResult(
                engine_name="Python", method="code_execution",
                translation=_first(translations),
                result=None, confidence=0.0,
                latency_ms=(time.time() - start) * 1000, success=False,
                error=str(e), status="BLOCKED",
                **_cause_fields(e, translated),
            )
    
    # The Z3 engine's status for each verdict prove_from_dsl gives (#659),
    # and why it is not VERIFIED. Only VALID is VERIFIED: the claim follows
    # from the constraints, which can all hold. INVALID, VACUOUS and UNKNOWN
    # are UNVERIFIABLE; a verdict not listed here (ERROR) is BLOCKED.
    _PROOF_VERDICTS = {
        "VALID": ("VERIFIED", None),
        "INVALID": ("UNVERIFIABLE", "The claim does not follow from the constraints: Z3 found a counterexample"),
        "VACUOUS": ("UNVERIFIABLE", "The constraints cannot all hold, so any claim would follow from them"),
        "UNKNOWN": ("UNVERIFIABLE", "Z3 did not decide whether the claim follows"),
    }

    def _verify_with_logic(self, query: str, translations: Optional[List[Translation]] = None) -> EngineResult:
        """Prove the claim of the model's logic translation from its
        constraints (#659), as /verify/logic does: the DSL bridge translates,
        and ``prove_from_dsl`` decides on the one z3 thread.

        VERIFIED only when the claim follows. A counterexample, constraints
        that cannot all hold, an undecided proof, or a translation that
        states no claim (constraints that can hold prove nothing, #631) is
        UNVERIFIABLE. A translation the bridge refuses, or a proof it cannot
        run, is BLOCKED. A z3 thread that does not answer in time raises
        TimeoutError, which the caller records as the engine failing.
        """
        start_ns = time.monotonic_ns()
        translations = [] if translations is None else translations
        # The bridge hands over the translation as soon as the model has
        # answered, before the DSL step, so an engine out of time while that
        # step runs keeps it and names no cause (#519).
        dsl_code, variables, _provider, refused, claim_dsl, _model, _translation = (
            self.logic_verifier.translate_to_dsl(
                query, on_translation=lambda found: translations.append(found.for_engine("Z3"))
            )
        )
        if refused is not None:
            # The bridge names the cause it stopped for, where it is one (#519).
            cause = refused.constraint_id if refused.constraint_id in CAUSES else None
            return self._z3_result(
                "BLOCKED", None, refused.error, translations, start_ns,
                cause=cause, cause_message=refused.error if cause else None,
            )
        if claim_dsl is None:
            return self._z3_result(
                "UNVERIFIABLE", None,
                "The translation states no claim to prove, and constraints that can hold prove nothing",
                translations, start_ns,
            )
        proof = run_z3_call_blocking(self.logic_verifier.prove_from_dsl, dsl_code, claim_dsl, variables)
        status, reason = self._PROOF_VERDICTS.get(
            proof.status, ("BLOCKED", proof.error or "Z3 could not run the proof")
        )
        return self._z3_result(status, proof.status, reason, translations, start_ns)

    @staticmethod
    def _z3_result(
        status: str, verdict: Optional[str], reason: Optional[str],
        translations: List[Translation], start_ns: int,
        cause: str | None = None, cause_message: str | None = None,
    ) -> EngineResult:
        """The Z3 engine's result: ``verdict`` is prove_from_dsl's, or None
        where no proof ran. ``start_ns`` is a ``time.monotonic_ns()``
        reading, so a wall-clock change cannot skew the latency."""
        return EngineResult(
            engine_name="Z3", method="claim_proof",
            translation=_first(translations),
            result=verdict,
            confidence=0.995 if status == "VERIFIED" else 0.0,
            latency_ms=(time.monotonic_ns() - start_ns) / 1_000_000,
            success=status == "VERIFIED",
            error=reason,
            status=status,
            cause=cause,
            cause_message=cause_message,
        )
    
    def _verify_with_stats(self, query: str) -> EngineResult:
        """Verify using Stats engine."""
        import statistics
        import re
        
        start = time.time()
        try:
            numbers = [float(x) for x in re.findall(r"[-+]?\d*\.?\d+", query)]
            
            query_lower = query.lower()
            if "average" in query_lower or "mean" in query_lower:
                result = statistics.mean(numbers)
            elif "median" in query_lower:
                result = statistics.median(numbers)
            elif "variance" in query_lower:
                result = statistics.variance(numbers)
            else:
                result = None
            
            # Statistical computation is advisory-only — calculating a value
            # is not verification. Only comparison against a claimed value
            # with proof of correctness should produce VERIFIED (#270).
            return EngineResult(
                engine_name="Stats", method="statistical_analysis",
                result=result,
                confidence=0.98 if result is not None else 0.0,
                latency_ms=(time.time() - start) * 1000,
                success=result is not None,
                status="UNVERIFIABLE",
            )
        except Exception as e:
            return EngineResult(
                engine_name="Stats", method="statistical_analysis",
                result=None, confidence=0.0,
                latency_ms=(time.time() - start) * 1000, success=False,
                error=str(e), status="BLOCKED",
            )
    
    def _verify_with_fact(self, _query: str) -> EngineResult:
        """Verify using Fact engine."""
        start = time.time()
        return EngineResult(
            engine_name="Fact",
            method="knowledge_retrieval",
            result=None,
            confidence=0.0,
            latency_ms=(time.time() - start) * 1000,
            success=False,
            error="External fact context is required for consensus fact verification"
        )
    
    # =========================================================================
    # Consensus Calculation
    # =========================================================================
    
    def _calculate_consensus(self, results: List[EngineResult]) -> Dict[str, Any]:
        """Calculate weighted consensus from engine results.

        Preserves DiagnosticStatus through aggregation:
        - BLOCKED engines are filtered out for counting but prevent VERIFIED
        - All BLOCKED → consensus BLOCKED
        - Any BLOCKED → maximum outcome is UNVERIFIABLE (fail-closed)
        - All UNVERIFIABLE → consensus UNVERIFIABLE
        - Verified by one engine alone, whatever the others did → BLOCKED:
          one engine is not a consensus (#320)
        - Otherwise UNVERIFIABLE, unanimous or not: consensus is advisory,
          never VERIFIED (#633)
        - A claim engine (CLAIM_ENGINES) counts as an engine that verified,
          but does not vote on the answer (#659)
        """
        if not results:
            return {"answer": None, "confidence": 0.0, "status": "no_results", "diagnostic_status": DiagnosticStatus.UNVERIFIABLE}

        if any(r.error == SECURE_EXECUTION_REQUIRED for r in results):
            return {"answer": None, "confidence": 0.0, "status": "blocked_secure_execution", "diagnostic_status": DiagnosticStatus.BLOCKED}

        blocked = [r for r in results if r.status == "BLOCKED"]
        active = [r for r in results if r.status != "BLOCKED"]

        if not active:
            blocked_errors = [r.error for r in blocked if r.error]
            cause, cause_message = self._shared_cause(blocked)
            if cause in TRANSLATION_CAUSES:
                # Nothing was translated, so nothing was decided (#519).
                return {
                    "answer": None,
                    "confidence": 0.0,
                    "status": NOT_TRANSLATED,
                    "diagnostic_status": DiagnosticStatus.UNVERIFIABLE,
                    "errors": blocked_errors,
                    "cause": cause,
                    "cause_message": cause_message,
                }
            return {
                "answer": None,
                "confidence": 0.0,
                "status": "blocked",
                "diagnostic_status": DiagnosticStatus.BLOCKED,
                "errors": blocked_errors,
                "cause": cause,
                "cause_message": cause_message,
            }

        successful = [r for r in active if r.success]

        if not successful:
            return {"answer": None, "confidence": 0.0, "status": "all_failed", "diagnostic_status": DiagnosticStatus.UNVERIFIABLE}

        # One engine is not a consensus (#320). An answer one engine verified
        # has not been verified by any other, whether the others were advisory
        # (Python in high mode), blocked or absent. In single mode the one
        # engine, SymPy, compares the expression the model translated with the
        # answer the same model gave, so the agreement is the model's with
        # itself. Without a second engine that verified, the result is BLOCKED.
        verified = self._verified_results(successful)
        if len({r.engine_name for r in verified}) == 1:
            return {
                "answer": next((r.result for r in verified if r.engine_name not in self.CLAIM_ENGINES), None),
                "confidence": 0.0,
                "status": NO_INDEPENDENT_VERIFICATION,
                "diagnostic_status": DiagnosticStatus.BLOCKED,
            }

        # A claim engine's verdict (VALID) is not an answer to agree on (#659).
        voters = [r for r in successful if r.engine_name not in self.CLAIM_ENGINES]
        if not voters:
            return {"answer": None, "confidence": 0.0, "status": "no_answer", "diagnostic_status": DiagnosticStatus.UNVERIFIABLE}

        # Weight answers by engine reliability
        weighted_answers: Dict[str, float] = {}
        answer_values: Dict[str, Any] = {}
        for r in voters:
            answer_key = self._consensus_answer_key(r.result)
            weight = self.ENGINE_WEIGHTS.get(r.engine_name, 0.5) * r.confidence
            weighted_answers[answer_key] = weighted_answers.get(answer_key, 0) + weight
            answer_values.setdefault(answer_key, r.result)

        best_answer = max(weighted_answers, key=weighted_answers.get)
        total_weight = sum(weighted_answers.values())
        best_weight = weighted_answers[best_answer]

        if len(weighted_answers) == 1:
            status = "unanimous"
            confidence = min(0.999, best_weight / len(voters))
        elif total_weight <= 0:
            # Engines that disagree, with no weight between them (each gave
            # its answer confidence 0): a split, not a division by zero.
            status = "split"
            confidence = 0.0
        elif best_weight > total_weight / 2:
            status = "majority"
            confidence = min(0.95, best_weight / total_weight)
        else:
            status = "split"
            confidence = min(0.7, best_weight / total_weight)

        # Advisory only (#633): every engine decided a model's translation of
        # the question, so engines that agree, however many, have not
        # verified a claim. The result is UNVERIFIABLE, never VERIFIED.
        return {
            "answer": answer_values[best_answer],
            "confidence": confidence,
            "status": status,
            "diagnostic_status": DiagnosticStatus.UNVERIFIABLE,
        }

    @staticmethod
    def _shared_cause(blocked: list[EngineResult]) -> tuple[str | None, str | None]:
        """The named cause every blocked engine stopped for, with its
        message (#519). Engines that each stopped for a translation cause
        translated nothing between them: the cause is no provider where one
        of them had none (the setting to fix), else a failed translation.
        Otherwise the engines must share one cause; if they do not, it is
        ``(None, None)``, and the consensus is BLOCKED with no cause, as
        before."""
        causes = {r.cause for r in blocked}
        if causes and causes <= TRANSLATION_CAUSES:
            cause = NO_PROVIDER if NO_PROVIDER in causes else TRANSLATION_FAILED
        elif len(causes) == 1 and None not in causes:
            (cause,) = causes
        else:
            return None, None
        return cause, next((r.cause_message for r in blocked if r.cause == cause and r.cause_message), None)

    @staticmethod
    def _verified_results(results: List[EngineResult]) -> List[EngineResult]:
        """The results whose engine verified its answer."""
        return [r for r in results if r.status == "VERIFIED"]

    @staticmethod
    def _consensus_answer_key(result: Any) -> str:
        """Normalize consensus answer keys without collapsing null to the string 'None'."""
        if result is None:
            return _NONE_CONSENSUS_KEY
        return str(result)
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _parse_math_query(
        self, query: str, translations: Optional[List[Translation]] = None
    ) -> Tuple[str, Decimal]:
        """Parse query into expression and expected value.
        
        Raises ValueError on translation failure — no fabricated fallback.
        claimed_answer is guaranteed non-null by the Pydantic schema.
        The translation is added to ``translations``, where given (#578).
        """
        try:
            from qwed_new.core.translator import TranslationLayer
            translator = TranslationLayer()
            task = translator.translate(query)
        except Exception as exc:
            _keep_refused(exc, translations, "SymPy")
            raise ValueError(f"Query translation failed: {exc}") from exc

        if translations is not None:
            translations.append(translation_of(translator, "math", task, engine="SymPy"))
        return task.expression, Decimal(str(task.claimed_answer))
    
    def _generate_verification_code(
        self, query: str, translations: Optional[List[Translation]] = None
    ) -> str:
        """Generate Python code for verification. The translation is added
        to ``translations``, where given (#578)."""
        try:
            # One read: a first use on two threads at once can build two
            # instances, and the model is named from the one that translated.
            # Inside the try, so a translator that cannot load still fails
            # as a code generation failure.
            translator = self.translator
            task = translator.translate(query)
            if translations is not None:
                translations.append(translation_of(translator, "math", task, engine="Python"))
            return f"result = {task.expression}"
        except Exception as e:
            _keep_refused(e, translations, "Python")
            raise ValueError(f"Verification code generation failed: {e}") from e
    
    # =========================================================================
    # Health Monitoring
    # =========================================================================
    
    def get_engine_health(self) -> Dict[str, Any]:
        """
        Get health status of all engines.

        Returns:
            Dict of engine health metrics.

        Example:
            >>> health = verifier.get_engine_health()
        """
        if self.circuit_breaker:
            return self.circuit_breaker.get_all_health()
        return {}
    
    def reset_circuit_breakers(self):
        """
        Reset all circuit breakers.

        Example:
            >>> verifier.reset_circuit_breakers()
        """
        if self.circuit_breaker:
            self.circuit_breaker.reset()

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="ConsensusVerifier",
        )



# Global singleton
consensus_verifier = ConsensusVerifier()


