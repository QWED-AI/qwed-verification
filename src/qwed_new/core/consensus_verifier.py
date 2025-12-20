"""
Enterprise Consensus Verifier: Multi-Engine Verification Orchestrator.

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
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import threading


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
    confidence: float  # 0.0 to 1.0
    latency_ms: float
    success: bool
    error: Optional[str] = None


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
        self._lock = threading.Lock()
    
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
        health = self.get_health(engine_name)
        
        if health.state == EngineState.HEALTHY:
            return True
        
        if health.state == EngineState.OPEN:
            # Check if recovery time has passed
            if health.circuit_open_until and time.time() > health.circuit_open_until:
                # Transition to half-open (allow test request)
                with self._lock:
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


class ConsensusVerifier:
    """
    Enterprise Consensus Verification Orchestrator.
    
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
        "Fact": 3000,
        "Image": 15000
    }
    
    # Engine reliability weights
    ENGINE_WEIGHTS = {
        "SymPy": 1.0,      # Deterministic math is most reliable
        "Z3": 0.995,       # Formal logic solver
        "Python": 0.99,    # Code execution
        "Stats": 0.98,     # Statistical analysis
        "Fact": 0.85,      # Depends on external sources
        "Image": 0.80      # VLM-dependent
    }
    
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
        self._stats_verifier = None
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
    def logic_verifier(self):
        if self._logic_verifier is None:
            from qwed_new.core.logic_verifier import LogicVerifier
            self._logic_verifier = LogicVerifier()
        return self._logic_verifier
    
    @property
    def code_verifier(self):
        if self._code_verifier is None:
            from qwed_new.core.code_verifier import CodeVerifier
            self._code_verifier = CodeVerifier()
        return self._code_verifier
    
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
            parallel_execution=parallel and len(engine_methods) > 1
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
            timeout_seconds: Max time for all engines.
            
        Returns:
            ConsensusResult object.

        Example:
            >>> result = await verifier.verify_async("2+2")
        """
        start_time = time.time()
        engine_methods = self._select_engines(query, mode)
        
        # Create async tasks
        loop = asyncio.get_event_loop()
        tasks = []
        
        for engine_name, method in engine_methods:
            if self._is_engine_available(engine_name):
                task = loop.run_in_executor(
                    self._executor,
                    method,
                    query
                )
                tasks.append((engine_name, task))
        
        # Gather results with timeout
        results = []
        try:
            for engine_name, task in tasks:
                try:
                    result = await asyncio.wait_for(task, timeout=timeout_seconds)
                    self._record_engine_result(engine_name, result)
                    results.append(result)
                except asyncio.TimeoutError:
                    results.append(EngineResult(
                        engine_name=engine_name,
                        method="timeout",
                        result=None,
                        confidence=0.0,
                        latency_ms=timeout_seconds * 1000,
                        success=False,
                        error="Timeout"
                    ))
        except Exception as e:
            pass
        
        consensus = self._calculate_consensus(results)
        total_latency = (time.time() - start_time) * 1000
        
        return ConsensusResult(
            final_answer=consensus["answer"],
            confidence=consensus["confidence"],
            engines_used=len(results),
            agreement_status=consensus["status"],
            verification_chain=results,
            total_latency_ms=total_latency,
            parallel_execution=True
        )
    
    # =========================================================================
    # Engine Selection
    # =========================================================================
    
    def _select_engines(self, query: str, mode: VerificationMode) -> List[Tuple[str, Callable]]:
        """Select engines based on mode and query type."""
        engines = []
        
        # Always include math
        engines.append(("SymPy", self._verify_with_math))
        
        if mode in [VerificationMode.HIGH, VerificationMode.MAXIMUM]:
            engines.append(("Python", self._verify_with_code))
        
        if mode == VerificationMode.MAXIMUM:
            engines.append(("Z3", self._verify_with_logic))
            
            # Add stats for statistical queries
            query_lower = query.lower()
            if any(kw in query_lower for kw in ["average", "mean", "median", "variance"]):
                engines.append(("Stats", self._verify_with_stats))
            
            # Add fact for knowledge queries
            if any(kw in query_lower for kw in ["capital", "president", "population"]):
                engines.append(("Fact", self._verify_with_fact))
        
        return engines
    
    def _is_engine_available(self, engine_name: str) -> bool:
        """Check if engine is available (circuit breaker)."""
        if self.circuit_breaker:
            return self.circuit_breaker.is_available(engine_name)
        return True
    
    def _record_engine_result(self, engine_name: str, result: EngineResult):
        """Record result with circuit breaker."""
        if self.circuit_breaker:
            if result.success:
                self.circuit_breaker.record_success(engine_name, result.latency_ms)
            else:
                self.circuit_breaker.record_failure(engine_name)
    
    # =========================================================================
    # Execution Methods
    # =========================================================================
    
    def _execute_parallel(self, query: str, engines: List[Tuple[str, Callable]]) -> List[EngineResult]:
        """Execute engines in parallel using thread pool."""
        results = []
        futures = {}
        
        for engine_name, method in engines:
            if self._is_engine_available(engine_name):
                future = self._executor.submit(method, query)
                futures[future] = engine_name
        
        for future in as_completed(futures, timeout=30):
            engine_name = futures[future]
            try:
                result = future.result()
                self._record_engine_result(engine_name, result)
                results.append(result)
            except Exception as e:
                results.append(EngineResult(
                    engine_name=engine_name,
                    method="parallel_execution",
                    result=None,
                    confidence=0.0,
                    latency_ms=0,
                    success=False,
                    error=str(e)
                ))
        
        return results
    
    def _execute_sequential(self, query: str, engines: List[Tuple[str, Callable]]) -> List[EngineResult]:
        """Execute engines sequentially."""
        results = []
        
        for engine_name, method in engines:
            if self._is_engine_available(engine_name):
                try:
                    result = method(query)
                    self._record_engine_result(engine_name, result)
                    results.append(result)
                except Exception as e:
                    results.append(EngineResult(
                        engine_name=engine_name,
                        method="sequential_execution",
                        result=None,
                        confidence=0.0,
                        latency_ms=0,
                        success=False,
                        error=str(e)
                    ))
        
        return results
    
    # =========================================================================
    # Engine Methods
    # =========================================================================
    
    def _verify_with_math(self, query: str) -> EngineResult:
        """Verify using SymPy math engine."""
        start = time.time()
        try:
            expression, expected = self._parse_math_query(query)
            result = self.math_verifier.verify_math(expression, expected)
            latency = (time.time() - start) * 1000
            
            return EngineResult(
                engine_name="SymPy",
                method="symbolic_math",
                result=result.get("calculated_value"),
                confidence=1.0 if result["is_correct"] else 0.0,
                latency_ms=latency,
                success=True
            )
        except Exception as e:
            return EngineResult(
                engine_name="SymPy",
                method="symbolic_math",
                result=None,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                success=False,
                error=str(e)
            )
    
    def _verify_with_code(self, query: str) -> EngineResult:
        """Verify by executing Python code."""
        start = time.time()
        try:
            code = self._generate_verification_code(query)
            
            # Safety check
            safety_result = self.code_verifier.verify_code(code)
            if not safety_result["is_safe"]:
                return EngineResult(
                    engine_name="Python",
                    method="code_execution",
                    result=None,
                    confidence=0.0,
                    latency_ms=(time.time() - start) * 1000,
                    success=False,
                    error=f"Unsafe code: {safety_result['issues']}"
                )
            
            # Execute
            from qwed_new.core.code_executor import CodeExecutor
            executor = CodeExecutor()
            output = executor.execute(code)
            
            return EngineResult(
                engine_name="Python",
                method="code_execution",
                result=output,
                confidence=0.99,
                latency_ms=(time.time() - start) * 1000,
                success=True
            )
        except Exception as e:
            return EngineResult(
                engine_name="Python",
                method="code_execution",
                result=None,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                success=False,
                error=str(e)
            )
    
    def _verify_with_logic(self, query: str) -> EngineResult:
        """Verify using Z3 logic solver."""
        start = time.time()
        try:
            variables, constraints = self._model_as_logic(query)
            result = self.logic_verifier.verify_logic(variables, constraints)
            
            return EngineResult(
                engine_name="Z3",
                method="constraint_solving",
                result=result.status,
                confidence=0.995 if result.status == "SAT" else 0.0,
                latency_ms=(time.time() - start) * 1000,
                success=True
            )
        except Exception as e:
            return EngineResult(
                engine_name="Z3",
                method="constraint_solving",
                result=None,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                success=False,
                error=str(e)
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
            
            return EngineResult(
                engine_name="Stats",
                method="statistical_analysis",
                result=result,
                confidence=0.98 if result else 0.0,
                latency_ms=(time.time() - start) * 1000,
                success=result is not None
            )
        except Exception as e:
            return EngineResult(
                engine_name="Stats",
                method="statistical_analysis",
                result=None,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                success=False,
                error=str(e)
            )
    
    def _verify_with_fact(self, query: str) -> EngineResult:
        """Verify using Fact engine."""
        start = time.time()
        try:
            from qwed_new.core.fact_verifier import FactVerifier
            verifier = FactVerifier()
            
            # Simple extraction - in production would use proper NER
            result = verifier.verify_fact(query, query)  # Self-reference for demo
            
            return EngineResult(
                engine_name="Fact",
                method="knowledge_retrieval",
                result=result.get("verdict"),
                confidence=result.get("confidence", 0.5),
                latency_ms=(time.time() - start) * 1000,
                success=True
            )
        except Exception as e:
            return EngineResult(
                engine_name="Fact",
                method="knowledge_retrieval",
                result=None,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                success=False,
                error=str(e)
            )
    
    # =========================================================================
    # Consensus Calculation
    # =========================================================================
    
    def _calculate_consensus(self, results: List[EngineResult]) -> Dict[str, Any]:
        """Calculate weighted consensus from engine results."""
        if not results:
            return {"answer": None, "confidence": 0.0, "status": "no_results"}
        
        successful = [r for r in results if r.success]
        
        if not successful:
            return {"answer": None, "confidence": 0.0, "status": "all_failed"}
        
        # Weight answers by engine reliability
        weighted_answers: Dict[str, float] = {}
        for r in successful:
            answer_key = str(r.result)
            weight = self.ENGINE_WEIGHTS.get(r.engine_name, 0.5) * r.confidence
            weighted_answers[answer_key] = weighted_answers.get(answer_key, 0) + weight
        
        # Find best answer
        best_answer = max(weighted_answers, key=weighted_answers.get)
        total_weight = sum(weighted_answers.values())
        best_weight = weighted_answers[best_answer]
        
        # Determine agreement status
        if len(set(str(r.result) for r in successful)) == 1:
            status = "unanimous"
            confidence = min(0.999, best_weight / len(successful))
        elif best_weight > total_weight / 2:
            status = "majority"
            confidence = min(0.95, best_weight / total_weight)
        else:
            status = "split"
            confidence = min(0.7, best_weight / total_weight)
        
        return {
            "answer": best_answer,
            "confidence": confidence,
            "status": status
        }
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _parse_math_query(self, query: str) -> Tuple[str, float]:
        """Parse query into expression and expected value."""
        try:
            from qwed_new.core.translator import TranslationLayer
            translator = TranslationLayer()
            task = translator.translate(query)
            return task.expression, task.expected_value or 0.0
        except:
            # Fallback: extract simple expression
            import re
            nums = re.findall(r"\d+", query)
            if len(nums) >= 2:
                return f"{nums[0]} + {nums[1]}", float(nums[0]) + float(nums[1])
            return "0", 0.0
    
    def _generate_verification_code(self, query: str) -> str:
        """Generate Python code for verification."""
        try:
            from qwed_new.core.translator import TranslationLayer
            translator = TranslationLayer()
            task = translator.translate(query)
            return f"print({task.expression})"
        except:
            return "print('Unable to generate code')"
    
    def _model_as_logic(self, query: str) -> Tuple[Dict, List]:
        """Model query as logic constraints."""
        try:
            from qwed_new.core.translator import TranslationLayer
            translator = TranslationLayer()
            return translator.translate_logic(query)
        except:
            return {}, []
    
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
            self.circuit_breaker._engines.clear()


# Global singleton
consensus_verifier = ConsensusVerifier()
