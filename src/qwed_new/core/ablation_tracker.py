"""
Ablation Tracker for QWED Verification Engines.

Tracks per-engine verification statistics to answer the question:
"Which engine caught which errors?"

This module collects real-time statistics from all 11 verification engines
and provides detailed breakdowns for transparency and ablation studies.

Usage:
    tracker = AblationTracker()
    
    # Engines report their results
    tracker.record("math", result)
    tracker.record("logic", result)
    
    # Get stats
    stats = tracker.get_stats()
    markdown = tracker.export_markdown()
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
import json
import threading


class EngineType(Enum):
    """The 11 verification engines in QWED."""
    MATH = "math"
    LOGIC = "logic"
    CODE = "code"
    SQL = "sql"
    STATS = "stats"
    FACT = "fact"
    IMAGE = "image"
    CONSENSUS = "consensus"


class VerificationStatus(Enum):
    """Possible outcomes of a verification."""
    VERIFIED = "verified"           # Output was correct
    REJECTED = "rejected"           # Output was incorrect (error caught)
    ERROR = "error"                 # Engine failed to process
    TIMEOUT = "timeout"             # Engine timed out
    UNSUPPORTED = "unsupported"     # Domain not supported


@dataclass
class VerificationRecord:
    """Record of a single verification attempt."""
    engine: str
    timestamp: datetime
    status: VerificationStatus
    is_correct: bool
    latency_ms: float
    error_type: Optional[str] = None
    details: Optional[Dict] = None


@dataclass
class EngineStats:
    """Aggregated statistics for a single engine."""
    engine: str
    total_verifications: int = 0
    verified_count: int = 0       # Correct outputs
    rejected_count: int = 0       # Errors caught
    error_count: int = 0          # Engine failures
    timeout_count: int = 0
    unsupported_count: int = 0
    total_latency_ms: float = 0.0
    
    @property
    def detection_rate(self) -> float:
        """Percentage of incorrect outputs caught."""
        total_checked = self.verified_count + self.rejected_count
        if total_checked == 0:
            return 0.0
        return (self.rejected_count / total_checked) * 100
    
    @property
    def accuracy(self) -> float:
        """Percentage of LLM outputs that were correct."""
        total_checked = self.verified_count + self.rejected_count
        if total_checked == 0:
            return 0.0
        return (self.verified_count / total_checked) * 100
    
    @property
    def avg_latency_ms(self) -> float:
        """Average latency per verification."""
        if self.total_verifications == 0:
            return 0.0
        return self.total_latency_ms / self.total_verifications


class AblationTracker:
    """
    Thread-safe tracker for per-engine verification statistics.
    
    Collects real-time data from all verification engines to provide:
    - Per-engine error detection rates
    - Latency breakdowns
    - Detailed verification logs (optional)
    """
    
    def __init__(self, keep_history: bool = True, max_history: int = 10000):
        """
        Initialize the ablation tracker.
        
        Args:
            keep_history: If True, store individual verification records
            max_history: Maximum number of records to keep in memory
        """
        self._lock = threading.Lock()
        self._stats: Dict[str, EngineStats] = {}
        self._history: List[VerificationRecord] = []
        self._keep_history = keep_history
        self._max_history = max_history
        self._start_time = datetime.now()
        
        # Initialize stats for all engines
        for engine in EngineType:
            self._stats[engine.value] = EngineStats(engine=engine.value)
    
    def record(
        self,
        engine: str,
        result: Dict[str, Any],
        latency_ms: float = 0.0
    ) -> None:
        """
        Record a verification result from an engine.
        
        Args:
            engine: Engine name (e.g., "math", "logic", "code")
            result: The verification result dict from the engine
            latency_ms: Time taken for verification
        """
        with self._lock:
            # Normalize engine name
            engine = engine.lower()
            
            # Ensure engine exists in stats
            if engine not in self._stats:
                self._stats[engine] = EngineStats(engine=engine)
            
            stats = self._stats[engine]
            stats.total_verifications += 1
            stats.total_latency_ms += latency_ms
            
            # Determine status from result
            is_correct = result.get("is_correct", result.get("is_valid", False))
            status_str = result.get("status", "").upper()
            error = result.get("error")
            
            if error:
                status = VerificationStatus.ERROR
                stats.error_count += 1
            elif "TIMEOUT" in status_str:
                status = VerificationStatus.TIMEOUT
                stats.timeout_count += 1
            elif "UNSUPPORTED" in status_str:
                status = VerificationStatus.UNSUPPORTED
                stats.unsupported_count += 1
            elif is_correct:
                status = VerificationStatus.VERIFIED
                stats.verified_count += 1
            else:
                status = VerificationStatus.REJECTED
                stats.rejected_count += 1
            
            # Store record if keeping history
            if self._keep_history:
                record = VerificationRecord(
                    engine=engine,
                    timestamp=datetime.now(),
                    status=status,
                    is_correct=is_correct,
                    latency_ms=latency_ms,
                    error_type=error,
                    details=result if status == VerificationStatus.REJECTED else None
                )
                self._history.append(record)
                
                # Trim history if needed
                if len(self._history) > self._max_history:
                    self._history = self._history[-self._max_history:]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics for all engines.
        
        Returns:
            Dict with per-engine stats and summary
        """
        with self._lock:
            engine_stats = {}
            total_verified = 0
            total_rejected = 0
            total_errors = 0
            
            for name, stats in self._stats.items():
                engine_stats[name] = {
                    "total": stats.total_verifications,
                    "verified": stats.verified_count,
                    "rejected": stats.rejected_count,
                    "errors": stats.error_count,
                    "timeouts": stats.timeout_count,
                    "unsupported": stats.unsupported_count,
                    "detection_rate": round(stats.detection_rate, 2),
                    "llm_accuracy": round(stats.accuracy, 2),
                    "avg_latency_ms": round(stats.avg_latency_ms, 2)
                }
                total_verified += stats.verified_count
                total_rejected += stats.rejected_count
                total_errors += stats.error_count
            
            total = total_verified + total_rejected
            overall_detection = (total_rejected / total * 100) if total > 0 else 0
            overall_accuracy = (total_verified / total * 100) if total > 0 else 0
            
            return {
                "engines": engine_stats,
                "summary": {
                    "total_verifications": sum(s.total_verifications for s in self._stats.values()),
                    "total_errors_caught": total_rejected,
                    "total_verified_correct": total_verified,
                    "total_engine_errors": total_errors,
                    "overall_detection_rate": round(overall_detection, 2),
                    "overall_llm_accuracy": round(overall_accuracy, 2),
                    "tracking_since": self._start_time.isoformat(),
                    "history_size": len(self._history) if self._keep_history else 0
                }
            }
    
    def get_errors_caught(self) -> List[Dict]:
        """
        Get list of all errors caught (rejected outputs).
        
        Returns:
            List of verification records where LLM output was rejected
        """
        with self._lock:
            return [
                {
                    "engine": r.engine,
                    "timestamp": r.timestamp.isoformat(),
                    "error_details": r.details
                }
                for r in self._history
                if r.status == VerificationStatus.REJECTED
            ]
    
    def get_engine_breakdown(self, engine: str) -> Dict[str, Any]:
        """
        Get detailed breakdown for a specific engine.
        
        Args:
            engine: Engine name
            
        Returns:
            Detailed stats for that engine
        """
        with self._lock:
            engine = engine.lower()
            if engine not in self._stats:
                return {"error": f"Unknown engine: {engine}"}
            
            stats = self._stats[engine]
            history = [r for r in self._history if r.engine == engine]
            
            return {
                "engine": engine,
                "stats": {
                    "total": stats.total_verifications,
                    "verified": stats.verified_count,
                    "rejected": stats.rejected_count,
                    "errors": stats.error_count,
                    "detection_rate": f"{stats.detection_rate:.1f}%",
                    "llm_accuracy": f"{stats.accuracy:.1f}%",
                    "avg_latency_ms": round(stats.avg_latency_ms, 2)
                },
                "recent_rejections": [
                    {"timestamp": r.timestamp.isoformat(), "details": r.details}
                    for r in history[-10:]
                    if r.status == VerificationStatus.REJECTED
                ]
            }
    
    def export_json(self) -> str:
        """Export stats as JSON string."""
        return json.dumps(self.get_stats(), indent=2, default=str)
    
    def export_markdown(self) -> str:
        """
        Export stats as markdown table for documentation.
        
        Returns:
            Markdown formatted string
        """
        stats = self.get_stats()
        
        lines = [
            "# QWED Per-Engine Ablation Statistics",
            "",
            f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Verifications | {stats['summary']['total_verifications']} |",
            f"| Errors Caught | {stats['summary']['total_errors_caught']} |",
            f"| Verified Correct | {stats['summary']['total_verified_correct']} |",
            f"| Overall Detection Rate | {stats['summary']['overall_detection_rate']}% |",
            f"| Overall LLM Accuracy | {stats['summary']['overall_llm_accuracy']}% |",
            "",
            "## Per-Engine Breakdown",
            "",
            "| Engine | Total | Verified | Rejected | Errors | Detection Rate | LLM Accuracy | Avg Latency |",
            "|--------|-------|----------|----------|--------|----------------|--------------|-------------|",
        ]
        
        for name, engine in stats['engines'].items():
            if engine['total'] > 0:
                lines.append(
                    f"| {name.capitalize()} | {engine['total']} | {engine['verified']} | "
                    f"{engine['rejected']} | {engine['errors']} | {engine['detection_rate']}% | "
                    f"{engine['llm_accuracy']}% | {engine['avg_latency_ms']}ms |"
                )
        
        lines.extend([
            "",
            "## Notes",
            "",
            "- **Verified**: LLM output was correct",
            "- **Rejected**: LLM output was incorrect (error caught by QWED)",
            "- **Errors**: Engine failed to process (syntax error, timeout, etc.)",
            "- **Detection Rate**: % of incorrect outputs caught",
            "- **LLM Accuracy**: % of LLM outputs that were correct",
        ])
        
        return "\n".join(lines)
    
    def reset(self) -> None:
        """Reset all statistics."""
        with self._lock:
            for stats in self._stats.values():
                stats.total_verifications = 0
                stats.verified_count = 0
                stats.rejected_count = 0
                stats.error_count = 0
                stats.timeout_count = 0
                stats.unsupported_count = 0
                stats.total_latency_ms = 0.0
            self._history.clear()
            self._start_time = datetime.now()


# Global tracker instance
_global_tracker: Optional[AblationTracker] = None


def get_tracker() -> AblationTracker:
    """
    Get the global ablation tracker instance.
    
    Returns:
        The singleton AblationTracker
    """
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = AblationTracker()
    return _global_tracker


def record_verification(engine: str, result: Dict[str, Any], latency_ms: float = 0.0) -> None:
    """
    Convenience function to record a verification to the global tracker.
    
    Args:
        engine: Engine name
        result: Verification result dict
        latency_ms: Time taken
    """
    get_tracker().record(engine, result, latency_ms)
