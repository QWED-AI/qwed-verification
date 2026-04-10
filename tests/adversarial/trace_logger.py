"""
QWED Adversarial Trace Logger — Full Forensic Audit Trail.

Logs every LLM interaction with:
  - Exact input prompts (system + user)
  - Exact raw LLM outputs
  - Chain-of-thought reasoning traces
  - QWED engine verdicts
  - SHA-256 hashes for tamper detection
  - Timestamps for reproducibility

Output: JSONL files (one JSON object per line) for streaming + analysis.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import threading


@dataclass
class TestTrace:
    """Complete forensic trace of a single test interaction."""

    # Identification
    test_id: str
    test_suite: str
    model: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Inputs
    system_prompt: str = ""
    input_prompt: str = ""
    input_prompt_variant: str = ""  # e.g., hinted version, audited version

    # Raw Outputs
    output_raw: str = ""
    output_raw_variant: str = ""

    # Extracted
    answer_extracted: Optional[float] = None
    answer_extracted_variant: Optional[float] = None
    correct_answer: Optional[float] = None

    # QWED Verdicts
    qwed_engine: str = ""  # "sympy", "z3", "reasoning"
    qwed_verdict: str = ""  # "VERIFIED", "CORRECTION_NEEDED", "SAT", "UNSAT"
    qwed_verdict_variant: str = ""

    # Analysis
    test_result: str = ""  # "FAITHFUL", "UNFAITHFUL", "DETECTED", "NONE"
    findings: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)

    # Integrity
    input_hash: str = ""
    output_hash: str = ""

    def compute_hashes(self):
        """Compute SHA-256 hashes for tamper detection."""
        d = asdict(self)
        d.pop("input_hash", None)
        d.pop("output_hash", None)
        canonical = json.dumps(d, sort_keys=True, separators=(',', ':')).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        self.input_hash = digest
        self.output_hash = digest

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict, computing hashes first."""
        self.compute_hashes()
        return asdict(self)


class TraceLogger:
    """
    Forensic trace logger for QWED adversarial tests.

    Writes JSONL (one JSON per line) for streaming analysis.
    Each test run creates a timestamped log file.
    """

    def __init__(self, output_dir: str = "adversarial_traces"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_path = self.output_dir / f"trace_{timestamp}.jsonl"
        self.traces: List[TestTrace] = []
        self.model = os.getenv("CUSTOM_MODEL", "unknown")
        self._lock = threading.Lock()

    def log(self, trace: TestTrace):
        """Log a test trace to file and memory."""
        trace.model = self.model
        with self._lock:
            self.traces.append(trace)

            # Append to JSONL file
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(trace.to_dict(), default=str) + "\n")

    def get_summary(self) -> Dict[str, Any]:
        """Generate summary statistics from logged traces."""
        if not self.traces:
            return {"total": 0}

        from collections import Counter
        result_counts = Counter(t.test_result for t in self.traces)
        return {
            "total_tests": len(self.traces),
            "model": self.model,
            "log_file": str(self.log_path),
            "results": dict(sorted(result_counts.items())),
            "engines_used": sorted({t.qwed_engine for t in self.traces}),
        }

    def write_summary(self):
        """Write a human-readable summary file."""
        summary = self.get_summary()
        summary_path = self.log_path.with_suffix(".summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        return summary_path


# Global logger instance (created per test session)
_logger: Optional[TraceLogger] = None
_logger_lock = threading.Lock()

def get_logger() -> TraceLogger:
    """Get or create the global trace logger."""
    global _logger
    with _logger_lock:
        if _logger is None:
            _logger = TraceLogger()
    return _logger
