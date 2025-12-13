"""
Base Test Class for QWED Testing
All specific test classes inherit from this
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Structured test result"""
    test_id: str
    test_name: str
    engine: str
    priority: str  # CRITICAL, HIGH, MEDIUM
    passed: bool
    expected_result: str
    actual_result: Dict[Any, Any]
    error: Optional[str] = None
    latency_ms: float = 0.0
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "engine": self.engine,
            "priority": self.priority,
            "passed": self.passed,
            "expected_result": self.expected_result,
            "actual_result": self.actual_result,
            "error": self.error,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp
        }


class BaseTest:
    """
    Base class for all QWED tests
    Provides common functionality and structure
    """
    
    def __init__(self, test_id: str, test_name: str, engine: str, priority: str):
        self.test_id = test_id
        self.test_name = test_name
        self.engine = engine
        self.priority = priority
    
    def execute(self, api_client) -> TestResult:
        """
        Execute the test (to be overridden by subclasses)
        """
        raise NotImplementedError("Subclasses must implement execute()")
    
    def _check_result(self, expected: str, actual: Dict[Any, Any]) -> bool:
        """
        Check if actual result matches expected
        
        Expected formats:
        - "SAFE" - is_safe == True
        - "UNSAFE" - is_safe == False
        - "CRITICAL" - severity_summary.critical > 0
        - "WARNING" - severity_summary.warning > 0
        - "ERROR" - success == False
        - Custom conditions can be added
        """
        if not actual:
            return False
        
        if expected == "SAFE":
            return actual.get("is_safe") == True
        
        elif expected == "UNSAFE":
            return actual.get("is_safe") == False
        
        elif expected == "CRITICAL":
            severity = actual.get("severity_summary", {})
            return severity.get("critical", 0) > 0
        
        elif expected == "WARNING":
            severity = actual.get("severity_summary", {})
            return severity.get("warning", 0) > 0
        
        elif expected == "ERROR":
            return "error" in actual or not actual.get("success", True)
        
        elif expected == "REQUIRES_REVIEW":
            return actual.get("requires_manual_review") == True
        
        # Default: check if there are any issues
        elif expected == "HAS_ISSUES":
            return len(actual.get("issues", [])) > 0
        
        return False
    
    def log_info(self, message: str):
        """Log test information"""
        logger.info(f"[{self.test_id}] {message}")
    
    def log_error(self, message: str):
        """Log test error"""
        logger.error(f"[{self.test_id}] {message}")
