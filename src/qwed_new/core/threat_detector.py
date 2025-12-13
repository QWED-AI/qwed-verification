"""
Real-Time Threat Detection for QWED.
Monitors security events, detects anomalies, and generates threat scores.

Features:
- Frequency-based anomaly detection
- Pattern-based threat scoring
- Failed attempt tracking
- IP-based rate limiting
- Real-time alerting
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from sqlmodel import Session, select

from qwed_new.core.models import SecurityEvent, Organization
from qwed_new.core.database import engine

logger = logging.getLogger(__name__)


class ThreatDetector:
    """
    Real-time threat detection and scoring.
    """
    
    def __init__(self):
        # In-memory tracking (should use Redis in production)
        self.request_counts = defaultdict(int)  # org_id -> count
        self.failed_attempts = defaultdict(list)  # org_id -> [timestamps]
        self.ip_blacklist = set()
        
        # Thresholds
        self.anomaly_threshold = 100  # requests per minute
        self.failed_attempt_limit = 10  # consecutive failures
        self.threat_score_threshold = 75  # out of 100
    
    def analyze_security_event(
        self,
        organization_id: int,
        event_type: str,
        reason: str,
        query: str,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze a security event and generate threat score.
        
        Returns:
            {
                "threat_score": int (0-100),
                "is_anomaly": bool,
                "should_alert": bool,
                "details": dict
            }
        """
        threat_score = 0
        details = {}
        
        # 1. Event type severity
        severity_scores = {
            "BLOCKED": 30,
            "INJECTION_DETECTED": 50,
            "SANITIZED": 10,
            "RATE_LIMIT_EXCEEDED": 20
        }
        threat_score += severity_scores.get(event_type, 0)
        
        # 2. Frequency analysis
        recent_failures = self._get_recent_failures(organization_id)
        if len(recent_failures) > self.failed_attempt_limit:
            threat_score += 30
            details["consecutive_failures"] = len(recent_failures)
        
        # 3. Pattern-based scoring
        dangerous_patterns = [
            "base64", "encoding", "system prompt", "jailbreak",
            "override", "bypass", "injection"
        ]
        pattern_matches = sum(1 for p in dangerous_patterns if p in reason.lower())
        threat_score += min(pattern_matches * 5, 20)
        
        if pattern_matches > 0:
            details["dangerous_patterns_found"] = pattern_matches
        
        # 4. IP-based scoring
        if ip_address and ip_address in self.ip_blacklist:
            threat_score += 20
            details["blacklisted_ip"] = True
        
        # 5. Query length/complexity
        if len(query) > 1500:
            threat_score += 10
            details["long_query"] = True
        
        # Determine if anomaly
        is_anomaly = (
            len(recent_failures) > self.anomaly_threshold or
            threat_score >= self.threat_score_threshold
        )
        
        # Track failure
        if event_type == "BLOCKED":
            self.failed_attempts[organization_id].append(datetime.utcnow())
        
        return {
            "threat_score": min(threat_score, 100),
            "is_anomaly": is_anomaly,
            "should_alert": threat_score >= self.threat_score_threshold,
            "details": details,
            "organization_id": organization_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _get_recent_failures(self, organization_id: int, minutes: int = 10) -> List[datetime]:
        """Get failed attempts in the last N minutes."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        failures = self.failed_attempts[organization_id]
        # Filter to recent only
        recent = [f for f in failures if f > cutoff]
        self.failed_attempts[organization_id] = recent  # Clean up old entries
        return recent
    
    def get_threat_summary(
        self,
        organization_id: int,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get threat summary for an organization.
        
        Returns aggregated threat metrics.
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        with Session(engine) as session:
            events = session.exec(
                select(SecurityEvent).where(
                    SecurityEvent.organization_id == organization_id,
                    SecurityEvent.timestamp >= cutoff
                )
            ).all()
            
            blocked_count = len([e for e in events if e.event_type == "BLOCKED"])
            high_severity = len([e for e in events if e.severity == "high" or e.severity == "critical"])
            
            # Calculate threat level
            if high_severity > 10 or blocked_count > 50:
                threat_level = "CRITICAL"
            elif high_severity > 5 or blocked_count > 20:
                threat_level = "HIGH"
            elif high_severity > 0 or blocked_count > 5:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            # Get security layer breakdown
            layer_counts = defaultdict(int)
            for event in events:
                if event.security_layer:
                    layer_counts[event.security_layer] += 1
            
            return {
                "organization_id": organization_id,
                "period_hours": hours,
                "threat_level": threat_level,
                "metrics": {
                    "total_events": len(events),
                    "blocked_attempts": blocked_count,
                    "high_severity_events": high_severity,
                    "recent_failures_10min": len(self._get_recent_failures(organization_id))
                },
                "security_layer_breakdown": dict(layer_counts),
                "generated_at": datetime.utcnow().isoformat()
            }
    
    def blacklist_ip(self, ip_address: str):
        """Add IP to blacklist."""
        self.ip_blacklist.add(ip_address)
        logger.warning(f"IP {ip_address} added to blacklist")
    
    def is_ip_blacklisted(self, ip_address: str) -> bool:
        """Check if IP is blacklisted."""
        return ip_address in self.ip_blacklist


# Global threat detector instance
threat_detector = ThreatDetector()
