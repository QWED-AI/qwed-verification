"""
Observability Layer: System Monitoring & Metrics.

This module provides the "System Logging" layer of the QWED OS,
similar to how operating systems track resource usage and performance.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

@dataclass
class TenantMetrics:
    """Metrics for a single tenant (organization)."""
    organization_id: int
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    blocked_requests: int = 0
    total_latency_ms: float = 0.0
    provider_usage: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_request_time: Optional[datetime] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def avg_latency_ms(self) -> float:
        """Calculate average latency."""
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests

@dataclass
class GlobalMetrics:
    """System-wide metrics."""
    total_requests: int = 0
    active_organizations: int = 0
    uptime_seconds: float = 0.0
    start_time: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def requests_per_second(self) -> float:
        """Calculate RPS."""
        if self.uptime_seconds == 0:
            return 0.0
        return self.total_requests / self.uptime_seconds

class MetricsCollector:
    """
    In-memory metrics aggregator.
    Tracks per-tenant and global performance metrics.
    """
    
    def __init__(self):
        self.tenant_metrics: Dict[int, TenantMetrics] = {}
        self.global_metrics = GlobalMetrics()
        self.start_time = time.time()
    
    def track_request(
        self,
        organization_id: int,
        status: str,
        latency_ms: float,
        provider: Optional[str] = None
    ):
        """
        Track a single request.
        
        Args:
            organization_id: Tenant ID
            status: "VERIFIED", "CORRECTED", "BLOCKED", "ERROR", etc.
            latency_ms: Request latency in milliseconds
            provider: LLM provider used (e.g., "azure_openai")
        """
        # Initialize tenant metrics if first request
        if organization_id not in self.tenant_metrics:
            self.tenant_metrics[organization_id] = TenantMetrics(organization_id=organization_id)
        
        metrics = self.tenant_metrics[organization_id]
        
        # Update counters
        metrics.total_requests += 1
        metrics.total_latency_ms += latency_ms
        metrics.last_request_time = datetime.utcnow()
        
        if status == "BLOCKED":
            metrics.blocked_requests += 1
        elif status in ["ERROR", "FAILED"]:
            metrics.failed_requests += 1
        else:
            metrics.successful_requests += 1
        
        if provider:
            metrics.provider_usage[provider] += 1
        
        # Update global metrics
        self.global_metrics.total_requests += 1
        self.global_metrics.active_organizations = len(self.tenant_metrics)
        self.global_metrics.uptime_seconds = time.time() - self.start_time
    
    def get_tenant_metrics(self, organization_id: int) -> Optional[Dict]:
        """Get metrics for a specific tenant."""
        if organization_id not in self.tenant_metrics:
            return None
        
        metrics = self.tenant_metrics[organization_id]
        return {
            "organization_id": metrics.organization_id,
            "total_requests": metrics.total_requests,
            "successful_requests": metrics.successful_requests,
            "failed_requests": metrics.failed_requests,
            "blocked_requests": metrics.blocked_requests,
            "success_rate": round(metrics.success_rate, 2),
            "avg_latency_ms": round(metrics.avg_latency_ms, 2),
            "provider_usage": dict(metrics.provider_usage),
            "last_request_time": metrics.last_request_time.isoformat() if metrics.last_request_time else None
        }
    
    def get_global_metrics(self) -> Dict:
        """Get system-wide metrics."""
        return {
            "total_requests": self.global_metrics.total_requests,
            "active_organizations": self.global_metrics.active_organizations,
            "uptime_seconds": round(self.global_metrics.uptime_seconds, 2),
            "requests_per_second": round(self.global_metrics.requests_per_second, 2),
            "start_time": self.global_metrics.start_time.isoformat()
        }
    
    def get_all_tenant_metrics(self) -> List[Dict]:
        """Get metrics for all tenants."""
        return [
            self.get_tenant_metrics(org_id)
            for org_id in self.tenant_metrics.keys()
        ]

# Global singleton instance
metrics_collector = MetricsCollector()
