"""
Observability Layer: System Monitoring & Metrics.

This module provides the "System Logging" layer of the QWED OS,
with both in-memory metrics and Prometheus export for production monitoring.
"""

import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

# =============================================================================
# Prometheus Metrics (Real Production Metrics)
# =============================================================================

try:
    from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus-client not installed. Prometheus metrics disabled.")
    def generate_latest() -> bytes:
        return b""
    CONTENT_TYPE_LATEST = "text/plain"

# Prometheus metric definitions
if PROMETHEUS_AVAILABLE:
    # Counters
    VERIFICATION_TOTAL = Counter(
        'qwed_verification_total',
        'Total number of verification requests',
        ['engine', 'status', 'tenant_id']
    )
    
    LLM_CALLS_TOTAL = Counter(
        'qwed_llm_calls_total',
        'Total number of LLM API calls',
        ['provider', 'model', 'status']
    )
    
    CACHE_OPERATIONS = Counter(
        'qwed_cache_operations_total',
        'Cache operations',
        ['operation', 'result']  # operation: get/set, result: hit/miss
    )
    
    RATE_LIMIT_HITS = Counter(
        'qwed_rate_limit_hits_total',
        'Rate limit enforcement events',
        ['tenant_id', 'action']  # action: allowed/blocked
    )
    
    SECURITY_BLOCKS = Counter(
        'qwed_security_blocks_total',
        'Security policy violations blocked',
        ['block_type']  # injection, pii, etc.
    )
    
    # Histograms
    VERIFICATION_LATENCY = Histogram(
        'qwed_verification_latency_seconds',
        'Verification request latency',
        ['engine'],
        buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    
    LLM_LATENCY = Histogram(
        'qwed_llm_latency_seconds',
        'LLM API call latency',
        ['provider'],
        buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
    )
    
    # Gauges
    ACTIVE_TENANTS = Gauge(
        'qwed_active_tenants',
        'Number of active tenants'
    )
    
    CACHE_SIZE = Gauge(
        'qwed_cache_size',
        'Current cache size',
        ['backend']  # redis/memory
    )
    
    # Info
    BUILD_INFO = Info(
        'qwed_build',
        'QWED build information'
    )
    BUILD_INFO.info({'version': '0.1.0', 'service': 'qwed-api'})


# =============================================================================
# Prometheus Metric Recording Functions
# =============================================================================

def record_verification(engine: str, status: str, latency_seconds: float, tenant_id: str = "global"):
    """Record a verification request to Prometheus."""
    if not PROMETHEUS_AVAILABLE:
        return
    
    VERIFICATION_TOTAL.labels(engine=engine, status=status, tenant_id=tenant_id).inc()
    VERIFICATION_LATENCY.labels(engine=engine).observe(latency_seconds)


def record_llm_call(provider: str, model: str, latency_seconds: float, success: bool = True):
    """Record an LLM API call to Prometheus."""
    if not PROMETHEUS_AVAILABLE:
        return
    
    status = "success" if success else "error"
    LLM_CALLS_TOTAL.labels(provider=provider, model=model, status=status).inc()
    LLM_LATENCY.labels(provider=provider).observe(latency_seconds)


def record_cache_operation(operation: str, hit: bool):
    """Record a cache operation (hit/miss)."""
    if not PROMETHEUS_AVAILABLE:
        return
    
    result = "hit" if hit else "miss"
    CACHE_OPERATIONS.labels(operation=operation, result=result).inc()


def record_rate_limit(tenant_id: str, blocked: bool):
    """Record a rate limit check."""
    if not PROMETHEUS_AVAILABLE:
        return
    
    action = "blocked" if blocked else "allowed"
    RATE_LIMIT_HITS.labels(tenant_id=tenant_id, action=action).inc()


def record_security_block(block_type: str):
    """Record a security policy block."""
    if not PROMETHEUS_AVAILABLE:
        return
    
    SECURITY_BLOCKS.labels(block_type=block_type).inc()


def update_active_tenants(count: int):
    """Update active tenant gauge."""
    if not PROMETHEUS_AVAILABLE:
        return
    
    ACTIVE_TENANTS.set(count)


def update_cache_size(backend: str, size: int):
    """Update cache size gauge."""
    if not PROMETHEUS_AVAILABLE:
        return
    
    CACHE_SIZE.labels(backend=backend).set(size)


def get_prometheus_metrics() -> bytes:
    """Generate Prometheus metrics output for /metrics endpoint."""
    if not PROMETHEUS_AVAILABLE:
        return b"# Prometheus client not installed\n"
    
    return generate_latest()


def get_prometheus_content_type() -> str:
    """Get content type for Prometheus metrics."""
    return CONTENT_TYPE_LATEST


# =============================================================================
# In-Memory Metrics (Original Implementation)
# =============================================================================

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
    In-memory metrics aggregator with Prometheus integration.
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
        provider: Optional[str] = None,
        engine: str = "unknown"
    ):
        """
        Track a single request.
        
        Args:
            organization_id: Tenant ID
            status: "VERIFIED", "CORRECTED", "BLOCKED", "ERROR", etc.
            latency_ms: Request latency in milliseconds
            provider: LLM provider used (e.g., "azure_openai")
            engine: Verification engine used (e.g., "math", "logic")
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
        
        # Record to Prometheus
        record_verification(
            engine=engine,
            status=status,
            latency_seconds=latency_ms / 1000.0,
            tenant_id=str(organization_id)
        )
        update_active_tenants(len(self.tenant_metrics))
    
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
