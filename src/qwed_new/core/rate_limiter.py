"""
Rate limiting for QWED API endpoints.

Implements:
- Per-API-key rate limits
- Global endpoint rate limits
- Returns 429 Too Many Requests when exceeded
"""

import heapq
import ipaddress
import itertools
import math
import os
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional

from fastapi import HTTPException

class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window algorithm.
    
    For production with multiple servers, consider using Redis instead.

    NOTE (Greptile round 5): all state here is PROCESS-LOCAL. With
    multiple uvicorn/gunicorn workers, each worker keeps its own buckets,
    so per-IP and per-key budgets are effectively multiplied by the
    worker count — every worker independently admits its own budget to
    the same client. Single-worker deployments get exact limits;
    multi-worker deployments need a shared store (Redis) for exact
    limits.

    Environment Variables:
        QWED_RATE_LIMIT_PER_KEY: Requests per minute per API key (default: 100)
        QWED_RATE_LIMIT_GLOBAL: Requests per minute globally (default: 1000)
        QWED_RATE_LIMIT_PER_IP: Requests per minute per client IP on
            anonymous /auth/* routes (default: 10) — these routes have no
            API key to key a bucket on, so without a per-IP bucket they are
            an unthrottled bcrypt/DoS surface (issues #226, #334).
    """

    def __init__(self, clock=None):
        # Injectable monotonic-ish clock (CodeRabbit on PR #345): rate-limit
        # tests can freeze/advance time deterministically instead of
        # manipulating wall-clock-derived stamps. Defaults to time.time,
        # matching the pre-existing per-key/global buckets.
        self._clock = clock if clock is not None else time.time
        self._lock = threading.Lock()

        # Per-API-key request timestamps: {api_key: [timestamp1, timestamp2, ...]}
        self.api_key_requests: Dict[str, list] = defaultdict(list)

        # Per-client-IP request timestamps for anonymous auth routes:
        # {ip: [timestamp1, timestamp2, ...]}
        self.ip_requests: Dict[str, list] = defaultdict(list)

        # Global request timestamps: [timestamp1, timestamp2, ...]
        self.global_requests: list = []

        # Rate limit configurations - configurable via env vars
        self.PER_KEY_LIMIT = int(os.environ.get("QWED_RATE_LIMIT_PER_KEY", "100"))
        self.PER_KEY_WINDOW = 60  # seconds

        self.GLOBAL_LIMIT = int(os.environ.get("QWED_RATE_LIMIT_GLOBAL", "1000"))
        self.GLOBAL_WINDOW = 60  # seconds

        self.PER_IP_LIMIT = int(os.environ.get("QWED_RATE_LIMIT_PER_IP", "10"))
        # Fail at construction (module import wires the singleton), never
        # per request: with a limit < 1 a fresh bucket is immediately "over
        # limit", the reset computation takes min() of an empty bucket, and
        # every anonymous /auth/* request would 500 instead of 429
        # (CodeRabbit on PR #345).
        if self.PER_IP_LIMIT < 1:
            raise ValueError(
                "QWED_RATE_LIMIT_PER_IP must be at least 1 (got "
                f"{self.PER_IP_LIMIT}) — a non-positive limit would turn "
                "every anonymous auth request into an HTTP 500."
            )
        self.PER_IP_WINDOW = 60  # seconds

        # Bound the per-IP table: floods from spoofed/varied IPs must not
        # grow memory unboundedly. Above the cap, drop IPs whose windows
        # have fully expired.
        self.MAX_TRACKED_IPS = 50_000

        # Min-heap of (expiry_deadline, ip) for capacity-time eviction.
        # Entries are pushed on every admitted request and cleaned lazily,
        # so the heap tracks the live set without any table-wide scan.
        self._expiry_heap: list = []
        # Bounded under-lock work (Greptile P1 round 4): at most this many
        # stale-record repairs during ONE capacity admission; leftovers are
        # finished off by later calls' hygiene trims, so a request's
        # critical section can never grow with accumulated stale records.
        self._MAX_HEAP_REPAIRS = 32
        # Hard memory bound on heap records: beyond this, new admissions
        # stop pushing records (the bounded insertion-order fallback scan
        # keeps capacity decisions correct even with a lossy heap).
        self._MAX_HEAP_RECORDS = 4 * self.MAX_TRACKED_IPS
        # Bounded capacity-fallback scan: when the heap cannot prove that
        # every bucket is live, at most this many oldest-admission buckets
        # are examined for expiry under the lock (Greptile P1 round 5).
        self._FALLBACK_SCAN_LIMIT = 64
    
    def _clean_old_requests(self, requests: list, window_seconds: int, now=None) -> list:
        """Remove timestamps older than the window (injected clock).

        `now` lets callers pin ONE clock reading across the cleanup and the
        reset-time computation (Sentry on PR #345: two reads can straddle
        the window deadline and yield Retry-After: 0 for a rejected
        request)."""
        if now is None:
            now = self._clock()
        cutoff = now - window_seconds
        return [ts for ts in requests if ts > cutoff]
    
    def check_api_key_limit(self, api_key: str) -> bool:
        """
        Check if API key has exceeded its rate limit.
        
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self._lock:
            # Clean old requests
            self.api_key_requests[api_key] = self._clean_old_requests(
                self.api_key_requests[api_key], 
                self.PER_KEY_WINDOW
            )
            
            # Check limit
            if len(self.api_key_requests[api_key]) >= self.PER_KEY_LIMIT:
                return False
            
            # Record this request
            self.api_key_requests[api_key].append(self._clock())
            return True
    
    def check_global_limit(self) -> bool:
        """
        Check if global endpoint has exceeded its rate limit.
        
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self._lock:
            # Clean old requests
            self.global_requests = self._clean_old_requests(
                self.global_requests, 
                self.GLOBAL_WINDOW
            )
            
            # Check limit
            if len(self.global_requests) >= self.GLOBAL_LIMIT:
                return False
            
            # Record this request
            self.global_requests.append(self._clock())
            return True
    
    def check_ip_limit(self, client_ip: str) -> bool:
        """
        Check if a client IP has exceeded the anonymous-route rate limit.

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        allowed, _ = self.check_ip_limit_with_reset(client_ip)
        return allowed

    def _trim_stale_heap_heads(self, rounds: int = 4) -> None:
        """Amortized O(1) heap hygiene: drop a few stale head entries so
        the heap tracks the live set even when the table never reaches
        capacity. Bounded to a constant per call — no scans."""
        for _ in range(rounds):
            if not self._expiry_heap:
                return
            head_deadline, head_ip = self._expiry_heap[0]
            head_bucket = self.ip_requests.get(head_ip)
            if (
                not head_bucket
                or max(head_bucket) + self.PER_IP_WINDOW != head_deadline
            ):
                heapq.heappop(self._expiry_heap)
                continue
            return

    def _reclaim_expired_slot(self, now: float) -> bool:
        """Pop expired / stale head entries until a genuinely expired
        bucket is reclaimed (True) or the earliest indexed deadline is
        live (False — the caller's bounded fallback then decides).

        Bounded under-lock work (Greptile P1 round 4): EVERY heap pop —
        empty, drifted, or expired — consumes one unit of the
        _MAX_HEAP_REPAIRS budget (round 5: empty heads previously bypassed
        the cap, so accumulated stale records could force unbounded pops
        while the shared lock is held). Drifted records are dropped, not
        re-pushed: each admission pushes a fresh record with the true
        deadline, so a drifted head is by definition superseded."""
        window = self.PER_IP_WINDOW
        repairs = 0
        while self._expiry_heap:
            if repairs >= self._MAX_HEAP_REPAIRS:
                return False
            deadline, evict_ip = self._expiry_heap[0]
            bucket = self.ip_requests.get(evict_ip)
            if not bucket:
                # Empty or already evicted: reclaim both.
                heapq.heappop(self._expiry_heap)
                self.ip_requests.pop(evict_ip, None)
                repairs += 1
                continue
            if max(bucket) + window != deadline:
                # Superseded record (bucket refreshed since push): the
                # ip's latest admission already pushed the true deadline.
                heapq.heappop(self._expiry_heap)
                repairs += 1
                continue
            if deadline <= now:
                # Genuinely expired: reclaim the slot and admit.
                heapq.heappop(self._expiry_heap)
                del self.ip_requests[evict_ip]
                return True
            # Earliest indexed deadline is live.
            return False
        return False

    def _fallback_admit_or_reject(self, now: float):
        """Heap exhausted, repair budget spent, or index incomplete while
        the table is full: bounded insertion-order scan (oldest admissions
        first) for an EXPIRED bucket to reclaim — including buckets the
        record cap left unindexed (Greptile P1 round 5: a lossy heap must
        not reject available capacity). No live bucket is ever evicted,
        and the scan is bounded to _FALLBACK_SCAN_LIMIT entries under the
        lock.

        Returns None when a slot was freed, else the (False, reset_after)
        rejection verdict."""
        window = self.PER_IP_WINDOW
        sample = list(itertools.islice(self.ip_requests, self._FALLBACK_SCAN_LIMIT))
        for ip in sample:
            bucket = self.ip_requests[ip]
            if not bucket or max(bucket) + window <= now:
                del self.ip_requests[ip]
                return None
        # Every sampled bucket is live; the front bucket is the stalest
        # admission, so its deadline is the soonest any slot can free up.
        front_bucket = self.ip_requests[sample[0]]
        return (
            False,
            max(1, math.ceil(max(front_bucket) + window - now)),
        )

    def check_ip_limit_with_reset(self, client_ip: str) -> tuple:
        """
        Atomic limit check + reset-time lookup under one lock acquisition.

        Splitting these into two locked calls (as check_auth_rate_limit
        did) lets concurrent cleanup observe an emptied window in between,
        which callers could surface as a misleading Retry-After (Sentry on
        PR #345).

        Returns:
            (allowed, reset_after_seconds) — reset_after is 0 when allowed.
        """
        with self._lock:
            self._trim_stale_heap_heads()

            # ONE clock reading for the whole decision (Sentry on PR
            # #345): the capacity deadline check, the window cleanup, the
            # over-limit reset computation and the recorded timestamp all
            # use `now`, so a rejected request can never observe its own
            # deadline crossed mid-decision and get Retry-After: 0.
            now = self._clock()

            # Hard cap WITHOUT table-wide scans inside the lock (a full
            # table must not stall every limiter call — Greptile P1, PR
            # #345) and WITHOUT evicting a live bucket (that would hand
            # the evicted client a fresh budget before its window ended —
            # Greptile P1 round 2). Buckets record their expiry deadline
            # in a min-heap; at capacity the earliest deadline is
            # reclaimed if expired. A live FRONT bucket no longer blocks
            # reclaiming EXPIRED later buckets (Greptile P1 round 3:
            # insertion order is not expiry order — otherwise one
            # first-seen client's traffic keeps anonymous signup/signin
            # 429 for every untracked address).
            if (
                client_ip not in self.ip_requests
                and len(self.ip_requests) >= self.MAX_TRACKED_IPS
            ):
                if not self._reclaim_expired_slot(now):
                    reject = self._fallback_admit_or_reject(now)
                    if reject is not None:
                        return reject

            bucket = self._clean_old_requests(
                self.ip_requests[client_ip],
                self.PER_IP_WINDOW,
                now,
            )
            self.ip_requests[client_ip] = bucket

            if len(bucket) >= self.PER_IP_LIMIT:
                # Bucket was just cleaned against `now`, so min() is the
                # oldest live stamp and the delta is strictly positive;
                # max(1, ...) keeps Retry-After non-zero at the boundary.
                reset_after = max(
                    1, math.ceil(min(bucket) + self.PER_IP_WINDOW - now)
                )
                return False, reset_after

            self.ip_requests[client_ip].append(now)
            # Hard memory bound on heap records (Greptile P1 round 4):
            # beyond the cap, stop pushing — the front-bucket fallback
            # keeps capacity decisions correct with a lossy heap.
            if len(self._expiry_heap) < self._MAX_HEAP_RECORDS:
                heapq.heappush(
                    self._expiry_heap,
                    (now + self.PER_IP_WINDOW, client_ip),
                )
            return True, 0

    def get_ip_reset_time(self, client_ip: str) -> int:
        """Seconds until this IP's auth-route window resets (rounded up)."""
        with self._lock:
            requests = list(self.ip_requests.get(client_ip, []))
            if not requests:
                return 0
            oldest = min(requests)
            # Round up: truncation could report Retry-After: 0 while the IP
            # is still inside its window, inviting immediate retry loops.
            return max(0, math.ceil(oldest + self.PER_IP_WINDOW - self._clock()))

    def get_reset_time(self, api_key: Optional[str] = None) -> int:
        """
        Get seconds until rate limit resets.
        
        Args:
            api_key: If provided, get per-key reset time. Otherwise, global reset time.
        
        Returns:
            Seconds until oldest request expires from the window
        """
        with self._lock:
            if api_key:
                # Copy list to prevent mutation during calculation
                requests = list(self.api_key_requests.get(api_key, []))
                window = self.PER_KEY_WINDOW
            else:
                requests = list(self.global_requests)
                window = self.GLOBAL_WINDOW
            
            if not requests:
                return 0
            
            oldest = min(requests)
            reset_time = oldest + window
            return max(0, int(reset_time - self._clock()))


# Global rate limiter instance
rate_limiter = RateLimiter()


def check_rate_limit(api_key: Optional[str] = None):
    """
    FastAPI dependency to check rate limits.
    
    Args:
        api_key: Optional API key for per-key limiting
    
    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    # Check global limit first
    if not rate_limiter.check_global_limit():
        reset_after = rate_limiter.get_reset_time()
        raise HTTPException(
            status_code=429,
            detail=f"Global rate limit exceeded. Try again in {reset_after} seconds.",
            headers={"Retry-After": str(reset_after)}
        )
    
    # Check per-API-key limit if key provided
    if api_key:
        if not rate_limiter.check_api_key_limit(api_key):
            reset_after = rate_limiter.get_reset_time(api_key)
            raise HTTPException(
                status_code=429,
                detail=f"API key rate limit exceeded. Try again in {reset_after} seconds.",
                headers={"Retry-After": str(reset_after)}
            )


# Comma-separated IPs/CIDRs of reverse proxies that are trusted to set (and
# sanitize) X-Forwarded-For. Default is empty: the direct peer address is
# used and the header is ignored, so a client cannot mint fresh bucket keys
# by rotating spoofed header values (CodeRabbit/CodeAnt on PR #345).
# On Cloud Run / behind a known LB, set e.g. QWED_AUTH_TRUSTED_PROXIES=172.16.0.0/12.
_TRUSTED_PROXIES: List = [
    ipaddress.ip_network(entry.strip(), strict=False)
    for entry in os.environ.get("QWED_AUTH_TRUSTED_PROXIES", "").split(",")
    if entry.strip()
]


def _normalize_ip(value: str) -> str:
    """
    Strip a port / bracket suffix from an XFF hop ("1.2.3.4:8080",
    "[2001:db8::1]:8080") so port rotation cannot mint fresh bucket keys
    (Sentry on PR #345). Unparseable values pass through unchanged — a
    malformed hop then shares one bucket instead of escaping throttling.
    """
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            # Unterminated bracket: slicing with -1 would truncate the last
            # group into a DIFFERENT valid address ([2001:db8::1 ->
            # 2001:db8::) and mis-bucket the client. Keep the raw value.
            return value
        candidate = value[1:end]
    else:
        candidate = value.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return value


def _is_trusted_proxy(peer: Optional[str]) -> bool:
    if not peer or not _TRUSTED_PROXIES:
        return False
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in network for network in _TRUSTED_PROXIES)


def client_ip_of(request) -> str:
    """
    Resolve the rate-limit key for anonymous-route throttling.

    The direct peer address is always the fallback and the default: a client
    must not be able to choose its bucket key. X-Forwarded-For is honored
    only when the direct peer is a configured trusted proxy — and then the
    RIGHTMOST hop is used, because our proxy appends the real client address
    after any client-supplied entries; a client sending its own header value
    therefore cannot select the key.
    """
    peer = request.client.host if request.client else None
    if _is_trusted_proxy(peer):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return _normalize_ip(forwarded.split(",")[-1])
    return peer or "unknown"


def check_auth_rate_limit(request):
    """
    FastAPI dependency for anonymous /auth/* routes: per-IP bucket only.

    These routes have no API key, so the per-key limiter cannot apply; an
    unthrottled bcrypt signup/signin is a ~4 req/s whole-service DoS plus a
    password-guessing oracle (issues #226, #334).
    """
    ip = client_ip_of(request)
    allowed, reset_after = rate_limiter.check_ip_limit_with_reset(ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many authentication attempts. Try again in {reset_after} seconds.",
            headers={"Retry-After": str(reset_after)},
        )
