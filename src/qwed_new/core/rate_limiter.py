"""
Rate limiting for QWED API endpoints.

Implements:
- Per-API-key rate limits
- Global endpoint rate limits
- Returns 429 Too Many Requests when exceeded
"""

import heapq
import ipaddress
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

        # Min-heap of (expiry_deadline, ip) indexing each tracked bucket's
        # earliest possible expiry, so capacity-time decisions never need a
        # table-wide scan. Push policy is DEDUPED (Greptile P1 round 6): a
        # bucket is (re)indexed only when its previous index entry has
        # already expired — at most one push per IP per window — so heap
        # memory is structurally bounded by the IP table instead of growing
        # with per-request records.
        #
        # The index is AUTHORITATIVE for the all-live verdict (Greptile P1
        # round 7): a record's deadline is a LOWER BOUND on its bucket's
        # true deadline (buckets only grow between re-indexes), so when the
        # earliest indexed deadline is live, EVERY bucket is live — no
        # table reconciliation required.
        self._expiry_heap: list = []
        self._indexed_deadline: Dict[str, float] = {}
        # Bounded under-lock work (Greptile P1 rounds 4-5): at most this
        # many heap pops — garbage purge, re-index, or reclaim — during ONE
        # capacity admission. When the budget is spent, the verdict is a
        # bounded conservative reject derived from the heap head, never a
        # table scan (round 7).
        self._MAX_HEAP_REPAIRS = 64
    
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
        """Amortized O(1) heap hygiene: drop a few garbage head entries
        (records whose bucket is gone or whose index entry moved on) so
        the heap tracks the live set even when the table never reaches
        capacity. Bounded to a constant per call — no scans.

        Garbage heads are removed via _purge_head so an EMPTY bucket is
        dropped from ip_requests too (Sentry round 9: popping only the
        record + index left a permanent "ghost" — a capacity slot with
        no heap record, impossible to ever reclaim). Hygiene pops count
        against the same bounded-work envelope as repair: at most
        _MAX_HEAP_REPAIRS pops here, so a zero budget means zero pops
        (Greptile round 9: the budget must not be bypassable)."""
        rounds = min(rounds, max(0, self._MAX_HEAP_REPAIRS))
        for _ in range(rounds):
            if not self._expiry_heap:
                return
            head_deadline, head_ip = self._expiry_heap[0]
            head_bucket = self.ip_requests.get(head_ip)
            if (
                head_bucket
                and self._indexed_deadline.get(head_ip) == head_deadline
            ):
                # Valid, current record at the head: the heap is clean.
                return
            self._purge_head(head_deadline, head_ip)

    def _head_record_state(self, now: float) -> tuple:
        """Classify the current heap head without mutating anything.

        Returns ("garbage", deadline, ip), ("expired", deadline, ip) or
        ("live", deadline, ip): garbage = bucket gone or the record is
        superseded by a newer index entry; expired = the bucket's window
        has fully elapsed at `now`; live = current, unexpired record."""
        deadline, evict_ip = self._expiry_heap[0]
        bucket = self.ip_requests.get(evict_ip)
        if not bucket or self._indexed_deadline.get(evict_ip) != deadline:
            return "garbage", deadline, evict_ip
        if max(bucket) + self.PER_IP_WINDOW <= now:
            return "expired", deadline, evict_ip
        return "live", deadline, evict_ip

    def _purge_head(self, deadline: float, evict_ip: str) -> None:
        """Drop one garbage head record; reclaim the table slot too when
        the bucket itself is gone or emptied."""
        heapq.heappop(self._expiry_heap)
        if self._indexed_deadline.get(evict_ip) == deadline:
            self._indexed_deadline.pop(evict_ip, None)
        if not self.ip_requests.get(evict_ip):
            self.ip_requests.pop(evict_ip, None)

    def _reindex_head(self, evict_ip: str, true_deadline: float) -> None:
        """Re-index a drifted record to its bucket's current true deadline
        (one repair per client per window) so its expiry stays visible
        without any table scan."""
        heapq.heappop(self._expiry_heap)
        heapq.heappush(self._expiry_heap, (true_deadline, evict_ip))
        self._indexed_deadline[evict_ip] = true_deadline

    def _reclaim_expired_slot(self, now: float) -> bool:
        """Reclaim one expired table slot via the expiry index.

        Pops garbage heads and re-indexes drifted ones until a genuinely
        expired bucket is reclaimed (True) or the earliest authoritative
        deadline is live (False — every tracked bucket is then live: a
        record's deadline is a LOWER BOUND on its bucket's true deadline,
        so a live head proves a live table, no reconciliation needed).

        Bounded under-lock work (Greptile P1 rounds 4-7): EVERY heap pop
        — garbage, re-index, or reclaim — consumes one unit of the
        _MAX_HEAP_REPAIRS budget. With one authoritative record per IP
        (`_indexed_deadline`) the repair rate is at most one per client
        per window, so no single client can exhaust the budget."""
        repairs = 0
        while self._expiry_heap and repairs < self._MAX_HEAP_REPAIRS:
            state, deadline, evict_ip = self._head_record_state(now)
            if state == "garbage":
                self._purge_head(deadline, evict_ip)
                repairs += 1
            elif state == "expired":
                # Genuinely expired: reclaim the slot and admit.
                heapq.heappop(self._expiry_heap)
                self._indexed_deadline.pop(evict_ip, None)
                del self.ip_requests[evict_ip]
                return True
            else:
                true_deadline = (
                    max(self.ip_requests[evict_ip]) + self.PER_IP_WINDOW
                )
                if true_deadline == deadline:
                    # Earliest authoritative deadline is live and
                    # current: every tracked bucket is live.
                    return False
                self._reindex_head(evict_ip, true_deadline)
                repairs += 1
        # Budget spent: ONE final bounded peek, no scan (Greptile P1
        # round 8). The last repair can expose an expired head — reclaim
        # it rather than rejecting available capacity. A live head here
        # may still be drifted (index not yet current), so it cannot
        # settle the verdict authoritatively; a garbage head would need
        # more pops. Either way the call falls through to the caller's
        # conservative reject, keeping under-lock work bounded.
        if self._expiry_heap:
            state, _deadline, evict_ip = self._head_record_state(now)
            if state == "expired":
                heapq.heappop(self._expiry_heap)
                self._indexed_deadline.pop(evict_ip, None)
                del self.ip_requests[evict_ip]
                return True
        return False

    def _conservative_reject(self, now: float) -> tuple:
        """Bounded O(1) capacity rejection when the heap could not settle
        the decision (repair budget exhausted under an injected or
        pathological state). The earliest indexed deadline is a lower
        bound on when some slot frees up, so retry then; with an empty
        heap, one full window. NEVER a table scan (Greptile P1 round 7:
        a full-table traversal under the shared limiter lock is an
        attacker-controlled stall)."""
        if self._expiry_heap:
            head_deadline = self._expiry_heap[0][0]
            reset_after = max(1, math.ceil(head_deadline - now))
        else:
            reset_after = self.PER_IP_WINDOW
        return (False, reset_after)

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
            # Greptile P1 round 2). Each IP holds ONE authoritative expiry
            # record in the min-heap; at capacity the earliest indexed
            # deadline decides: expired → that slot is reclaimed; live →
            # EVERY bucket is live (an indexed deadline is a lower bound
            # on its bucket's true deadline), so the verdict is final with
            # zero reconciliation — no scan, no fallback traversal
            # (Greptile P1 round 7). Budget exhaustion rejects
            # conservatively instead of scanning.
            if (
                client_ip not in self.ip_requests
                and len(self.ip_requests) >= self.MAX_TRACKED_IPS
            ):
                if not self._reclaim_expired_slot(now):
                    return self._conservative_reject(now)

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
            # Deduped indexing (Greptile P1 round 6): (re)index the bucket
            # only while it has no live index entry — at most one record
            # per IP per window, so heap memory is structurally bounded by
            # the IP table (no record cap needed) and refreshed buckets
            # stay indexed (their stale record is re-indexed to the true
            # deadline at reclaim time).
            if client_ip not in self._indexed_deadline:
                deadline = now + self.PER_IP_WINDOW
                self._indexed_deadline[client_ip] = deadline
                heapq.heappush(self._expiry_heap, (deadline, client_ip))
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
