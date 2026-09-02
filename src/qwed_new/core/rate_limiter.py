"""
Rate limiting for QWED API endpoints.

Implements:
- Per-API-key rate limits
- Global endpoint rate limits
- Returns 429 Too Many Requests when exceeded
"""

import ipaddress
import math
import os
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional

from fastapi import HTTPException

class _IndexedExpiryQueue:
    """Min-heap of (deadline, ip) with O(log n) IN-PLACE key updates.

    ONE authoritative record per IP: `set_deadline` repositions the
    existing entry instead of leaving stale lower-bound records behind.
    The head is therefore always the bucket's TRUE earliest expiry —
    capacity decisions need no garbage collection, no drift repair, and
    no repair budget (Greptile P1 rounds 4-10: with lazy lower-bound
    records, bounded repair, no-hidden-expired-capacity and no-table-scan
    were mutually exclusive; eager repositioning delivers all three)."""

    __slots__ = ("_heap", "_pos")

    def __init__(self):
        self._heap: list = []
        self._pos: Dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._heap)

    def set_deadline(self, ip: str, deadline: float) -> None:
        """Insert or reposition the IP's record (O(log n))."""
        idx = self._pos.get(ip)
        if idx is None:
            self._heap.append((deadline, ip))
            idx = len(self._heap) - 1
            self._pos[ip] = idx
            self._sift_up(idx)
            return
        old_deadline = self._heap[idx][0]
        self._heap[idx] = (deadline, ip)
        if deadline < old_deadline:
            self._sift_up(idx)
        elif deadline > old_deadline:
            self._sift_down(idx)

    def peek(self):
        """(deadline, ip) of the earliest expiry, or None."""
        return self._heap[0] if self._heap else None

    def pop_min(self):
        """Remove and return the earliest (deadline, ip), or None."""
        if not self._heap:
            return None
        head = self._heap[0]
        self._remove_at(0)
        return head

    def remove(self, ip: str) -> None:
        """Drop the IP's record if present (O(log n))."""
        idx = self._pos.get(ip)
        if idx is not None:
            self._remove_at(idx)

    def clear(self) -> None:
        """Drop every record. Whoever empties the bucket table must empty
        the queue in the same breath: a record whose bucket is gone would
        surface at the head and make capacity reclaim delete a missing
        bucket (Sentry on PR #345 round 11)."""
        self._heap.clear()
        self._pos.clear()

    def _remove_at(self, idx: int) -> None:
        heap = self._heap
        last = len(heap) - 1
        removed_ip = heap[idx][1]
        if idx == last:
            heap.pop()
        else:
            heap[idx] = heap[last]
            heap.pop()
            self._pos[heap[idx][1]] = idx
            self._sift_down(idx)
            self._sift_up(idx)
        del self._pos[removed_ip]

    def _sift_up(self, idx: int) -> None:
        heap = self._heap
        entry = heap[idx]
        while idx > 0:
            parent = (idx - 1) // 2
            if heap[parent] <= entry:
                break
            heap[idx] = heap[parent]
            self._pos[heap[idx][1]] = idx
            idx = parent
        heap[idx] = entry
        self._pos[entry[1]] = idx

    def _sift_down(self, idx: int) -> None:
        heap = self._heap
        n = len(heap)
        entry = heap[idx]
        while True:
            left, right = 2 * idx + 1, 2 * idx + 2
            # Track the running minimum against the CARRIED entry, never
            # heap[idx]: once the entry has been displaced past a child
            # position, that slot still holds a moved-up value, and
            # comparing against it would end the sift early and leave a
            # parent above a smaller child.
            smallest, smallest_val = idx, entry
            if left < n and heap[left] < smallest_val:
                smallest, smallest_val = left, heap[left]
            if right < n and heap[right] < smallest_val:
                smallest = right
            if smallest == idx:
                break
            heap[idx] = heap[smallest]
            self._pos[heap[idx][1]] = idx
            idx = smallest
        heap[idx] = entry
        self._pos[entry[1]] = idx


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

        # Indexed expiry queue: ONE authoritative record per tracked
        # bucket, eagerly repositioned on every admission, so the heap
        # head is always the TRUE earliest expiry. Capacity decisions are
        # then O(1): expired head -> reclaim that slot; live head ->
        # every bucket is live. No lazy lower-bound records means no
        # garbage, no drift, no repair budget, no conservative fallback —
        # the trio Greptile showed to be impossible with a lazy-deletion
        # heap (P1 rounds 4-10).
        self._expiries = _IndexedExpiryQueue()
    
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
            # Greptile P1 round 2). Every tracked bucket holds exactly ONE
            # expiry record, eagerly repositioned on every admitted
            # request, so a non-empty bucket's record EQUALS its true
            # deadline. The head is therefore the table's true earliest
            # expiry and the capacity verdict is exact in O(1): past-due
            # head → reclaim that one slot; live head → EVERY bucket is
            # live. No lazy lower-bound records means no drift, no
            # garbage, no repair budget and no conservative fallback —
            # with lazy records, budget exhaustion could strand an
            # expired slot behind refreshed buckets and 429 a new client
            # while capacity was free (Greptile P1 round 10); eager
            # repositioning removes the failure mode instead of widening
            # the budget.
            if (
                client_ip not in self.ip_requests
                and len(self.ip_requests) >= self.MAX_TRACKED_IPS
            ):
                head = self._expiries.peek()
                if head is None:
                    # Fail closed: unreachable while every tracked bucket
                    # has exactly one record (a full table implies at
                    # least one), but a capacity decision must never
                    # dereference None or admit unboundedly.
                    return False, self.PER_IP_WINDOW
                if head[0] <= now:
                    # Exactly one expired slot is reclaimed per admission.
                    # The record equals the bucket's true deadline, so
                    # this is genuinely expired — never a live eviction.
                    _, evict_ip = self._expiries.pop_min()
                    del self.ip_requests[evict_ip]
                else:
                    # The earliest true expiry is in the future: every
                    # bucket is live. Retry-After derives from the exact
                    # head deadline; max(1, ...) keeps it non-zero at the
                    # boundary.
                    return False, max(1, math.ceil(head[0] - now))

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
            # Eager repositioning (Greptile P1 rounds 4-10): the bucket's
            # single expiry record is moved to its new true deadline on
            # EVERY admitted request, so no stale lower-bound record can
            # accumulate between admissions and the capacity verdict
            # above stays exact. Queue memory remains bounded 1:1 by the
            # IP table.
            self._expiries.set_deadline(client_ip, now + self.PER_IP_WINDOW)
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
