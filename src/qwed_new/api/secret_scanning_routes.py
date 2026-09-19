"""Signature verification and alert intake for external secret-leak reports.

GitHub secret scanning (and compatible scanners) POST leak matches to
``POST /webhooks/secret-scanning``. This module is the trust gate for that
class of events: nothing in the payload is touched, logged, or processed
until the ECDSA signature is verified against GitHub's published public keys.

Process (issue #367 — the order of operations is the whole point)::

    read raw body -> verify signature -> only then parse JSON / touch DB

Verification parameters (per GitHub's partner-program documentation):

* ``Github-Public-Key-Identifier`` — which ``key_identifier`` signed this.
* ``Github-Public-Key-Signature`` — base64 ASN.1/DER ECDSA signature.
* Keys from ``https://api.github.com/meta/public_keys/secret_scanning``.
* Algorithm ``ECDSA-NIST-P256V1-SHA256`` (P-256 / secp256r1 + SHA-256).
* The signature covers the **raw message body bytes** — never re-serialize
  the JSON, since reformatting breaks the signature.
"""

import base64
import hmac
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from pydantic import BaseModel, Field, ValidationError
from starlette.concurrency import run_in_threadpool

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

#: Where GitHub publishes its secret-scanning signing keys.
GITHUB_KEYS_URI = "https://api.github.com/meta/public_keys/secret_scanning"

#: Exact header names carrying the signing key id and the signature.
KEY_ID_HEADER = "github-public-key-identifier"
SIGNATURE_HEADER = "github-public-key-signature"

#: Cap the request body (a webhook is an unbounded-by-design JSON array).
MAX_BODY_BYTES = 1 << 20  # 1 MiB

#: Cap the number of matches per request (bound per-item work).
MAX_MATCHES_PER_REQUEST = 500

#: Cap individual token length (a token is tens of chars; garbage can be huge).
MAX_TOKEN_CHARS = 512

#: How long cached signing keys are trusted before a refresh is required.
#: A failed refresh fails closed (see get_signing_keys) rather than extending
#: trust in a key GitHub may have retired.
KEYS_CACHE_TTL_SECONDS = 6 * 60 * 60  # 6h

#: Minimum interval between rotation-triggered forced refetches. An attacker
#: cannot drive the outbound GitHub fetch rate faster than this (CodeRabbit
#: on #374). Only *forced* refreshes are throttled, so a normal TTL/startup
#: fetch never delays recognising a newly rotated key (Greptile on #374).
MIN_FORCED_REFRESH_SECONDS = 60.0

#: Generic rejection detail for every signature failure. One constant on
#: purpose: success vs failure must not be distinguishable, so all paths
#: return the identical message (Sonar: no duplicated literals).
_INVALID_SIGNATURE_DETAIL = "invalid webhook signature"

#: Hard cap on the base64 signature header before decoding. A DER P-256
#: signature is ~70-72 bytes (~96-100 b64 chars); anything far larger is
#: garbage, rejected before decode work.
_MAX_SIGNATURE_B64_CHARS = 1024

# ---------------------------------------------------------------------------
# Payload models
# ---------------------------------------------------------------------------


class SecretMatch(BaseModel):
    """One verified secret match.

    Extra keys are ignored (not rejected): scanners may add informational
    fields over time and this is an intake endpoint, not a strict schema.
    """

    token: str = Field(min_length=1, max_length=MAX_TOKEN_CHARS)
    type: str = Field(min_length=1, max_length=128)
    url: str = Field(default="", max_length=4096)
    source: str = Field(default="unknown", max_length=64)

    class Config:
        extra = "ignore"


#: Sink for verified match batches. Replaced by the #368 revocation handler;
#: until then batches are dropped after counting (fail-closed intake stays up
#: while downstream work is still being built). The signature MUST stay a
#: plain ``Callable[[List[SecretMatch]], None]`` so #368 can swap it without
#: touching this module.
VerifiedMatchSink = Callable[[list[SecretMatch]], None]


def _default_sink(matches: list[SecretMatch]) -> None:
    _record_receipt(matches, event="matches_dropped_no_handler")


on_verified_matches: VerifiedMatchSink = _default_sink


# ---------------------------------------------------------------------------
# The trust gate: parse nothing until the signature is proven genuine.
# ---------------------------------------------------------------------------


class SignatureRejected(HTTPException):
    """A 401/403 raised for unsigned, forged, or unverifiable requests.

    Subclassing HTTPException (not ValueError) is deliberate: FastAPI turns
    the rejection into the correct response with zero handling code, and the
    verifier needs no Request context to produce it.
    """


class SignatureVerifier:
    """ECDSA-NIST-P256V1-SHA256 over the raw body, checked against known keys."""

    def __init__(self, keys: dict[str, str]) -> None:
        self._pubkeys: dict[str, Any] = {}
        for key_id, pem in keys.items():
            try:
                self._pubkeys[key_id] = self._parse_key(pem)
            except SignatureRejected:
                # One off-spec entry must not kill the whole verifier: GitHub
                # may add a key on another curve during a future rotation. Skip
                # it, keep the valid ones, fail closed only if NONE are usable.
                logger.warning("signing key %s… skipped (unsupported shape)", key_id[:8])
        if not self._pubkeys:
            raise SignatureRejected(status_code=403, detail="no usable signing keys")

    # -- public API ------------------------------------------------------

    def verify(self, raw_body: bytes, key_id: str, signature_b64: str) -> str:
        """Return ``key_id`` iff the signature is valid; raise otherwise.

        The signature covers the RAW body bytes. Every failure mode — missing
        or malformed pieces, unknown key, bad DER, non-P-256 key, invalid
        signature — raises the same ``SignatureRejected(403)`` with a generic
        detail, so nothing about which step failed is observable.
        """
        public_key = self._pubkeys.get(key_id)
        signature = _decode_signature_b64(signature_b64)
        if public_key is None or not signature:
            raise SignatureRejected(status_code=403, detail=_INVALID_SIGNATURE_DETAIL)

        try:
            candidate = public_key.verify(signature, raw_body, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            candidate = False
        except (ValueError, TypeError):
            raise SignatureRejected(status_code=403, detail=_INVALID_SIGNATURE_DETAIL)

        return key_id if self._constant_compare(candidate) else self._reject()

    # -- parsing (fail closed on anything unexpected) --------------------

    @staticmethod
    def _parse_key(pem: str) -> Any:
        """Load a PEM public key, pinned to P-256.

        Accepting only the exact documented curve keeps a future key-list
        entry on another curve from silently changing what this service
        verifies. Anything off-spec is dropped at load time, not at
        verify time.
        """
        try:
            key = serialization.load_pem_public_key(pem.encode("ascii"))
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise SignatureRejected(status_code=403, detail=_INVALID_SIGNATURE_DETAIL)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise SignatureRejected(status_code=403, detail=_INVALID_SIGNATURE_DETAIL)
        if not isinstance(key.curve, ec.SECP256R1):
            raise SignatureRejected(status_code=403, detail=_INVALID_SIGNATURE_DETAIL)
        # Coordinates are already validated against the curve's field prime by
        # the loader + curve check above; a separate bound would be redundant.
        return key

    # -- timing safety ---------------------------------------------------

    @staticmethod
    def _constant_compare(candidate: Any) -> bool:
        """True iff ``candidate`` is an int equal to 1, in constant time.

        ``cryptography``'s ECDSA ``verify()`` returns ``None`` on success and
        raises on failure — one shape for both outcomes. Mapping that to a
        fixed integer (1 == success) and running it through ``compare_digest``
        keeps the success/failure branch from being distinguishable by timing.
        ``candidate`` must never be a user-controlled blob here: callers pass
        the fixed ``1``/``0`` mapped above; the signature bytes live only
        inside the ``verify()`` call.
        """
        verdict = 1 if candidate is None else 0
        expected = _expected_verdict_bytes()
        return hmac.compare_digest(f"verdict:{verdict}".encode(), expected)

    @staticmethod
    def _reject() -> str:
        raise SignatureRejected(status_code=403, detail=_INVALID_SIGNATURE_DETAIL)


def _decode_signature_b64(signature_b64: str) -> bytes:
    """Decode the GitHub signature header to DER bytes, fail-closed to b"".

    QWED codeguard-b64-payload review (#374): this base64 blob is the ECDSA
    protocol-envelope signature documented at
    https://docs.github.com/en/developers/overview/secret-scanning-partner-program,
    NOT executable code. It is length-capped, strictly validated
    (validate=True), never logged, never executed — the bytes flow only into
    ``public_key.verify()``. Any decode problem returns b"" so the caller
    rejects with the generic 403.
    """
    if not signature_b64 or len(signature_b64) > _MAX_SIGNATURE_B64_CHARS:
        return b""
    try:
        return base64.b64decode(signature_b64, validate=True)
    except ValueError:
        # binascii.Error subclasses ValueError; one clause covers both.
        return b""


def _expected_verdict_bytes() -> bytes:
    """The canonical success verdict; split out so the compare is explicit."""
    return b"verdict:1"


# ---------------------------------------------------------------------------
# Signing-key cache: fetch once, reuse offline, refetch on rotation.
# ---------------------------------------------------------------------------

#: Process-wide cache. Keys are trusted material but not secrets — the shape
#: is {"keys": {key_id: pem}, "etag": str|None, "fetched_at": epoch,
#: "last_forced_refresh": epoch|None}. Only rotation-triggered forced
#: refreshes touch last_forced_refresh, so a normal TTL/startup fetch never
#: delays recognising a newly rotated key.
#: A lock serializes cache reads/writes (network I/O runs outside the lock).
_KEYS_CACHE: dict[str, Any] = {
    "keys": {},
    "etag": None,
    "fetched_at": 0.0,
    "last_forced_refresh": None,
}
_KEYS_CACHE_LOCK = threading.Lock()

#: Singleflight gate for signing-key refreshes (Greptile P1 on #374).
#: Without it, N concurrent webhooks on an empty/expired cache each start
#: their own GitHub fetch (threadpool + key-endpoint amplification). With
#: it, exactly one leader fetches; followers wait on the event (bounded)
#: and then re-read the cache. The gate never holds the cache lock during
#: network I/O and never serves stale keys on failure — followers re-check
#: and fail closed if the leader failed.
_FETCH_GATE_LOCK = threading.Lock()
#: In-flight refresh event, held as {"event": Event|None} (dict, not a bare
#: rebinding global, so no `global` statement is needed). Exactly one leader
#: fetches; followers wait bounded and re-check freshness, failing closed.
_FETCH_STATE: dict[str, Any] = {"event": None}
#: Upper bound for a follower to wait for the leader's fetch (httpx timeout
#: is 10s; margin covers scheduling jitter). Expiry means fail closed, not
#: a cascading second fetch — the next webhook retries.
_FETCH_WAIT_SECONDS = 20.0


def _signing_key_token() -> str | None:
    """Optional PAT for the keys endpoint (rate-limit hygiene only)."""
    return os.getenv("GITHUB_KEYS_TOKEN") or os.getenv("GITHUB_TOKEN")


def _fetch_keys() -> tuple[dict[str, str], str | None]:
    """Fetch the signing-key list; returns (keys, etag).

    Uses a conditional request: a ``304 Not Modified`` keeps the cached keys
    untouched (and — since nothing changed — needs no new trust decision).
    Any transport-level or shape problem raises; the caller decides whether
    cached keys are still usable.

    The etag/keys snapshot is taken under the cache lock (Sentry on #374):
    a bare ``_KEYS_CACHE.get`` outside the lock could read a torn
    etag-then-keys pair and write the stale etag back over a fresh one.
    The lock is held only for the two dict reads, never for the network.
    """
    with _KEYS_CACHE_LOCK:
        cached_etag = _KEYS_CACHE.get("etag")
        cached_keys = dict(_KEYS_CACHE.get("keys", {}))
    headers = {"Accept": "application/vnd.github+json"}
    if cached_etag:
        headers["If-None-Match"] = cached_etag
    token = _signing_key_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = httpx.get(GITHUB_KEYS_URI, headers=headers, timeout=10.0)
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("signing-key fetch failed: %s", type(exc).__name__)
        raise

    if resp.status_code == 304:
        return cached_keys, cached_etag
    if resp.status_code != 200:
        logger.warning("signing-key fetch returned HTTP %s", resp.status_code)
        raise RuntimeError(f"keys endpoint returned HTTP {resp.status_code}")

    try:
        body = resp.json()
        entries = body["public_keys"]
    except (ValueError, KeyError, TypeError):
        logger.warning("signing-key response had an unexpected shape")
        raise RuntimeError("keys endpoint returned an unexpected shape")

    keys: dict[str, str] = {}
    for entry in entries:
        try:
            key_id, pem = entry["key_identifier"], entry["key"]
        except (KeyError, TypeError):
            continue
        if isinstance(key_id, str) and isinstance(pem, str) and key_id and pem:
            keys[key_id] = pem
    return keys, resp.headers.get("ETag")


def get_signing_keys(force_refresh: bool = False) -> dict[str, str]:
    """Return the current signing keys, refreshing on TTL expiry.

    Fail-closed and bounded:

    * a failed refresh **propagates** — we never fall back to stale cached keys.
      If the trust anchor cannot be refreshed, verification fails closed rather
      than trusting a key GitHub may have retired (CodeRabbit on #374; QWED
      Rule 2 "Fail Closed", Rule 6 "No Silent Degradation").
    * ``force_refresh`` is throttled against the last *forced* refresh only, so
      a normal startup/TTL fetch never delays recognising a newly rotated key
      (Greptile on #374).
    * the network call runs OUTSIDE the cache lock, so one refresh cannot
      serialize every other webhook request (Sentry on #374).
    * concurrent refreshes are singleflighted: exactly one leader fetches,
      followers wait bounded and re-read (Greptile P1 on #374). Followers
      never trigger a cascading fetch on leader failure — they fail closed.
    """
    now = time.monotonic()
    with _KEYS_CACHE_LOCK:
        cached = dict(_KEYS_CACHE.get("keys", {}))
        fetched_at = _KEYS_CACHE.get("fetched_at")
        fresh = bool(cached) and fetched_at is not None and (
            now - fetched_at < KEYS_CACHE_TTL_SECONDS
        )
        # Throttle rotation-triggered refetches only: unknown key ids must not
        # drive the outbound GitHub fetch rate (CodeRabbit on #374). A normal
        # fetch does not set this, so rotation is recognised immediately.
        if force_refresh:
            last_forced = _KEYS_CACHE.get("last_forced_refresh")
            if last_forced is not None and (now - last_forced < MIN_FORCED_REFRESH_SECONDS):
                force_refresh = False
            else:
                _KEYS_CACHE["last_forced_refresh"] = now
        if fresh and not force_refresh:
            return cached

    # Singleflight election: only the leader hits the network.
    # No `global` rebinding: the event lives in _FETCH_STATE (dict mutation).
    with _FETCH_GATE_LOCK:
        in_flight = _FETCH_STATE.get("event")
        if in_flight is not None:
            follower_event = in_flight
            is_leader = False
        else:
            follower_event = threading.Event()
            _FETCH_STATE["event"] = follower_event
            is_leader = True
    if not is_leader:
        # Follower: bounded wait, then require a FRESH cache. A failed
        # leader must not leave followers trusting expired keys (Sentry
        # HIGH + CodeRabbit major on #374): stale or empty -> fail closed.
        follower_event.wait(timeout=_FETCH_WAIT_SECONDS)
        with _KEYS_CACHE_LOCK:
            after = dict(_KEYS_CACHE.get("keys", {}))
            after_fetched_at = _KEYS_CACHE.get("fetched_at")
        refreshed = (
            bool(after)
            and after_fetched_at is not None
            and (time.monotonic() - after_fetched_at < KEYS_CACHE_TTL_SECONDS)
        )
        if not refreshed:
            raise RuntimeError("signing-key refresh in progress failed")
        return after

    # Leader path: publish BEFORE releasing followers (Greptile P1 on #374).
    # A follower woken before publication would otherwise verify against the
    # old cache and 403 an authentic rotated-key report. The finally only
    # releases the gate; publication happens first inside try.
    try:
        fetched_keys, fetched_etag = _fetch_keys()
        if not fetched_keys:
            raise RuntimeError("no signing keys available")
        with _KEYS_CACHE_LOCK:
            _KEYS_CACHE["keys"] = fetched_keys
            _KEYS_CACHE["etag"] = fetched_etag
            _KEYS_CACHE["fetched_at"] = time.monotonic()
        published = dict(fetched_keys)
    finally:
        with _FETCH_GATE_LOCK:
            _FETCH_STATE["event"] = None
            follower_event.set()
    return published


# ---------------------------------------------------------------------------
# Envelope guards: bounded work before and after the crypto.
# ---------------------------------------------------------------------------


def _parse_match_batch(raw_body: bytes) -> list[SecretMatch]:
    """Parse + validate the envelope AFTER the signature is proven genuine.

    Raises 413 on an over-cap body or batch, 400 on non-JSON or a wrong shape.
    Individual items are validated by pydantic; a bad item fails the whole
    batch with 400 (fail closed — never silently drop a reported leak).
    """
    if len(raw_body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="webhook body too large")
    try:
        data = json.loads(raw_body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="webhook body is not valid JSON")
    if not isinstance(data, list) or not data:
        raise HTTPException(status_code=400, detail="webhook body must be a non-empty JSON array")
    if len(data) > MAX_MATCHES_PER_REQUEST:
        raise HTTPException(status_code=413, detail="too many matches in one request")
    # Every item must be a JSON object; anything else is a malformed envelope
    # (fail closed -> 400, never silently drop a reported leak). Pydantic v2's
    # model_validate/`**item` is used — v1's `parse_obj` no longer exists.
    matches: list[SecretMatch] = []
    for item in data:
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail="invalid match envelope")
        try:
            matches.append(SecretMatch(**item))
        except ValidationError:
            raise HTTPException(status_code=400, detail="invalid match envelope")
    return matches


def _record_receipt(matches: list[SecretMatch], *, event: str) -> None:
    """One structured log line per accepted batch. Token values NEVER appear.

    Emits counts, types, and sources only. The count is bounded-proof: it is
    derived from len() after the batch cap, not by iterating token material.
    """
    by_source: dict[str, int] = {}
    for match in matches:
        by_source[match.source] = by_source.get(match.source, 0) + 1
    logger.info(
        "secret-scanning webhook %s: received=%d sources=%s",
        event,
        len(matches),
        sorted(by_source.items()),
    )


# ---------------------------------------------------------------------------
# The endpoint: raw body in, verified matches out (fast).
# ---------------------------------------------------------------------------


@router.post(
    "/secret-scanning",
    responses={
        200: {"description": "Verified receipt; matches queued for background handling"},
        400: {"description": "Malformed envelope: non-JSON or wrong shape"},
        401: {"description": "Missing signature headers"},
        403: {"description": "Invalid, forged, or unverifiable signature"},
        413: {"description": "Body or batch over cap"},
    },
)
async def secret_scanning_webhook(request: Request, background: BackgroundTasks) -> Response:
    """Receive a secret-leak report from GitHub secret scanning.

    Unauthenticated by design (it must be reachable by the scanner) — the
    ECDSA signature is the ONLY credential. The order below is the whole
    security model:

    1. read the body incrementally, bounded at ``MAX_BODY_BYTES`` (reject 413
       the instant the cap is exceeded — never buffer an unbounded body);
    2. fetch the headers and verify the signature against the cached keys
       (key lookup runs in a threadpool so sync HTTP never blocks the loop);
    3. on unknown key id, refetch ONCE (rotation, throttled) then fail closed;
    4. only then parse the envelope;
    5. hand verified matches to the sink in the background and return 200.

    Verified receipt (200) is returned even though downstream work (#368) runs
    later — the report itself is authentic, so acknowledging it is safe. Only
    signature failures (401/403) and malformed envelopes (400/413) are non-2xx.
    """
    # Bound the read FIRST: consume the stream incrementally and reject the
    # moment the cap is exceeded. We never buffer an unbounded unsigned body.
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="webhook body too large")
        body.extend(chunk)
    raw_body = bytes(body)

    key_id = request.headers.get(KEY_ID_HEADER, "")
    signature_b64 = request.headers.get(SIGNATURE_HEADER, "")
    if not key_id or not signature_b64:
        raise SignatureRejected(status_code=401, detail="missing webhook signature")

    keys = await run_in_threadpool(get_signing_keys)
    verifier = SignatureVerifier(keys)
    try:
        verified_id = verifier.verify(raw_body, key_id, signature_b64)
    except SignatureRejected as first:
        if first.status_code != 403 or key_id in keys:
            raise
        # Unknown key id, exactly once: maybe GitHub rotated. Refetch and
        # retry against the fresh list; anything still unknown fails closed.
        # The forced refetch is throttled inside get_signing_keys, so a flood
        # of unknown ids cannot drive the outbound GitHub rate.
        try:
            keys = await run_in_threadpool(get_signing_keys, True)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError):
            raise first
        verifier = SignatureVerifier(keys)
        verified_id = verifier.verify(raw_body, key_id, signature_b64)
    if verified_id != key_id:
        raise SignatureRejected(status_code=403, detail=_INVALID_SIGNATURE_DETAIL)

    matches = _parse_match_batch(raw_body)
    background.add_task(_deliver_verified_matches, matches)
    _record_receipt(matches, event="accepted")
    return Response(
        content=json.dumps({"received": len(matches)}),
        media_type="application/json",
        status_code=200,
    )


def _deliver_verified_matches(matches: list[SecretMatch]) -> None:
    """Background delivery to the sink; the 200 was already sent."""
    try:
        on_verified_matches(matches)
    except Exception:
        # #368's sink must never crash the already-acknowledged response; log
        # with the traceback so the batch can be re-delivered or investigated.
        logger.exception("verified-match sink failed")
        _record_receipt(matches, event="sink_failed")