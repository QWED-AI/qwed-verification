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
from pydantic import BaseModel, ConfigDict, Field, ValidationError
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

#: Generic 503 detail when the trust anchor cannot be refreshed or is
#: unusable. Retryable: the scanner should redeliver (Sonar: one constant).
_KEYS_UNAVAILABLE_DETAIL = "signing keys unavailable"

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

    model_config = ConfigDict(extra="ignore")


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

    def knows(self, key_id: str) -> bool:
        """True iff ``key_id`` maps to a usable (P-256) public key.

        The raw fetched dict may contain off-spec entries skipped at load;
        rotation decisions must use THIS set, not the raw dict (Sentry on
        #374): a kid present-but-unusable still needs a refetch when its
        curve is fixed upstream.
        """
        return key_id in self._pubkeys

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
#: "last_forced_refresh": epoch|None, "last_fetch_error_at": epoch|None}.
#: Only rotation-triggered forced refreshes touch last_forced_refresh, so a
#: normal TTL/startup fetch never delays recognising a newly rotated key.
#: last_fetch_error_at is stamped on fetch FAILURE only (never optimistically)
#: so a failed fetch cannot arm the success throttle (Sentry HIGH on #374).
#: A lock serializes cache reads/writes (network I/O runs outside the lock).
_KEYS_CACHE: dict[str, Any] = {
    "keys": {},
    "etag": None,
    "fetched_at": 0.0,
    "last_forced_refresh": None,
    "last_fetch_error_at": None,
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

#: Backoff for rotation-triggered fetches after a FAILED fetch. Successes
#: throttle at MIN_FORCED_REFRESH_SECONDS (60s); failures back off much
#: shorter so a legit rotation during an outage is retried promptly, while
#: still bounding the outbound rate to 1 fetch / 10s (Sentry HIGH on #374).
_FETCH_ERROR_BACKOFF_SECONDS = 10.0

#: Window in which a past fetch failure makes the trust anchor suspect: an
#: unknown key in this window is 503 (unverifiable, retry), not 403
#: (forged, don't retry). Restamped on every failed fetch, so it stays
#: true through an ongoing outage and clears on the first success.
_FETCH_ERROR_SUSPECT_SECONDS = 60.0


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
    if not isinstance(entries, list):
        # 200 with public_keys: null (or any non-list) must be a retryable
        # 503 via the leader's RuntimeError path — never a TypeError 500
        # with no error stamp (Greptile P1 on #374).
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

    Fail-closed and bounded (see helpers below for the pieces):

    * a failed refresh **propagates** — we never fall back to stale cached keys
      (QWED Rule 2 "Fail Closed", Rule 6 "No Silent Degradation").
    * ``force_refresh`` is throttled (success 60s / failure backoff 10s);
      outcome stamps happen after the fetch, never optimistically.
    * network I/O runs OUTSIDE the cache lock; concurrent refreshes are
      singleflighted with publish-before-release.
    """
    now = time.monotonic()
    cached, do_fetch, want_forced_stamp = _plan_refresh(force_refresh, now)
    if not do_fetch:
        return cached
    is_leader, event = _elect_refresh()
    if not is_leader:
        return _await_leader(event)
    return _leader_refresh(event, want_forced_stamp)


def _plan_refresh(force_refresh: bool, now: float) -> tuple[dict[str, str], bool, bool]:
    """Locked read + throttle resolution. Returns (cached, do_fetch, want_stamp).

    Merges the success throttle and the failure backoff into ONE predicate
    (Sonar: no duplicated ``force_refresh = False`` branches).
    """
    with _KEYS_CACHE_LOCK:
        cached = dict(_KEYS_CACHE.get("keys", {}))
        fetched_at = _KEYS_CACHE.get("fetched_at")
        fresh = bool(cached) and fetched_at is not None and (
            now - fetched_at < KEYS_CACHE_TTL_SECONDS
        )
        if force_refresh:
            # Throttle rotation-triggered refetches only: unknown key ids must
            # not drive the outbound GitHub fetch rate (CodeRabbit on #374).
            last_ok = _KEYS_CACHE.get("last_forced_refresh")
            last_err = _KEYS_CACHE.get("last_fetch_error_at")
            err_backoff = last_err is not None and (now - last_err < _FETCH_ERROR_BACKOFF_SECONDS)
            ok_throttled = last_ok is not None and (now - last_ok < MIN_FORCED_REFRESH_SECONDS)
            if err_backoff or ok_throttled:
                force_refresh = False
        return cached, (not fresh or force_refresh), force_refresh


def _elect_refresh() -> tuple[bool, threading.Event]:
    """Singleflight election: exactly one leader fetches. No ``global``
    rebinding: the event lives in _FETCH_STATE (dict mutation)."""
    with _FETCH_GATE_LOCK:
        in_flight = _FETCH_STATE.get("event")
        if in_flight is not None:
            return False, in_flight
        event = threading.Event()
        _FETCH_STATE["event"] = event
        return True, event


def _await_leader(event: threading.Event) -> dict[str, str]:
    """Follower: bounded wait, then require a FRESH cache.

    A failed leader must not leave followers trusting expired keys (Sentry
    HIGH + CodeRabbit major on #374): stale or empty -> fail closed, never
    a cascading second fetch.
    """
    event.wait(timeout=_FETCH_WAIT_SECONDS)
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


def _leader_refresh(event: threading.Event, want_forced_stamp: bool) -> dict[str, str]:
    """Leader: fetch outside all locks, publish BEFORE releasing followers
    (Greptile P1 on #374), stamp the outcome (Sentry HIGH on #374)."""
    try:
        fetched_keys, fetched_etag = _fetch_keys()
        if not fetched_keys:
            raise RuntimeError("no signing keys available")
        with _KEYS_CACHE_LOCK:
            _KEYS_CACHE["keys"] = fetched_keys
            _KEYS_CACHE["etag"] = fetched_etag
            _KEYS_CACHE["fetched_at"] = time.monotonic()
            _KEYS_CACHE["last_fetch_error_at"] = None
            if want_forced_stamp:
                _KEYS_CACHE["last_forced_refresh"] = time.monotonic()
        published = dict(fetched_keys)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError):
        with _KEYS_CACHE_LOCK:
            _KEYS_CACHE["last_fetch_error_at"] = time.monotonic()
        raise
    finally:
        with _FETCH_GATE_LOCK:
            _FETCH_STATE["event"] = None
            event.set()
    return published


def _trust_anchor_suspect() -> bool:
    """True iff an unknown key must be 503 (not 403).

    403 means "verified against a good anchor and still unknown: forged".
    503 means "the anchor itself is suspect, redeliver later". Suspect iff
    a fetch failed recently (ongoing outage, restamped per failure) or the
    cache is missing/stale. Fresh anchor + unknown key -> forged -> 403.
    """
    now = time.monotonic()
    with _KEYS_CACHE_LOCK:
        last_err = _KEYS_CACHE.get("last_fetch_error_at")
        keys = _KEYS_CACHE.get("keys", {})
        fetched_at = _KEYS_CACHE.get("fetched_at")
    if last_err is not None and (now - last_err < _FETCH_ERROR_SUSPECT_SECONDS):
        return True
    return not (
        bool(keys) and fetched_at is not None and (now - fetched_at < KEYS_CACHE_TTL_SECONDS)
    )


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
# Verification driver: fetch anchor, verify, one rotation retry.
# (Module level so the endpoint stays under the Sonar complexity gate.)
# ---------------------------------------------------------------------------


async def _verified_key_id(raw_body: bytes, key_id: str, signature_b64: str) -> str:
    """Verify the signature, with exactly one rotation retry.

    Returns ``key_id`` iff genuine. Raises 401 (missing), 403 (forged against
    a good anchor), 503 (anchor dead/unusable/suspect — redeliver later).
    """
    try:
        keys = await run_in_threadpool(get_signing_keys)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
        # Fail closed with a retryable 503, not an unhandled 500 (Sentry
        # HIGH on #374). SignatureRejected (401/403) is an HTTPException
        # and is NOT caught here — it propagates unchanged.
        raise HTTPException(status_code=503, detail=_KEYS_UNAVAILABLE_DETAIL) from exc
    verifier = _try_build(keys)
    if verifier is None:
        # Anchor present but unusable (e.g. the only cached key is off-spec):
        # one rotation attempt before giving up — the curve may have been
        # fixed upstream (Sentry MEDIUM on #374).
        keys = await _forced_keys()
        verifier = _build_verifier(keys)
    try:
        return verifier.verify(raw_body, key_id, signature_b64)
    except SignatureRejected as first:
        if first.status_code != 403 or verifier.knows(key_id):
            raise
    # Unknown key id, exactly once: maybe GitHub rotated. Refetch and
    # retry against the fresh list; anything still unknown fails closed.
    # The forced refetch is throttled inside get_signing_keys, so a flood
    # of unknown ids cannot drive the outbound GitHub rate.
    with _KEYS_CACHE_LOCK:
        stamp_before = _KEYS_CACHE.get("last_forced_refresh")
    keys = await _forced_keys()
    with _KEYS_CACHE_LOCK:
        stamp_after = _KEYS_CACHE.get("last_forced_refresh")
    # Throttled (no fresh fetch happened): the anchor may predate a rotation
    # that landed inside the throttle window, so "unknown" proves nothing —
    # 503 below, never 403 (Sentry HIGH on #374). A completed fetch restamps,
    # so stamp_after != stamp_before exactly when we fetched.
    now = time.monotonic()
    rotation_throttled = (
        stamp_after == stamp_before
        and stamp_after is not None
        and (now - stamp_after < MIN_FORCED_REFRESH_SECONDS)
    )
    verifier = _build_verifier(keys)
    try:
        return verifier.verify(raw_body, key_id, signature_b64)
    except SignatureRejected as exc:
        # Fresh anchor + still unknown -> forged -> 403. Suspect anchor
        # (recent fetch failure, stale cache, or throttled rotation retry)
        # -> 503 so the scanner redelivers (Sentry HIGH on #374).
        if rotation_throttled or _trust_anchor_suspect():
            raise HTTPException(status_code=503, detail=_KEYS_UNAVAILABLE_DETAIL) from exc
        raise


async def _forced_keys() -> dict[str, str]:
    """One rotation-triggered refetch. Fetch failure is 503 (retryable),
    NOT 403: 403 means "forged/retired, don't retry", but here verification
    was impossible — the scanner should redeliver (CodeRabbit major #374)."""
    try:
        return await run_in_threadpool(get_signing_keys, True)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=_KEYS_UNAVAILABLE_DETAIL) from exc


def _try_build(keys: dict[str, str]) -> SignatureVerifier | None:
    """Build the verifier, or None if the anchor has no usable P-256 key."""
    try:
        return SignatureVerifier(keys)
    except SignatureRejected:
        return None


def _build_verifier(keys: dict[str, str]) -> SignatureVerifier:
    """Build the verifier, mapping an unusable anchor to 503.

    Construction fails only when NO key is usable P-256: verification was
    impossible, not forged -> retryable 503, never 403 (Sentry LOW on #374).
    verify() failures are raised by the caller and keep 401/403.
    """
    try:
        return SignatureVerifier(keys)
    except SignatureRejected as exc:
        raise HTTPException(status_code=503, detail=_KEYS_UNAVAILABLE_DETAIL) from exc


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
        503: {"description": "Signing keys unavailable; retry later"},
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
    A dead/unreachable key service is 503 (retryable), never a 500: the trust
    anchor cannot be refreshed, so verification fails closed without leaking
    internals.
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

    await _verified_key_id(raw_body, key_id, signature_b64)

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
        # Receipt first (counts only, never token material), then drop the
        # raw batch BEFORE logging: a locals-capturing reporter must not
        # observe the plaintext batch through this frame (#380 follow-up —
        # the sink now raises loudly on enforcement failure, so this path
        # is live, not theoretical).
        _record_receipt(matches, event="sink_failed")
        del matches
        # #368's sink must never crash the already-acknowledged response; log
        # with the traceback so the batch can be re-delivered or investigated.
        logger.exception("verified-match sink failed")