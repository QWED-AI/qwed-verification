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
import binascii
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

#: How long cached signing keys are trusted before a background refresh.
KEYS_CACHE_TTL_SECONDS = 6 * 60 * 60  # 6h

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


#: P-256 group order — the hard boundary of the allowed curve.
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


class SignatureVerifier:
    """ECDSA-NIST-P256V1-SHA256 over the raw body, checked against known keys."""

    def __init__(self, keys: dict[str, str]) -> None:
        self._pubkeys: dict[str, Any] = {}
        for key_id, pem in keys.items():
            self._pubkeys[key_id] = self._parse_key(pem)

    # -- public API ------------------------------------------------------

    def verify(self, raw_body: bytes, key_id: str, signature_b64: str) -> str:
        """Return ``key_id`` iff the signature is valid; raise otherwise.

        The signature covers the RAW body bytes. Every failure mode — missing
        or malformed pieces, unknown key, bad DER, non-P-256 key, invalid
        signature — raises the same ``SignatureRejected(403)`` with a generic
        detail, so nothing about which step failed is observable.
        """
        public_key = self._pubkeys.get(key_id)
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError):
            signature = b""
        if public_key is None or not signature:
            raise SignatureRejected(status_code=403, detail="invalid webhook signature")

        try:
            candidate = public_key.verify(signature, raw_body, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            candidate = False
        except (ValueError, TypeError):
            raise SignatureRejected(status_code=403, detail="invalid webhook signature")

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
            raise SignatureRejected(status_code=403, detail="invalid webhook signature")
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise SignatureRejected(status_code=403, detail="invalid webhook signature")
        if not isinstance(key.curve, ec.SECP256R1):
            raise SignatureRejected(status_code=403, detail="invalid webhook signature")
        numbers = key.public_numbers()
        if not (1 <= numbers.x < _P256_ORDER and 1 <= numbers.y < _P256_ORDER):
            raise SignatureRejected(status_code=403, detail="invalid webhook signature")
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
        raise SignatureRejected(status_code=403, detail="invalid webhook signature")


def _expected_verdict_bytes() -> bytes:
    """The canonical success verdict; split out so the compare is explicit."""
    return b"verdict:1"


# ---------------------------------------------------------------------------
# Signing-key cache: fetch once, reuse offline, refetch on rotation.
# ---------------------------------------------------------------------------

#: Process-wide cache. Keys are trusted material but not secrets — the shape
#: is {"keys": {key_id: pem}, "etag": str|None, "fetched_at": epoch}.
#: A lock serializes refetches so concurrent webhooks don't stampede GitHub.
_KEYS_CACHE: dict[str, Any] = {"keys": {}, "etag": None, "fetched_at": 0.0}
_KEYS_CACHE_LOCK = threading.Lock()


def _signing_key_token() -> str | None:
    """Optional PAT for the keys endpoint (rate-limit hygiene only)."""
    return os.getenv("GITHUB_KEYS_TOKEN") or os.getenv("GITHUB_TOKEN")


def _fetch_keys() -> tuple[dict[str, str], str | None]:
    """Fetch the signing-key list; returns (keys, etag).

    Uses a conditional request: a ``304 Not Modified`` keeps the cached keys
    untouched (and — since nothing changed — needs no new trust decision).
    Any transport-level or shape problem raises; the caller decides whether
    cached keys are still usable.
    """
    headers = {"Accept": "application/vnd.github+json"}
    cached_etag = _KEYS_CACHE.get("etag")
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
        return dict(_KEYS_CACHE.get("keys", {})), cached_etag
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

    A failed refresh never empties the cache: stale keys keep verifying
    already-issued signatures until the TTL plus a grace window passes; only
    then do we fail closed. GitHub rotates by ADDING the new key alongside the
    old one, so a short staleness window never rejects legitimate traffic.
    """
    now = time.monotonic()
    with _KEYS_CACHE_LOCK:
        cached = dict(_KEYS_CACHE.get("keys", {}))
        fresh = bool(cached) and (now - float(_KEYS_CACHE.get("fetched_at", 0.0)) < KEYS_CACHE_TTL_SECONDS)
        if fresh and not force_refresh:
            return cached
        try:
            keys, etag = _fetch_keys()
        except (httpx.HTTPError, OSError, RuntimeError, ValueError):
            if cached:
                logger.warning("using stale signing keys after failed refresh")
                return cached
            raise
        if keys:
            _KEYS_CACHE["keys"] = keys
            _KEYS_CACHE["etag"] = etag
            _KEYS_CACHE["fetched_at"] = now
            return dict(keys)
        if cached:
            return cached
        raise RuntimeError("no signing keys available")


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
    try:
        return [SecretMatch(**item) if isinstance(item, dict) else SecretMatch.parse_obj(item) for item in data]
    except (ValidationError, TypeError):
        raise HTTPException(status_code=400, detail="invalid match envelope")


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


@router.post("/secret-scanning")
async def secret_scanning_webhook(request: Request, background: BackgroundTasks) -> Response:
    """Receive a secret-leak report from GitHub secret scanning.

    Unauthenticated by design (it must be reachable by the scanner) — the
    ECDSA signature is the ONLY credential. The order below is the whole
    security model:

    1. read the RAW body bytes (never parse-then-reserialize);
    2. fetch the headers and verify the signature against the cached keys;
    3. on unknown key id, refetch ONCE (rotation) then fail closed;
    4. only then parse the envelope;
    5. hand verified matches to the sink in the background and return 200.

    Verified receipt (200) is returned even though downstream work (#368) runs
    later — the report itself is authentic, so acknowledging it is safe. Only
    signature failures (401/403) and malformed envelopes (400/413) are non-2xx.
    """
    raw_body = await request.body()
    key_id = request.headers.get(KEY_ID_HEADER, "")
    signature_b64 = request.headers.get(SIGNATURE_HEADER, "")
    if not key_id or not signature_b64:
        raise SignatureRejected(status_code=401, detail="missing webhook signature")

    keys = get_signing_keys()
    verifier = SignatureVerifier(keys)
    try:
        verified_id = verifier.verify(raw_body, key_id, signature_b64)
    except SignatureRejected as first:
        if first.status_code != 403 or key_id in keys:
            raise
        # Unknown key id, exactly once: maybe GitHub rotated. Refetch and
        # retry against the fresh list; anything still unknown fails closed.
        try:
            keys = get_signing_keys(force_refresh=True)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError):
            raise first
        verifier = SignatureVerifier(keys)
        verified_id = verifier.verify(raw_body, key_id, signature_b64)
    if verified_id != key_id:
        raise SignatureRejected(status_code=403, detail="invalid webhook signature")

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