"""
QWED SDK Client.

Provides synchronous and asynchronous clients for the QWED API.
"""

import asyncio
import functools
import threading
import httpx
import time
from typing import List, Dict, Any, Optional
import os

from qwed_sdk.attestation import (
    DEFAULT_ISSUER,
    JWKS_PATH,
    KeyMismatchError,
    KeysUnavailableError,
    require_answer,
    verify_attestation,
)
from qwed_sdk.models import VerificationResult, BatchResult, token_fields

# How long a fetched JWKS is reused, as the server's Cache-Control says.
_JWKS_MAX_AGE_SECONDS = 300.0
# The least time since the last fetch ended before another: after a token
# none of the cached keys verifies (a key rotation or a restart with a new
# ephemeral key is picked up within this, but a stream of forged tokens
# cannot turn each one into a request), and after a failed fetch, whose
# failure every caller gets meanwhile instead of a request each (#512). It
# counts from the end, so a fetch that is slow to fail is still shared for
# all of it (#513).
_JWKS_MIN_REFRESH_SECONDS = 30.0


def _attestation_of(
    result: VerificationResult | dict[str, Any],
) -> tuple[str | None, str | None]:
    """The token and proof_ref of an answer, typed or as the response dict,
    checked before any key is fetched so a missing one is an
    AttestationError, not a network error."""
    if isinstance(result, VerificationResult):
        token, proof_ref = result.attestation, result.proof_ref
    elif isinstance(result, dict):
        token, proof_ref = result.get("attestation"), result.get("proof_ref")
    else:
        raise TypeError("expected a VerificationResult or a response dict")
    require_answer(token, proof_ref)
    return token, proof_ref


class QWEDClient:
    """
    Synchronous QWED API client.
    
    Example:
        client = QWEDClient(api_key="qwed_...")
        result = client.verify("What is 2+2?")
        print(result.status)  # "VERIFIED"
    """
    
    DEFAULT_TIMEOUT = 60.0
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",
        timeout: float = DEFAULT_TIMEOUT
    ):
        """
        Initialize the QWED client.
        
        Args:
            api_key: Your QWED API key (starts with qwed_)
            base_url: QWED API base URL
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_fetched_at = 0.0
        self._jwks_attempted_at = 0.0
        self._jwks_error: Exception | None = None
        # One fetch at a time: callers that wait reuse what it fetched.
        self._jwks_lock = threading.Lock()

    def _jwks_fresh(self) -> bool:
        return self._jwks is not None and time.monotonic() - self._jwks_fetched_at <= _JWKS_MAX_AGE_SECONDS

    def _raise_recent_failure(self) -> None:
        """Within _JWKS_MIN_REFRESH_SECONDS of a failed fetch, its failure
        again, without a request. Keys past their age are not used instead:
        a key the server has since withdrawn would still verify."""
        if self._jwks_error is not None and \
                time.monotonic() - self._jwks_attempted_at < _JWKS_MIN_REFRESH_SECONDS:
            raise KeysUnavailableError("attestation keys unavailable; the last fetch failed") \
                from self._jwks_error

    def _fetch_jwks(self) -> dict[str, Any]:
        try:
            response = self._client.get(f"{self.base_url}{JWKS_PATH}")
            response.raise_for_status()
            jwks = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            self._jwks_error, self._jwks_attempted_at = exc, time.monotonic()
            raise KeysUnavailableError("attestation keys unavailable") from exc
        self._jwks, self._jwks_error = jwks, None
        self._jwks_fetched_at = self._jwks_attempted_at = time.monotonic()
        return jwks

    def get_jwks(self, refresh: bool = False) -> Dict[str, Any]:
        """The server's attestation keys (GET /.well-known/jwks.json, no API
        key), reused for five minutes as the server's Cache-Control says.
        Raises KeysUnavailableError if they cannot be fetched, and for
        _JWKS_MIN_REFRESH_SECONDS after, unless ``refresh``."""
        if not refresh and self._jwks_fresh():
            return self._jwks
        with self._jwks_lock:
            # Callers that waited get what the fetch before them got.
            if not refresh:
                if self._jwks_fresh():
                    return self._jwks
                self._raise_recent_failure()
            return self._fetch_jwks()

    def _jwks_after_mismatch(self, used: dict[str, Any]) -> dict[str, Any] | None:
        """Keys to try once more after none in ``used`` verified a token:
        those another caller fetched meanwhile, else a fresh fetch if the
        last one ended at least _JWKS_MIN_REFRESH_SECONDS ago. Within that,
        the last fetch's failure if it failed (not a missing key, #513), else
        None."""
        with self._jwks_lock:
            if self._jwks is not None and self._jwks is not used:
                return self._jwks
            if time.monotonic() - self._jwks_attempted_at < _JWKS_MIN_REFRESH_SECONDS:
                self._raise_recent_failure()
                return None
            return self._fetch_jwks()

    def verify_attestation(
        self,
        result: VerificationResult | dict[str, Any],
        query: Optional[str] = None,
        *,
        issuer: str = DEFAULT_ISSUER,
        leeway: int = 0,
    ) -> Dict[str, Any]:
        """Verify an answer's attestation against this server's keys and
        return its claims; raise qwed_sdk.attestation.AttestationError if it
        does not verify or is not this answer's (#319).

        ``query``, when given, must be the statement the verdict covers. To
        verify against keys you pinned, use
        qwed_sdk.attestation.verify_attestation with your JWKS.
        """
        token, proof_ref = _attestation_of(result)
        verify = functools.partial(
            verify_attestation, token, proof_ref=proof_ref, query=query, issuer=issuer, leeway=leeway,
        )
        jwks = self.get_jwks()
        try:
            return verify(jwks)
        except KeyMismatchError:
            # The key may have rotated, or the server restarted with a new
            # key under the same kid, since the JWKS was cached: try the
            # keys once more (see _jwks_after_mismatch).
            newer = self._jwks_after_mismatch(jwks)
            if newer is None:
                raise
            return verify(newer)

    def _headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
    
    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Make an HTTP request to the API."""
        url = f"{self.base_url}{endpoint}"
        response = self._client.request(
            method,
            url,
            headers=self._headers(),
            **kwargs
        )
        response.raise_for_status()
        return response.json()
    
    def health(self) -> Dict[str, Any]:
        """Check API health status."""
        return self._request("GET", "/health")

    def create_verification_context_from_diagnostic(
        self,
        diagnostic: Dict[str, Any],
        query: str,
        verifier: str,
        verifier_version: Optional[str] = None,
        attestation_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a schema-valid Verification Context from a DiagnosticResult.

        The server records the diagnostic without vouching for it: the
        message and developer fields are kept under
        ``developer_fields.caller_supplied`` and the admission is always DENY.
        """
        return self._request(
            "POST",
            "/verification-context/from-diagnostic",
            json={
                "diagnostic": diagnostic,
                "query": query,
                "verifier": verifier,
                "verifier_version": verifier_version,
                "attestation_token": attestation_token,
            },
        )

    def validate_verification_context(self, document: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a Verification Context document against the v1.0 schema."""
        return self._request(
            "POST",
            "/verification-context/validate",
            json={"document": document},
        )

    def resolve_verification_context(self, document: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve the proof_ref commitment for a Verification Context document."""
        return self._request(
            "POST",
            "/verification-context/resolve",
            json={"document": document},
        )

    def verify(
        self,
        query: str,
        provider: Optional[str] = None
    ) -> VerificationResult:
        """
        Verify a natural language math query.
        
        Args:
            query: The query to verify (e.g., "What is 2+2?")
            provider: Optional LLM provider preference
            
        Returns:
            VerificationResult with status and details
        """
        start = time.time()
        data = self._request(
            "POST",
            "/verify/natural_language",
            json={"query": query, "provider": provider}
        )
        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)
    
    def verify_logic(self, query: str) -> VerificationResult:
        """Verify a logic puzzle."""
        start = time.time()
        data = self._request(
            "POST",
            "/verify/logic",
            json={"query": query}
        )
        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)
    
    def verify_math(self, expression: str) -> VerificationResult:
        """Verify a mathematical expression."""
        start = time.time()
        data = self._request(
            "POST",
            "/verify/math",
            json={"expression": expression}
        )
        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)
    
    def verify_code(
        self,
        code: str,
        language: str = "python"
    ) -> VerificationResult:
        """Verify code for security vulnerabilities."""
        start = time.time()
        # Try local execution first (Technical Safety - Phase 12)
        try:
            from qwed_new.guards.code_guard import CodeGuard
            guard = CodeGuard()
            result_dict = guard.verify_safety(code, language=language)
            
            result = VerificationResult(
                status="VERIFIED" if result_dict["verified"] else "UNVERIFIED",
                is_verified=result_dict["verified"],
                result=result_dict,
                latency_ms=(time.time() - start) * 1000
            )
            return result
        except ImportError:
            # Fallback to API
            data = self._request(
                "POST",
                "/verify/code",
                json={"code": code, "language": language}
            )
            data["latency_ms"] = (time.time() - start) * 1000
            return VerificationResult.from_dict(data)
    
    def verify_fact(
        self,
        claim: str,
        context: str
    ) -> VerificationResult:
        """Verify a factual claim against context."""
        start = time.time()
        
        # Try local PII scanning first (Privacy Safety - Mode B)
        try:
            from qwed_new.guards.pii_guard import PIIGuard
            guard = PIIGuard()
            # Treat the 'claim' (response) as the content to scan for leaks
            pii_result = guard.scan(claim)
            
            if not pii_result["verified"]:
                # PII Detected locally - Return immediately
                return VerificationResult(
                    status="UNVERIFIED",
                    is_verified=False,
                    result=pii_result,
                    latency_ms=(time.time() - start) * 1000
                )
        except ImportError:
            pass # Fallback to remote if local guard missing

        try:
            # Remote verification (if no local PII or Guard missing)
            data = self._request(
                "POST",
                "/verify/fact",
                json={"claim": claim, "context": context}
            )
            data["latency_ms"] = (time.time() - start) * 1000
            return VerificationResult.from_dict(data)
        except (httpx.ConnectError, httpx.TimeoutException):
            # The local PII check passed (or didn't run), but the verification
            # service could not be reached or did not respond in time, so the
            # deterministic fact check never completed. Absence of verification
            # must never read as success (#326): QWED fails closed, so this is
            # UNVERIFIABLE, not VERIFIED. The local PII scan covers one guard,
            # not the fact verification.
            return VerificationResult(
                status="UNVERIFIABLE",
                is_verified=False,
                result={"message": "Remote verification unavailable; the local PII check is not a fact check. Result is UNVERIFIABLE."},
                latency_ms=(time.time() - start) * 1000
            )
    
    def verify_sql(
        self,
        query: str,
        schema_ddl: str = "",
        dialect: str = "sqlite"
    ) -> VerificationResult:
        """Verify SQL query against schema."""
        start = time.time()
        # Try local execution first (Technical Safety - Phase 12)
        try:
            from qwed_new.guards.sql_guard import SQLGuard
            # Note: SQLGuard in client ignores schema/dialect for deep checks in this simple integration
            # but we can pass dialect if needed.
            guard = SQLGuard() 
            result_dict = guard.verify_query(query, dialect)
            
            result = VerificationResult(
                status="VERIFIED" if result_dict["verified"] else "UNVERIFIED",
                is_verified=result_dict["verified"],
                result=result_dict,
                latency_ms=(time.time() - start) * 1000
            )
            return result
        except ImportError:
            data = self._request(
                "POST",
                "/verify/sql",
                json={"query": query, "schema_ddl": schema_ddl, "dialect": dialect}
            )
            data["latency_ms"] = (time.time() - start) * 1000
            return VerificationResult.from_dict(data)

    def verify_stats(
        self,
        query: str,
        file_path: str
    ) -> VerificationResult:
        """
        Verify statistical claims about uploaded data.

        Args:
            query: The question or claim to verify
            file_path: Path to the CSV file
        """
        start = time.time()
        url = f"{self.base_url}/verify/stats"

        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            # Do not use _request here because it sets Content-Type to JSON
            response = self._client.post(
                url,
                headers={"X-API-Key": self.api_key},
                data={"query": query},
                files=files
            )
            response.raise_for_status()
            data = response.json()

        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)

    def verify_consensus(
        self,
        query: str,
        mode: str = "single",
        min_confidence: float = 0.95
    ) -> VerificationResult:
        """
        Verify with multi-engine consensus.

        Args:
            query: The query to verify
            mode: Verification mode ("single", "high", "maximum")
            min_confidence: Minimum confidence threshold (0.0 to 1.0)
        """
        start = time.time()
        data = self._request(
            "POST",
            "/verify/consensus",
            json={
                "query": query,
                "verification_mode": mode,
                "min_confidence": min_confidence
            }
        )
        data["latency_ms"] = (time.time() - start) * 1000
        # The API returns a structure that VerificationResult.from_dict can handle
        # provided we treat the response as the "result" dictionary or map fields.
        # The API returns: { "final_answer": ..., "confidence": ..., "verification_chain": ... }
        # We wrap this in a VerificationResult.

        return VerificationResult(
            status="VERIFIED" if data.get("meets_requirement", False) else "UNVERIFIED",
            is_verified=data.get("meets_requirement", False),
            result=data,
            latency_ms=data.get("latency_ms", 0.0) or (time.time() - start) * 1000,
            # So verify_attestation works on a consensus answer too (#319).
            **token_fields(data),
        )
    
    def verify_image(
        self,
        image_path: str,
        claim: str
    ) -> VerificationResult:
        """
        Verify a claim against an image.
        
        Args:
            image_path: Path to the image file
            claim: The claim to verify (e.g., "The image is 800x600 pixels")
            
        Returns:
            VerificationResult with verdict and confidence
        """
        start = time.time()
        
        with open(image_path, "rb") as f:
            files = {"image": (image_path, f, "application/octet-stream")}
            data = {"claim": claim}
            
            url = f"{self.base_url}/verify/image"
            response = self._client.post(
                url,
                headers={"X-API-Key": self.api_key},
                files=files,
                data=data
            )
            response.raise_for_status()
            result = response.json()
        
        result["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(result)
    
    def verify_batch(
        self,
        items: List[Dict[str, Any]]
    ) -> BatchResult:
        """
        Submit a batch of verification requests.
        
        Args:
            items: List of verification items, each with:
                   - query: str
                   - type: str (optional, default: "natural_language")
                   - params: dict (optional)
                   
        Returns:
            BatchResult with all item results
        """
        data = self._request(
            "POST",
            "/verify/batch",
            json={"items": items}
        )
        return BatchResult.from_dict(data)
    
    def get_batch_status(self, job_id: str) -> BatchResult:
        """Get status of a batch job."""
        data = self._request("GET", f"/verify/batch/{job_id}")
        return BatchResult.from_dict(data)
    
    def close(self):
        """Close the HTTP client."""
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


class QWEDAsyncClient:
    """
    Asynchronous QWED API client.
    
    Example:
        async with QWEDAsyncClient(api_key="qwed_...") as client:
            result = await client.verify("What is 2+2?")
            print(result.status)
    """
    
    DEFAULT_TIMEOUT = 60.0
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",
        timeout: float = DEFAULT_TIMEOUT
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_fetched_at = 0.0
        self._jwks_attempted_at = 0.0
        self._jwks_error: Exception | None = None
        # One fetch at a time: callers that wait reuse what it fetched.
        self._jwks_lock = asyncio.Lock()

    def _jwks_fresh(self) -> bool:
        return self._jwks is not None and time.monotonic() - self._jwks_fetched_at <= _JWKS_MAX_AGE_SECONDS

    def _raise_recent_failure(self) -> None:
        """Within _JWKS_MIN_REFRESH_SECONDS of a failed fetch, its failure
        again, without a request. Keys past their age are not used instead:
        a key the server has since withdrawn would still verify."""
        if self._jwks_error is not None and \
                time.monotonic() - self._jwks_attempted_at < _JWKS_MIN_REFRESH_SECONDS:
            raise KeysUnavailableError("attestation keys unavailable; the last fetch failed") \
                from self._jwks_error

    async def _fetch_jwks(self) -> dict[str, Any]:
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")
        # Recorded when the fetch ends; a cancelled task records nothing.
        try:
            response = await self._client.get(f"{self.base_url}{JWKS_PATH}")
            response.raise_for_status()
            jwks = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            self._jwks_error, self._jwks_attempted_at = exc, time.monotonic()
            raise KeysUnavailableError("attestation keys unavailable") from exc
        self._jwks, self._jwks_error = jwks, None
        self._jwks_fetched_at = self._jwks_attempted_at = time.monotonic()
        return jwks

    async def get_jwks(self, refresh: bool = False) -> Dict[str, Any]:
        """The server's attestation keys; see QWEDClient.get_jwks."""
        if not refresh and self._jwks_fresh():
            return self._jwks
        async with self._jwks_lock:
            if not refresh:
                if self._jwks_fresh():
                    return self._jwks
                self._raise_recent_failure()
            return await self._fetch_jwks()

    async def _jwks_after_mismatch(self, used: dict[str, Any]) -> dict[str, Any] | None:
        """See QWEDClient._jwks_after_mismatch."""
        async with self._jwks_lock:
            if self._jwks is not None and self._jwks is not used:
                return self._jwks
            if time.monotonic() - self._jwks_attempted_at < _JWKS_MIN_REFRESH_SECONDS:
                self._raise_recent_failure()
                return None
            return await self._fetch_jwks()

    async def verify_attestation(
        self,
        result: VerificationResult | dict[str, Any],
        query: Optional[str] = None,
        *,
        issuer: str = DEFAULT_ISSUER,
        leeway: int = 0,
    ) -> Dict[str, Any]:
        """Verify an answer's attestation; see QWEDClient.verify_attestation."""
        token, proof_ref = _attestation_of(result)
        verify = functools.partial(
            verify_attestation, token, proof_ref=proof_ref, query=query, issuer=issuer, leeway=leeway,
        )
        jwks = await self.get_jwks()
        try:
            return verify(jwks)
        except KeyMismatchError:
            newer = await self._jwks_after_mismatch(jwks)
            if newer is None:
                raise
            return verify(newer)

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=self.timeout)
        return self
    
    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
    
    def _headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")
        
        url = f"{self.base_url}{endpoint}"
        response = await self._client.request(
            method,
            url,
            headers=self._headers(),
            **kwargs
        )
        response.raise_for_status()
        return response.json()
    
    async def health(self) -> Dict[str, Any]:
        """Check API health status."""
        return await self._request("GET", "/health")

    async def create_verification_context_from_diagnostic(
        self,
        diagnostic: Dict[str, Any],
        query: str,
        verifier: str,
        verifier_version: Optional[str] = None,
        attestation_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a schema-valid Verification Context from a DiagnosticResult.

        The server records the diagnostic without vouching for it: the
        message and developer fields are kept under
        ``developer_fields.caller_supplied`` and the admission is always DENY.
        """
        return await self._request(
            "POST",
            "/verification-context/from-diagnostic",
            json={
                "diagnostic": diagnostic,
                "query": query,
                "verifier": verifier,
                "verifier_version": verifier_version,
                "attestation_token": attestation_token,
            },
        )

    async def validate_verification_context(self, document: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a Verification Context document against the v1.0 schema."""
        return await self._request(
            "POST",
            "/verification-context/validate",
            json={"document": document},
        )

    async def resolve_verification_context(self, document: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve the proof_ref commitment for a Verification Context document."""
        return await self._request(
            "POST",
            "/verification-context/resolve",
            json={"document": document},
        )

    async def verify(
        self,
        query: str,
        provider: Optional[str] = None
    ) -> VerificationResult:
        """Verify a natural language math query."""
        start = time.time()
        data = await self._request(
            "POST",
            "/verify/natural_language",
            json={"query": query, "provider": provider}
        )
        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)
    
    async def verify_logic(self, query: str) -> VerificationResult:
        """Verify a logic puzzle."""
        start = time.time()
        data = await self._request(
            "POST",
            "/verify/logic",
            json={"query": query}
        )
        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)
    
    async def verify_math(self, expression: str) -> VerificationResult:
        """Verify a mathematical expression."""
        start = time.time()
        data = await self._request(
            "POST",
            "/verify/math",
            json={"expression": expression}
        )
        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)
    
    async def verify_code(
        self,
        code: str,
        language: str = "python"
    ) -> VerificationResult:
        """Verify code for security vulnerabilities."""
        start = time.time()
        data = await self._request(
            "POST",
            "/verify/code",
            json={"code": code, "language": language}
        )
        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)
    
    async def verify_stats(
        self,
        query: str,
        file_path: str
    ) -> VerificationResult:
        """Verify statistical claims about uploaded data."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")

        start = time.time()
        url = f"{self.base_url}/verify/stats"

        # Async file upload logic
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = await self._client.post(
                url,
                headers={"X-API-Key": self.api_key},
                data={"query": query},
                files=files
            )
            response.raise_for_status()
            data = response.json()

        data["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(data)

    async def verify_consensus(
        self,
        query: str,
        mode: str = "single",
        min_confidence: float = 0.95
    ) -> VerificationResult:
        """Verify with multi-engine consensus."""
        start = time.time()
        data = await self._request(
            "POST",
            "/verify/consensus",
            json={
                "query": query,
                "verification_mode": mode,
                "min_confidence": min_confidence
            }
        )

        return VerificationResult(
            status="VERIFIED" if data.get("meets_requirement", False) else "UNVERIFIED",
            is_verified=data.get("meets_requirement", False),
            result=data,
            latency_ms=data.get("latency_ms", 0.0) or (time.time() - start) * 1000,
            # So verify_attestation works on a consensus answer too (#319).
            **token_fields(data),
        )

    async def verify_image(
        self,
        image_path: str,
        claim: str
    ) -> VerificationResult:
        """
        Verify a claim against an image.
        
        Args:
            image_path: Path to the image file
            claim: The claim to verify
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")
        
        start = time.time()
        
        with open(image_path, "rb") as f:
            files = {"image": (image_path, f, "application/octet-stream")}
            data = {"claim": claim}
            
            url = f"{self.base_url}/verify/image"
            response = await self._client.post(
                url,
                headers={"X-API-Key": self.api_key},
                files=files,
                data=data
            )
            response.raise_for_status()
            result = response.json()
        
        result["latency_ms"] = (time.time() - start) * 1000
        return VerificationResult.from_dict(result)
    
    async def verify_batch(
        self,
        items: List[Dict[str, Any]]
    ) -> BatchResult:
        """Submit a batch of verification requests."""
        data = await self._request(
            "POST",
            "/verify/batch",
            json={"items": items}
        )
        return BatchResult.from_dict(data)
    
    async def get_batch_status(self, job_id: str) -> BatchResult:
        """Get status of a batch job."""
        data = await self._request("GET", f"/verify/batch/{job_id}")
        return BatchResult.from_dict(data)
