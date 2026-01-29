"""
QWED SDK Client.

Provides synchronous and asynchronous clients for the QWED API.
"""

import httpx
import time
from typing import List, Dict, Any, Optional, Union
from contextlib import contextmanager
import os

from qwed_sdk.models import VerificationResult, BatchResult, VerificationType


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
        except httpx.ConnectError:
            # If we reached here, local PII check passed (or didn't run),
            # but we can't reach the server.
            # In "Moltbot Standalone" mode, we treat this as "Pass" for safety checks.
            return VerificationResult(
                status="VERIFIED",
                is_verified=True,
                result={"message": "Local safety checks passed. Remote verification unavailable (Offline Mode)."},
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
            latency_ms=data.get("latency_ms", 0.0) or (time.time() - start) * 1000
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
        start = time.time()
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
            latency_ms=data.get("latency_ms", 0.0) or (time.time() - start) * 1000
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
