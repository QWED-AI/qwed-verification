"""
QWED API Client with Retry Logic and Error Handling
Production-grade client for interacting with QWED verification endpoints.
"""

import requests
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class APIResponse:
    """Structured API response"""
    success: bool
    status_code: int
    data: Dict[Any, Any]
    error: Optional[str] = None
    latency_ms: float = 0.0


class QWEDAPIClient:
    """
    Production QWED API Client with:
    - Automatic retries with exponential backoff
    - Timeout handling
    - Request/response logging
    - Error handling
    """
    
    def __init__(self, base_url: str, api_key: str, timeout: int = 30, max_retries: int = 3):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = {
            "x-api-key": api_key,
            "Content-Type": "application/json"
        }
    
    def _make_request(self, endpoint: str, payload: Dict[Any, Any], retry_count: int = 0) -> APIResponse:
        """Make HTTP request with retry logic"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            start_time = time.time()
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            latency = (time.time() - start_time) * 1000  # Convert to ms
            
            if response.status_code == 200:
                return APIResponse(
                    success=True,
                    status_code=200,
                    data=response.json(),
                    latency_ms=latency
                )
            else:
                # Non-200 status
                error_msg = f"HTTP {response.status_code}: {response.text}"
                logger.warning(f"Request failed: {error_msg}")
                
                # Retry on 5xx errors
                if response.status_code >= 500 and retry_count < self.max_retries:
                    wait_time = 2 ** retry_count  # Exponential backoff
                    logger.info(f"Retrying in {wait_time}s (attempt {retry_count + 1}/{self.max_retries})")
                    time.sleep(wait_time)
                    return self._make_request(endpoint, payload, retry_count + 1)
                
                return APIResponse(
                    success=False,
                    status_code=response.status_code,
                    data={},
                    error=error_msg,
                    latency_ms=latency
                )
        
        except requests.exceptions.Timeout:
            error_msg = f"Request timeout after {self.timeout}s"
            logger.error(error_msg)
            
            if retry_count < self.max_retries:
                wait_time = 2 ** retry_count
                logger.info(f"Retrying after timeout (attempt {retry_count + 1}/{self.max_retries})")
                time.sleep(wait_time)
                return self._make_request(endpoint, payload, retry_count + 1)
            
            return APIResponse(
                success=False,
                status_code=408,
                data={},
                error=error_msg
            )
        
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            logger.error(error_msg)
            
            if retry_count < self.max_retries:
                wait_time = 2 ** retry_count
                logger.info(f"Retrying after connection error (attempt {retry_count + 1}/{self.max_retries})")
                time.sleep(wait_time)
                return self._make_request(endpoint, payload, retry_count + 1)
            
            return APIResponse(
                success=False,
                status_code=0,
                data={},
                error=error_msg
            )
        
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            return APIResponse(
                success=False,
                status_code=0,
                data={},
                error=error_msg
            )
    
    def verify_code(self, code: str, language: str = "python") -> APIResponse:
        """Verify code security"""
        logger.info(f"Verifying {len(code)} characters of {language} code")
        payload = {"code": code, "language": language}
        return self._make_request("/verify/code", payload)
    
    def verify_math(self, expression: str, context: Dict[Any, Any] = None) -> APIResponse:
        """Verify mathematical expression"""
        logger.info(f"Verifying math expression: {expression[:50]}...")
        payload = {"expression": expression, "context": context or {}}
        return self._make_request("/verify/math", payload)
    
    def verify_logic(self, query: str, provider: str = None) -> APIResponse:
        """Verify logical constraints"""
        logger.info(f"Verifying logic query: {query[:50]}...")
        payload = {"query": query, "provider": provider}
        return self._make_request("/verify/logic", payload)
    
    def verify_stats(self, code: str, context: Dict[Any, Any] = None) -> APIResponse:
        """Verify statistical code"""
        logger.info(f"Verifying stats code ({len(code)} chars)")
        payload = {"code": code, "context": context or {}}
        return self._make_request("/verify/stats", payload)
    
    def verify_sql(self, query: str, schema: Dict[Any, Any] = None) -> APIResponse:
        """Verify SQL query"""
        logger.info(f"Verifying SQL query: {query[:50]}...")
        payload = {"query": query, "schema": schema or {}}
        return self._make_request("/verify/sql", payload)
    
    def verify_fact(self, claim: str, context: Dict[Any, Any] = None) -> APIResponse:
        """Verify factual claim"""
        logger.info(f"Verifying fact claim: {claim[:50]}...")
        payload = {"claim": claim, "context": context or {}}
        return self._make_request("/verify/fact", payload)
    
    def verify_image(self, image_data: Any, claim: str, context: Dict[Any, Any] = None) -> APIResponse:
        """Verify image claim"""
        logger.info(f"Verifying image claim: {claim[:50]}...")
        payload = {"image": image_data, "claim": claim, "context": context or {}}
        return self._make_request("/verify/image", payload)
    
    def health_check(self) -> APIResponse:
        """Check if API is healthy"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            return APIResponse(
                success=response.status_code == 200,
                status_code=response.status_code,
                data=response.json() if response.status_code == 200 else {}
            )
        except Exception as e:
            return APIResponse(
                success=False,
                status_code=0,
                data={},
                error=str(e)
            )
