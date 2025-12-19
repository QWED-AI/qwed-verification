"""
QWED SDK - Python Client for the QWED Verification Platform.

Provides both synchronous and asynchronous clients for interacting
with the QWED API.

Usage:
    from qwed_sdk import QWEDClient
    
    # Sync client
    client = QWEDClient(api_key="qwed_...", base_url="http://localhost:8000")
    result = client.verify("What is 2+2?")
    
    # Async client
    async with QWEDAsyncClient(api_key="qwed_...") as client:
        result = await client.verify("Is 2+2=4?")
"""

from qwed_sdk.client import QWEDClient, QWEDAsyncClient
from qwed_sdk.models import (
    VerificationResult,
    BatchResult,
    VerificationType,
)

__version__ = "0.1.0"
__all__ = [
    "QWEDClient",
    "QWEDAsyncClient",
    "VerificationResult",
    "BatchResult",
    "VerificationType",
]
