# Copyright (c) 2024 QWED Team
# SPDX-License-Identifier: Apache-2.0

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

Framework Integrations:
    # LangChain
    from qwed_sdk.langchain import QWEDTool, QWEDVerificationCallback
    
    # LlamaIndex
    from qwed_sdk.llamaindex import QWEDQueryEngine, QWEDVerificationTransform
    
    # CrewAI
    from qwed_sdk.crewai import QWEDVerifiedAgent, QWEDVerificationTool
"""

from qwed_sdk.client import QWEDClient, QWEDAsyncClient
from qwed_sdk.qwed_local import QWEDLocal  # NEW!
from qwed_sdk.models import (
    VerificationResult,
    BatchResult,
    VerificationType,
)

__version__ = "2.1.0-dev"
__all__ = [
    "QWEDClient",
    "QWEDAsyncClient",
    "QWEDLocal",  # NEW!
    "VerificationResult",
    "BatchResult",
    "VerificationType",
]

# Optional framework integrations (lazy imports)
def get_langchain_tools():
    """Get LangChain integration classes."""
    from qwed_sdk.langchain import (
        QWEDTool, QWEDMathTool, QWEDLogicTool, QWEDCodeTool,
        QWEDVerificationCallback, QWEDVerifiedChain
    )
    return {
        "QWEDTool": QWEDTool,
        "QWEDMathTool": QWEDMathTool,
        "QWEDLogicTool": QWEDLogicTool,
        "QWEDCodeTool": QWEDCodeTool,
        "QWEDVerificationCallback": QWEDVerificationCallback,
        "QWEDVerifiedChain": QWEDVerifiedChain,
    }

def get_llamaindex_tools():
    """Get LlamaIndex integration classes."""
    from qwed_sdk.llamaindex import (
        QWEDQueryEngine, QWEDVerificationTransform,
        QWEDCallbackHandler, QWEDVerifyTool
    )
    return {
        "QWEDQueryEngine": QWEDQueryEngine,
        "QWEDVerificationTransform": QWEDVerificationTransform,
        "QWEDCallbackHandler": QWEDCallbackHandler,
        "QWEDVerifyTool": QWEDVerifyTool,
    }

def get_crewai_tools():
    """Get CrewAI integration classes."""
    from qwed_sdk.crewai import (
        QWEDVerificationTool, QWEDMathTool, QWEDCodeTool,
        QWEDVerifiedAgent, QWEDVerifiedCrew, VerificationConfig
    )
    return {
        "QWEDVerificationTool": QWEDVerificationTool,
        "QWEDVerifiedAgent": QWEDVerifiedAgent,
        "QWEDVerifiedCrew": QWEDVerifiedCrew,
        "VerificationConfig": VerificationConfig,
    }
