"""
QWED Framework Integrations.

Import integrations for your favorite agent frameworks.
"""

# LangChain
QWEDTool = None
try:
    from .langchain import QWEDTool
except ImportError:
    QWEDTool = None

# CrewAI
QWEDVerifiedAgent = None
VerificationConfig = None
try:
    from .crewai import QWEDVerifiedAgent, VerificationConfig
except ImportError:
    QWEDVerifiedAgent = None
    VerificationConfig = None

# LlamaIndex
QWEDQueryEngine = None
VerifiedResponse = None
try:
    from .llamaindex import QWEDQueryEngine, VerifiedResponse
except ImportError:
    QWEDQueryEngine = None
    VerifiedResponse = None

__all__ = [
    "QWEDTool",
    "QWEDVerifiedAgent", 
    "VerificationConfig",
    "QWEDQueryEngine", 
    "VerifiedResponse"
]
