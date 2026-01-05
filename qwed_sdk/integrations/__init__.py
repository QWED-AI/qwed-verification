"""QWED integrations with popular AI frameworks.

This module provides seamless integration with major AI/ML frameworks:
- LangChain: Agent tools and chains
- LlamaIndex: Tools and query engines (coming soon)
- CrewAI: Agent tools (coming soon)

Usage:
    from qwed_sdk.integrations.langchain import QWEDTool
"""

__all__ = ["langchain"]

# Lazy imports - only load what's needed
def __getattr__(name):
    if name == "langchain":
        from qwed_sdk.integrations import langchain as lc_module
        return lc_module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
