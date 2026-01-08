"""
Framework Integration Tests

Tests QWED's compatibility with popular LLM frameworks.
Most tests are marked as optional (skip) to avoid requiring heavy dependencies.
"""

import pytest


# ============================================================================
# LangChain Integration Tests
# ============================================================================

@pytest.mark.skip(reason="Optional: Requires langchain installation")
def test_langchain_tool_integration():
    """
    Test QWED as a LangChain tool
    
    Demonstrates that QWED can be used within LangChain agent workflows.
    """
    try:
        from langchain.tools import Tool
        from qwed_sdk.integrations.langchain import QWEDTool
        
        tool = QWEDTool(engine="math")
        result = tool.run("2+2=5")
        
        assert result["verified"] == False, \
            "Should detect hallucination via LangChain"
        
    except ImportError:
        pytest.skip("LangChain not installed")


@pytest.mark.skip(reason="Optional: Requires langchain installation")
def test_langchain_agent_workflow():
    """
    Test QWED within a LangChain agent workflow
    
    Shows how verification integrates into multi-step agent processes.
    """
    try:
        from langchain.agents import initialize_agent, AgentType
        from langchain.llms import OpenAI
        from qwed_sdk.integrations.langchain import QWEDTool
        
        tools = [QWEDTool(engine="math")]
        agent = initialize_agent(
            tools,
            OpenAI(temperature=0),
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
        )
        
        response = agent.run("Verify that 2+2=4")
        assert "verified" in response.lower() or "true" in response.lower()
        
    except ImportError:
        pytest.skip("LangChain not installed")


# ============================================================================
# LlamaIndex Integration Tests
# ============================================================================

@pytest.mark.skip(reason="Optional: Requires llama-index installation")
def test_llamaindex_query_engine():
    """
    Test QWED with LlamaIndex query engine
    
    Demonstrates fact verification against a LlamaIndex knowledge base.
    """
    try:
        from llama_index import VectorStoreIndex, SimpleDirectoryReader
        from qwed_sdk.integrations.llamaindex import QWEDQueryEngine
        
        # Mock index
        documents = SimpleDirectoryReader("./docs").load_data()
        index = VectorStoreIndex.from_documents(documents)
        
        engine = QWEDQueryEngine(index=index, qwed_engine="facts")
        response = engine.query("What is the capital of France?")
        
        assert hasattr(response, "verified"), \
            "Response should have verification status"
        
    except ImportError:
        pytest.skip("LlamaIndex not installed")


# ============================================================================
# LLM Provider Integration Tests (Mocked)
# ============================================================================

def test_openai_integration_mock():
    """
    Test QWED with OpenAI provider (mocked)
    
    Verifies that QWED can process OpenAI responses.
    Uses mock to avoid requiring API key.
    """
    from qwed_sdk import QWEDClient
    
    client = QWEDClient(provider="mock")  # Use mock instead of real OpenAI
    
    # Simulate OpenAI response
    result = client.verify_math("What is 2+2?")
    
    assert "verified" in result, "Should return verification result"
    assert isinstance(result["verified"], bool), \
        "Verified field should be boolean"


def test_anthropic_integration_mock():
    """
    Test QWED with Anthropic/Claude provider (mocked)
    
    Verifies that QWED can process Claude responses.
    Uses mock to avoid requiring API key.
    """
    from qwed_sdk import QWEDClient
    
    client = QWEDClient(provider="mock")  # Use mock instead of real Anthropic
    
    # Simulate Claude response
    result = client.verify_math("What is 2+2?")
    
    assert "verified" in result, "Should return verification result"
    assert isinstance(result["verified"], bool), \
        "Verified field should be boolean"


# ============================================================================
# API Integration Tests
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.skip(reason="Requires running QWED API server")
async def test_fastapi_endpoint_integration():
    """
    Test QWED REST API endpoint
    
    Verifies that the FastAPI server correctly processes verification requests.
    """
    import httpx
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/verify/math",
            json={"claim": "2+2=4"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "verified" in data
        assert data["verified"] == True


# ============================================================================
# Custom Integration Example
# ============================================================================

def test_custom_integration_pattern():
    """
    Test custom integration pattern
    
    Demonstrates how to build custom integrations with QWED.
    This pattern can be adapted for any LLM framework.
    """
    from qwed_sdk import QWEDClient
    
    class CustomLLMWrapper:
        """Example wrapper showing integration pattern"""
        
        def __init__(self):
            self.qwed = QWEDClient(provider="mock")
        
        def generate_and_verify(self, query, engine="math"):
            """Generate response and verify it"""
            # In real integration, this would call your LLM
            llm_response = "mock response"
            
            # Verify the response
            verification = self.qwed.verify(llm_response, engine=engine)
            
            return {
                "response": llm_response,
                "verified": verification["verified"],
                "explanation": verification.get("explanation", "")
            }
    
    wrapper = CustomLLMWrapper()
    result = wrapper.generate_and_verify("Test query")
    
    assert "response" in result, "Should contain LLM response"
    assert "verified" in result, "Should contain verification status"


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
