"""
Tests for QWED LlamaIndex Integration.

Tests the QWED query engine wrapper, node postprocessor, and callback handler.
These are simple import and initialization tests - no mocks needed.
"""

import pytest


class TestQWEDLlamaIndexImports:
    """Test that QWED LlamaIndex components can be imported."""
    
    def test_import_query_engine(self):
        """Test QWEDQueryEngine import."""
        from qwed_sdk.llamaindex import QWEDQueryEngine
        assert QWEDQueryEngine is not None
    
    def test_import_verification_transform(self):
        """Test QWEDVerificationTransform import."""
        from qwed_sdk.llamaindex import QWEDVerificationTransform
        assert QWEDVerificationTransform is not None
    
    def test_import_callback_handler(self):
        """Test QWEDCallbackHandler import."""
        from qwed_sdk.llamaindex import QWEDCallbackHandler
        assert QWEDCallbackHandler is not None
    
    def test_import_verify_tool(self):
        """Test QWEDVerifyTool import."""
        from qwed_sdk.llamaindex import QWEDVerifyTool
        assert QWEDVerifyTool is not None
    
    def test_import_verified_response(self):
        """Test VerifiedResponse import."""
        from qwed_sdk.llamaindex import VerifiedResponse
        assert VerifiedResponse is not None


class TestQWEDQueryEngine:
    """Test QWEDQueryEngine functionality."""
    
    def test_query_engine_initialization(self):
        """Test query engine initializes with base engine."""
        from qwed_sdk.llamaindex import QWEDQueryEngine
        
        class MockEngine:
            pass
        
        mock_engine = MockEngine()
        engine = QWEDQueryEngine(mock_engine, api_key="test_key")
        
        assert engine.query_engine == mock_engine
    
    def test_query_engine_has_query_method(self):
        """Test query engine has query method."""
        from qwed_sdk.llamaindex import QWEDQueryEngine
        
        class MockEngine:
            pass
        
        engine = QWEDQueryEngine(MockEngine(), api_key="test_key")
        assert hasattr(engine, 'query')
    
    def test_query_engine_has_aquery_method(self):
        """Test query engine has async query method."""
        from qwed_sdk.llamaindex import QWEDQueryEngine
        
        class MockEngine:
            pass
        
        engine = QWEDQueryEngine(MockEngine(), api_key="test_key")
        assert hasattr(engine, 'aquery')
    
    def test_query_engine_options(self):
        """Test query engine accepts options."""
        from qwed_sdk.llamaindex import QWEDQueryEngine
        
        class MockEngine:
            pass
        
        engine = QWEDQueryEngine(
            MockEngine(),
            api_key="test_key",
            verify_math=True,
            verify_facts=False,
            auto_correct=True,
        )
        
        assert engine.verify_math is True
        assert engine.verify_facts is False
        assert engine.auto_correct is True


class TestVerifiedResponse:
    """Test VerifiedResponse dataclass."""
    
    def test_verified_response_creation(self):
        """Test VerifiedResponse can be created."""
        from qwed_sdk.llamaindex import VerifiedResponse
        
        response = VerifiedResponse(
            response="The answer is 4",
            verified=True,
            status="VERIFIED",
        )
        
        assert response.response == "The answer is 4"
        assert response.verified is True
        assert response.status == "VERIFIED"
    
    def test_verified_response_str(self):
        """Test VerifiedResponse str method."""
        from qwed_sdk.llamaindex import VerifiedResponse
        
        response = VerifiedResponse(
            response="The answer is 4",
            verified=True,
            status="VERIFIED",
        )
        
        assert str(response) == "The answer is 4"
    
    def test_verified_response_with_attestation(self):
        """Test VerifiedResponse with attestation."""
        from qwed_sdk.llamaindex import VerifiedResponse
        
        response = VerifiedResponse(
            response="The answer is 4",
            verified=True,
            status="VERIFIED",
            attestation="eyJhbGciOiJFUzI1NiIs...",
        )
        
        assert response.attestation is not None
    
    def test_verified_response_default_source_nodes(self):
        """Test VerifiedResponse defaults source_nodes to empty list."""
        from qwed_sdk.llamaindex import VerifiedResponse
        
        response = VerifiedResponse(
            response="Test",
            verified=True,
            status="VERIFIED",
        )
        
        assert response.source_nodes == []


class TestQWEDVerificationTransform:
    """Test QWEDVerificationTransform node postprocessor."""
    
    def test_transform_initialization(self):
        """Test transform initializes correctly."""
        from qwed_sdk.llamaindex import QWEDVerificationTransform
        
        transform = QWEDVerificationTransform(api_key="test_key")
        assert transform is not None
    
    def test_transform_options(self):
        """Test transform accepts options."""
        from qwed_sdk.llamaindex import QWEDVerificationTransform
        
        transform = QWEDVerificationTransform(
            api_key="test_key",
            verify_math=False,
            verify_code=True,
            min_score_threshold=0.7,
        )
        
        assert transform.verify_math is False
        assert transform.verify_code is True
        assert transform.min_score_threshold == 0.7


class TestQWEDCallbackHandler:
    """Test QWEDCallbackHandler functionality."""
    
    def test_callback_initialization(self):
        """Test callback handler initializes correctly."""
        from qwed_sdk.llamaindex import QWEDCallbackHandler
        
        handler = QWEDCallbackHandler(api_key="test_key")
        assert handler is not None
    
    def test_callback_stores_events(self):
        """Test callback handler stores events."""
        from qwed_sdk.llamaindex import QWEDCallbackHandler
        
        handler = QWEDCallbackHandler(api_key="test_key")
        assert hasattr(handler, 'events')
        assert isinstance(handler.events, list)
    
    def test_callback_log_all_option(self):
        """Test callback handler has log_all option."""
        from qwed_sdk.llamaindex import QWEDCallbackHandler
        
        handler = QWEDCallbackHandler(api_key="test_key", log_all=False)
        assert handler.log_all is False


class TestQWEDVerifyTool:
    """Test QWEDVerifyTool for agents."""
    
    def test_verify_tool_initialization(self):
        """Test verify tool initializes correctly."""
        from qwed_sdk.llamaindex import QWEDVerifyTool
        
        tool = QWEDVerifyTool(api_key="test_key")
        assert tool is not None
    
    def test_verify_tool_has_metadata(self):
        """Test verify tool has metadata property."""
        from qwed_sdk.llamaindex import QWEDVerifyTool
        
        tool = QWEDVerifyTool(api_key="test_key")
        assert hasattr(tool, 'metadata')
        metadata = tool.metadata
        assert 'name' in metadata
        assert 'description' in metadata
        assert metadata['name'] == 'qwed_verify'
    
    def test_verify_tool_is_callable(self):
        """Test verify tool is callable."""
        from qwed_sdk.llamaindex import QWEDVerifyTool
        
        tool = QWEDVerifyTool(api_key="test_key")
        assert callable(tool)


class TestModuleAvailability:
    """Test LLAMAINDEX_AVAILABLE flag."""
    
    def test_llamaindex_available_flag_exists(self):
        """Test LLAMAINDEX_AVAILABLE flag is exported."""
        from qwed_sdk.llamaindex import LLAMAINDEX_AVAILABLE
        assert isinstance(LLAMAINDEX_AVAILABLE, bool)
