"""
Tests for QWED LlamaIndex Integration.

Tests the QWED query engine wrapper, node postprocessor, and callback handler.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock


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
        
        mock_engine = Mock()
        engine = QWEDQueryEngine(mock_engine, api_key="test_key")
        
        assert engine.query_engine == mock_engine
    
    def test_query_engine_has_query_method(self):
        """Test query engine has query method."""
        from qwed_sdk.llamaindex import QWEDQueryEngine
        
        mock_engine = Mock()
        engine = QWEDQueryEngine(mock_engine, api_key="test_key")
        
        assert hasattr(engine, 'query')
    
    def test_query_engine_has_aquery_method(self):
        """Test query engine has async query method."""
        from qwed_sdk.llamaindex import QWEDQueryEngine
        
        mock_engine = Mock()
        engine = QWEDQueryEngine(mock_engine, api_key="test_key")
        
        assert hasattr(engine, 'aquery')
    
    @patch('qwed_sdk.llamaindex.QWEDClient')
    def test_query_returns_verified_response(self, mock_client_class):
        """Test query returns VerifiedResponse object."""
        from qwed_sdk.llamaindex import QWEDQueryEngine, VerifiedResponse
        
        # Setup mocks
        mock_client = Mock()
        mock_result = Mock()
        mock_result.verified = True
        mock_result.status = "VERIFIED"
        mock_client.verify.return_value = mock_result
        mock_client_class.return_value = mock_client
        
        mock_base_engine = Mock()
        mock_base_engine.query.return_value = "The answer is 30"
        
        engine = QWEDQueryEngine(mock_base_engine, api_key="test_key")
        response = engine.query("What is 15% of 200?")
        
        assert isinstance(response, VerifiedResponse)


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


class TestQWEDVerificationTransform:
    """Test QWEDVerificationTransform node postprocessor."""
    
    def test_transform_initialization(self):
        """Test transform initializes correctly."""
        from qwed_sdk.llamaindex import QWEDVerificationTransform
        
        transform = QWEDVerificationTransform(api_key="test_key")
        assert transform is not None
    
    def test_transform_has_postprocess_method(self):
        """Test transform has _postprocess_nodes method."""
        from qwed_sdk.llamaindex import QWEDVerificationTransform
        
        transform = QWEDVerificationTransform(api_key="test_key")
        assert hasattr(transform, '_postprocess_nodes')


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
    
    def test_callback_has_event_methods(self):
        """Test callback handler has event methods."""
        from qwed_sdk.llamaindex import QWEDCallbackHandler
        
        handler = QWEDCallbackHandler(api_key="test_key")
        assert hasattr(handler, 'on_event_start')
        assert hasattr(handler, 'on_event_end')


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
        assert 'name' in tool.metadata
        assert 'description' in tool.metadata
    
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
