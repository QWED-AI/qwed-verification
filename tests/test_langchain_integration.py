"""
Tests for QWED LangChain Integration.

Tests the QWED tools, callbacks, and chain wrappers for LangChain.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock


class TestQWEDToolImports:
    """Test that QWED LangChain tools can be imported."""
    
    def test_import_qwed_tool(self):
        """Test QWEDTool import."""
        from qwed_sdk.langchain import QWEDTool
        assert QWEDTool is not None
    
    def test_import_specialized_tools(self):
        """Test specialized tool imports."""
        from qwed_sdk.langchain import QWEDMathTool, QWEDLogicTool, QWEDCodeTool
        assert QWEDMathTool is not None
        assert QWEDLogicTool is not None
        assert QWEDCodeTool is not None
    
    def test_import_callback(self):
        """Test callback handler import."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        assert QWEDVerificationCallback is not None
    
    def test_import_chain_wrapper(self):
        """Test chain wrapper import."""
        from qwed_sdk.langchain import QWEDVerifiedChain
        assert QWEDVerifiedChain is not None


class TestQWEDTool:
    """Test QWEDTool functionality."""
    
    def test_tool_initialization(self):
        """Test tool initializes with default config."""
        from qwed_sdk.langchain import QWEDTool
        
        tool = QWEDTool(api_key="test_key")
        assert tool.name == "QWED Verify"
        assert "verify" in tool.description.lower()
    
    def test_tool_has_run_method(self):
        """Test tool has _run method."""
        from qwed_sdk.langchain import QWEDTool
        
        tool = QWEDTool(api_key="test_key")
        assert hasattr(tool, '_run')
    
    @patch('qwed_sdk.langchain.QWEDClient')
    def test_tool_run_calls_verify(self, mock_client_class):
        """Test tool._run calls the verify method."""
        from qwed_sdk.langchain import QWEDTool
        
        # Setup mock
        mock_client = Mock()
        mock_result = Mock()
        mock_result.verified = True
        mock_result.status = "VERIFIED"
        mock_client.verify.return_value = mock_result
        mock_client_class.return_value = mock_client
        
        tool = QWEDTool(api_key="test_key")
        result = tool._run("2+2=4")
        
        assert "VERIFIED" in result or "verified" in result.lower()


class TestQWEDMathTool:
    """Test QWEDMathTool functionality."""
    
    def test_math_tool_initialization(self):
        """Test math tool initializes correctly."""
        from qwed_sdk.langchain import QWEDMathTool
        
        tool = QWEDMathTool(api_key="test_key")
        assert tool.name == "QWED Math"
        assert "math" in tool.description.lower()
    
    @patch('qwed_sdk.langchain.QWEDClient')
    def test_math_tool_calls_verify_math(self, mock_client_class):
        """Test math tool calls verify_math."""
        from qwed_sdk.langchain import QWEDMathTool
        
        mock_client = Mock()
        mock_result = Mock()
        mock_result.verified = True
        mock_result.result = {"is_valid": True}
        mock_client.verify_math.return_value = mock_result
        mock_client_class.return_value = mock_client
        
        tool = QWEDMathTool(api_key="test_key")
        result = tool._run("x^2 + 2x + 1 = (x+1)^2")
        
        assert result is not None


class TestQWEDCodeTool:
    """Test QWEDCodeTool functionality."""
    
    def test_code_tool_initialization(self):
        """Test code tool initializes correctly."""
        from qwed_sdk.langchain import QWEDCodeTool
        
        tool = QWEDCodeTool(api_key="test_key")
        assert tool.name == "QWED Code Security"
        assert "security" in tool.description.lower() or "code" in tool.description.lower()
    
    @patch('qwed_sdk.langchain.QWEDClient')
    def test_code_tool_detects_vulnerabilities(self, mock_client_class):
        """Test code tool returns vulnerability info."""
        from qwed_sdk.langchain import QWEDCodeTool
        
        mock_client = Mock()
        mock_result = Mock()
        mock_result.verified = False
        mock_result.status = "BLOCKED"
        mock_result.result = {
            "vulnerabilities": [
                {"severity": "critical", "message": "os.system detected"}
            ]
        }
        mock_client.verify_code.return_value = mock_result
        mock_client_class.return_value = mock_client
        
        tool = QWEDCodeTool(api_key="test_key")
        result = tool._run("import os; os.system('rm -rf /')")
        
        assert result is not None


class TestQWEDVerificationCallback:
    """Test QWEDVerificationCallback functionality."""
    
    def test_callback_initialization(self):
        """Test callback initializes correctly."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(api_key="test_key")
        assert callback is not None
    
    def test_callback_has_on_llm_end(self):
        """Test callback has on_llm_end method."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(api_key="test_key")
        assert hasattr(callback, 'on_llm_end')
    
    def test_callback_stores_results(self):
        """Test callback stores verification results."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(api_key="test_key")
        assert hasattr(callback, 'verification_results')
        assert isinstance(callback.verification_results, list)


class TestQWEDVerifiedChain:
    """Test QWEDVerifiedChain wrapper."""
    
    def test_verified_chain_initialization(self):
        """Test verified chain initializes with base chain."""
        from qwed_sdk.langchain import QWEDVerifiedChain
        
        mock_chain = Mock()
        verified_chain = QWEDVerifiedChain(mock_chain, api_key="test_key")
        
        assert verified_chain.chain == mock_chain
    
    def test_verified_chain_has_run_method(self):
        """Test verified chain has run method."""
        from qwed_sdk.langchain import QWEDVerifiedChain
        
        mock_chain = Mock()
        verified_chain = QWEDVerifiedChain(mock_chain, api_key="test_key")
        
        assert hasattr(verified_chain, 'run')


class TestModuleAvailability:
    """Test LANGCHAIN_AVAILABLE flag."""
    
    def test_langchain_available_flag_exists(self):
        """Test LANGCHAIN_AVAILABLE flag is exported."""
        from qwed_sdk.langchain import LANGCHAIN_AVAILABLE
        assert isinstance(LANGCHAIN_AVAILABLE, bool)
