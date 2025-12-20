"""
Tests for QWED LangChain Integration.

Tests the QWED tools, callbacks, and chain wrappers for LangChain.
These are simple import and initialization tests - no mocks needed.
"""

import pytest


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
        assert tool.name == "qwed_verify"
        assert "verify" in tool.description.lower()
    
    def test_tool_has_run_method(self):
        """Test tool has _run method."""
        from qwed_sdk.langchain import QWEDTool
        
        tool = QWEDTool(api_key="test_key")
        assert hasattr(tool, '_run')
        assert callable(tool._run)
    
    def test_tool_has_arun_method(self):
        """Test tool has async _arun method."""
        from qwed_sdk.langchain import QWEDTool
        
        tool = QWEDTool(api_key="test_key")
        assert hasattr(tool, '_arun')


class TestQWEDMathTool:
    """Test QWEDMathTool functionality."""
    
    def test_math_tool_initialization(self):
        """Test math tool initializes correctly."""
        from qwed_sdk.langchain import QWEDMathTool
        
        tool = QWEDMathTool(api_key="test_key")
        assert tool.name == "qwed_math"
        assert "math" in tool.description.lower()
    
    def test_math_tool_has_run(self):
        """Test math tool has _run method."""
        from qwed_sdk.langchain import QWEDMathTool
        
        tool = QWEDMathTool(api_key="test_key")
        assert hasattr(tool, '_run')


class TestQWEDLogicTool:
    """Test QWEDLogicTool functionality."""
    
    def test_logic_tool_initialization(self):
        """Test logic tool initializes correctly."""
        from qwed_sdk.langchain import QWEDLogicTool
        
        tool = QWEDLogicTool(api_key="test_key")
        assert tool.name == "qwed_logic"
        assert "logic" in tool.description.lower()


class TestQWEDCodeTool:
    """Test QWEDCodeTool functionality."""
    
    def test_code_tool_initialization(self):
        """Test code tool initializes correctly."""
        from qwed_sdk.langchain import QWEDCodeTool
        
        tool = QWEDCodeTool(api_key="test_key")
        assert tool.name == "qwed_code"
        assert "code" in tool.description.lower()


class TestQWEDVerificationCallback:
    """Test QWEDVerificationCallback functionality."""
    
    def test_callback_initialization(self):
        """Test callback initializes correctly."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(api_key="test_key")
        assert callback is not None
        assert callback.verify_math is True
        assert callback.verify_code is True
    
    def test_callback_stores_results(self):
        """Test callback stores verification results."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(api_key="test_key")
        assert hasattr(callback, 'verification_results')
        assert isinstance(callback.verification_results, list)
    
    def test_callback_has_on_llm_end(self):
        """Test callback has on_llm_end method."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(api_key="test_key")
        assert hasattr(callback, 'on_llm_end')
    
    def test_callback_get_summary(self):
        """Test callback can produce summary."""
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(api_key="test_key")
        summary = callback.get_summary()
        assert 'total_outputs' in summary
        assert 'verified' in summary
        assert 'verification_rate' in summary


class TestQWEDVerifiedChain:
    """Test QWEDVerifiedChain wrapper."""
    
    def test_verified_chain_initialization(self):
        """Test verified chain initializes with base chain."""
        from qwed_sdk.langchain import QWEDVerifiedChain
        
        class MockChain:
            pass
        
        mock_chain = MockChain()
        verified_chain = QWEDVerifiedChain(mock_chain, api_key="test_key")
        
        assert verified_chain.chain == mock_chain
    
    def test_verified_chain_has_run_method(self):
        """Test verified chain has run method."""
        from qwed_sdk.langchain import QWEDVerifiedChain
        
        class MockChain:
            pass
        
        verified_chain = QWEDVerifiedChain(MockChain(), api_key="test_key")
        assert hasattr(verified_chain, 'run')
    
    def test_verified_chain_auto_correct_option(self):
        """Test verified chain has auto_correct option."""
        from qwed_sdk.langchain import QWEDVerifiedChain
        
        class MockChain:
            pass
        
        chain = QWEDVerifiedChain(MockChain(), api_key="test_key", auto_correct=True)
        assert chain.auto_correct is True


class TestVerifiedOutput:
    """Test VerifiedOutput dataclass."""
    
    def test_verified_output_creation(self):
        """Test VerifiedOutput can be created."""
        from qwed_sdk.langchain import VerifiedOutput
        
        output = VerifiedOutput(
            output="The answer is 4",
            verified=True,
            status="VERIFIED",
        )
        
        assert output.output == "The answer is 4"
        assert output.verified is True
        assert output.status == "VERIFIED"
    
    def test_verified_output_str(self):
        """Test VerifiedOutput str method."""
        from qwed_sdk.langchain import VerifiedOutput
        
        output = VerifiedOutput(
            output="The answer is 4",
            verified=True,
            status="VERIFIED",
        )
        
        assert str(output) == "The answer is 4"


class TestModuleAvailability:
    """Test LANGCHAIN_AVAILABLE flag."""
    
    def test_langchain_available_flag_exists(self):
        """Test LANGCHAIN_AVAILABLE flag is exported."""
        from qwed_sdk.langchain import LANGCHAIN_AVAILABLE
        assert isinstance(LANGCHAIN_AVAILABLE, bool)
