"""
Tests for QWED CrewAI Integration.

Tests the QWED verified agents, crews, and tools for CrewAI.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock


class TestQWEDCrewAIImports:
    """Test that QWED CrewAI components can be imported."""
    
    def test_import_verification_tool(self):
        """Test QWEDVerificationTool import."""
        from qwed_sdk.crewai import QWEDVerificationTool
        assert QWEDVerificationTool is not None
    
    def test_import_math_tool(self):
        """Test QWEDMathTool import."""
        from qwed_sdk.crewai import QWEDMathTool
        assert QWEDMathTool is not None
    
    def test_import_code_tool(self):
        """Test QWEDCodeTool import."""
        from qwed_sdk.crewai import QWEDCodeTool
        assert QWEDCodeTool is not None
    
    def test_import_sql_tool(self):
        """Test QWEDSQLTool import."""
        from qwed_sdk.crewai import QWEDSQLTool
        assert QWEDSQLTool is not None
    
    def test_import_verified_agent(self):
        """Test QWEDVerifiedAgent import."""
        from qwed_sdk.crewai import QWEDVerifiedAgent
        assert QWEDVerifiedAgent is not None
    
    def test_import_verified_crew(self):
        """Test QWEDVerifiedCrew import."""
        from qwed_sdk.crewai import QWEDVerifiedCrew
        assert QWEDVerifiedCrew is not None
    
    def test_import_verification_config(self):
        """Test VerificationConfig import."""
        from qwed_sdk.crewai import VerificationConfig
        assert VerificationConfig is not None
    
    def test_import_crew_verified_result(self):
        """Test CrewVerifiedResult import."""
        from qwed_sdk.crewai import CrewVerifiedResult
        assert CrewVerifiedResult is not None
    
    def test_import_verified_task_decorator(self):
        """Test verified_task import."""
        from qwed_sdk.crewai import verified_task
        assert verified_task is not None


class TestQWEDVerificationTool:
    """Test QWEDVerificationTool functionality."""
    
    def test_tool_initialization(self):
        """Test tool initializes correctly."""
        from qwed_sdk.crewai import QWEDVerificationTool
        
        tool = QWEDVerificationTool(api_key="test_key")
        assert tool.name == "QWED Verification"
    
    def test_tool_has_description(self):
        """Test tool has description."""
        from qwed_sdk.crewai import QWEDVerificationTool
        
        tool = QWEDVerificationTool(api_key="test_key")
        assert len(tool.description) > 0
        assert "verify" in tool.description.lower()
    
    def test_tool_has_run_method(self):
        """Test tool has _run method."""
        from qwed_sdk.crewai import QWEDVerificationTool
        
        tool = QWEDVerificationTool(api_key="test_key")
        assert hasattr(tool, '_run')


class TestQWEDMathTool:
    """Test QWEDMathTool functionality."""
    
    def test_math_tool_initialization(self):
        """Test math tool initializes correctly."""
        from qwed_sdk.crewai import QWEDMathTool
        
        tool = QWEDMathTool(api_key="test_key")
        assert "Math" in tool.name
    
    def test_math_tool_description(self):
        """Test math tool has appropriate description."""
        from qwed_sdk.crewai import QWEDMathTool
        
        tool = QWEDMathTool(api_key="test_key")
        assert "math" in tool.description.lower()


class TestQWEDCodeTool:
    """Test QWEDCodeTool functionality."""
    
    def test_code_tool_initialization(self):
        """Test code tool initializes correctly."""
        from qwed_sdk.crewai import QWEDCodeTool
        
        tool = QWEDCodeTool(api_key="test_key")
        assert "Code" in tool.name or "Security" in tool.name
    
    def test_code_tool_description(self):
        """Test code tool has appropriate description."""
        from qwed_sdk.crewai import QWEDCodeTool
        
        tool = QWEDCodeTool(api_key="test_key")
        assert "code" in tool.description.lower() or "security" in tool.description.lower()


class TestVerificationConfig:
    """Test VerificationConfig dataclass."""
    
    def test_config_defaults(self):
        """Test config has sensible defaults."""
        from qwed_sdk.crewai import VerificationConfig
        
        config = VerificationConfig()
        assert config.enabled is True
        assert config.verify_math is True
        assert config.verify_code is True
    
    def test_config_customization(self):
        """Test config can be customized."""
        from qwed_sdk.crewai import VerificationConfig
        
        config = VerificationConfig(
            enabled=False,
            verify_math=False,
            auto_correct=True,
        )
        
        assert config.enabled is False
        assert config.verify_math is False
        assert config.auto_correct is True


class TestQWEDVerifiedAgent:
    """Test QWEDVerifiedAgent functionality."""
    
    def test_verified_agent_initialization(self):
        """Test verified agent initializes correctly."""
        from qwed_sdk.crewai import QWEDVerifiedAgent
        
        agent = QWEDVerifiedAgent(
            role="Analyst",
            goal="Analyze data",
            api_key="test_key",
        )
        
        assert agent is not None
    
    def test_verified_agent_has_config(self):
        """Test verified agent has verification config."""
        from qwed_sdk.crewai import QWEDVerifiedAgent, VerificationConfig
        
        config = VerificationConfig(verify_math=True)
        agent = QWEDVerifiedAgent(
            role="Analyst",
            goal="Analyze data",
            verification_config=config,
            api_key="test_key",
        )
        
        assert agent.config == config
    
    def test_verified_agent_stores_results(self):
        """Test verified agent stores verification results."""
        from qwed_sdk.crewai import QWEDVerifiedAgent
        
        agent = QWEDVerifiedAgent(
            role="Analyst",
            goal="Analyze data",
            api_key="test_key",
        )
        
        assert hasattr(agent, 'verification_results')
        assert isinstance(agent.verification_results, list)
    
    def test_verified_agent_has_verify_output(self):
        """Test verified agent has verify_output method."""
        from qwed_sdk.crewai import QWEDVerifiedAgent
        
        agent = QWEDVerifiedAgent(
            role="Analyst",
            goal="Analyze data",
            api_key="test_key",
        )
        
        assert hasattr(agent, 'verify_output')
    
    def test_verified_agent_verification_summary(self):
        """Test verified agent can produce summary."""
        from qwed_sdk.crewai import QWEDVerifiedAgent
        
        agent = QWEDVerifiedAgent(
            role="Analyst",
            goal="Analyze data",
            api_key="test_key",
        )
        
        summary = agent.verification_summary()
        assert 'total_outputs' in summary
        assert 'verified' in summary
        assert 'failed' in summary


class TestCrewVerifiedResult:
    """Test CrewVerifiedResult dataclass."""
    
    def test_result_creation(self):
        """Test CrewVerifiedResult can be created."""
        from qwed_sdk.crewai import CrewVerifiedResult
        
        result = CrewVerifiedResult(
            output="Task completed",
            verified=True,
            status="VERIFIED",
        )
        
        assert result.output == "Task completed"
        assert result.verified is True
        assert result.status == "VERIFIED"
    
    def test_result_str(self):
        """Test CrewVerifiedResult str method."""
        from qwed_sdk.crewai import CrewVerifiedResult
        
        result = CrewVerifiedResult(
            output="Task completed",
            verified=True,
            status="VERIFIED",
        )
        
        assert str(result) == "Task completed"
    
    def test_result_total_verifications(self):
        """Test CrewVerifiedResult total_verifications property."""
        from qwed_sdk.crewai import CrewVerifiedResult
        
        result = CrewVerifiedResult(
            output="Task completed",
            verified=True,
            status="VERIFIED",
            agent_summaries=[
                {"total_outputs": 5, "verified": 4},
                {"total_outputs": 3, "verified": 3},
            ]
        )
        
        assert result.total_verifications == 8


class TestVerifiedTaskDecorator:
    """Test verified_task decorator."""
    
    def test_decorator_returns_callable(self):
        """Test decorator returns a callable."""
        from qwed_sdk.crewai import verified_task
        
        @verified_task(verify_output=True)
        def my_task(output):
            return output.upper()
        
        assert callable(my_task)


class TestModuleAvailability:
    """Test CREWAI_AVAILABLE flag."""
    
    def test_crewai_available_flag_exists(self):
        """Test CREWAI_AVAILABLE flag is exported."""
        from qwed_sdk.crewai import CREWAI_AVAILABLE
        assert isinstance(CREWAI_AVAILABLE, bool)
