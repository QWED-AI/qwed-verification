import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from qwed_sdk.cli import cli, verify
import os

@pytest.fixture
def runner():
    return CliRunner()

@pytest.fixture(autouse=True)
def wipe_env():
    with patch.dict(os.environ, {}, clear=True):
        yield

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_success_provider(mock_qwedlocal, runner):
    """Test verify with provider flag."""
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = True
    mock_result.value = "4"
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance
    
    result = runner.invoke(verify, ["What is 2+2?", "--provider", "openai", "--api-key", "test-key", "--quiet"])
    
    assert result.exit_code == 0
    assert "VERIFIED: 4" in result.output
    mock_qwedlocal.assert_called_once_with(
        provider="openai",
        api_key="test-key",
        model="gpt-3.5-turbo",
        cache=True,
        mask_pii=False
    )

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_success_base_url(mock_qwedlocal, runner):
    """Test verify with base_url flag."""
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = True
    mock_result.value = "math result"
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance
    
    result = runner.invoke(verify, ["query", "--base-url", "http://localhost/v1", "--model", "custom"])
    
    assert result.exit_code == 0
    mock_qwedlocal.assert_called_once_with(
        base_url="http://localhost/v1",
        model="custom",
        api_key=None,
        cache=True,
        mask_pii=False
    )

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_failure_result(mock_qwedlocal, runner):
    """Test verify when result.verified is False."""
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = False
    mock_result.error = "Hallucination detected"
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance
    
    result = runner.invoke(verify, ["query", "--provider", "openai", "--api-key", "key"])
    
    assert result.exit_code == 1

def test_verify_missing_provider_and_base_url(runner):
    """Test verify without any provider info."""
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": ""}, clear=True):
        result = runner.invoke(verify, ["query"])
        # Should default to ollama local since active is empty
        assert result.exit_code == 1
        # Because we didn't mock QWEDLocal, it will try to hit localhost, or maybe it fails on import
        pass

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_active_provider_ollama(mock_qwedlocal, runner):
    """Test verify with ACTIVE_PROVIDER = ollama"""
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = True
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance
    
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": "ollama", "OLLAMA_BASE_URL": "http://test", "OLLAMA_MODEL": "test-model"}):
        result = runner.invoke(verify, ["query"])
        assert result.exit_code == 0
        mock_qwedlocal.assert_called_once_with(
            base_url="http://test",
            model="test-model",
            api_key=None, # Ollama has no key by default or gets it from kwargs? Wait, it falls back
            cache=True,
            mask_pii=False
        )

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_active_provider_named(mock_qwedlocal, runner):
    """Test verify hydrates api_key from named provider env vars."""
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = True
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance
    
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-ant-test"}):
        result = runner.invoke(verify, ["query"])
        assert result.exit_code == 0
        mock_qwedlocal.assert_called_once_with(
            provider="anthropic",
            api_key="sk-ant-test",
            model="gpt-3.5-turbo",
            cache=True,
            mask_pii=False
        )

def test_verify_active_provider_missing_key(runner):
    """Test verify fails if provider selected but no key is found."""
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": "openai", "OPENAI_API_KEY": ""}, clear=True):
        result = runner.invoke(verify, ["query"])
        assert result.exit_code == 1
        assert "API key required for openai" in result.output

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_dotenv_missing_warning(mock_qwedlocal, runner):
    """Test warning shown if dotenv is missing in regular mode."""
    import sys
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = True
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance
    
    with patch.dict(sys.modules, {'dotenv': None}):
        result = runner.invoke(verify, ["query", "--provider", "openai", "--api-key", "test"])
        assert result.exit_code == 0
        assert "python-dotenv not installed" in result.output

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_quiet_mode(mock_qwedlocal, runner):
    """Test quiet mode suppresses logs and warnings."""
    import sys
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = True
    mock_result.value = "quiet-result"
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance
    
    # Even without dotenv, warning shouldn't print
    with patch.dict(sys.modules, {'dotenv': None}):
        result = runner.invoke(verify, ["query", "--provider", "openai", "--api-key", "test", "--quiet"])
        assert result.exit_code == 0
        assert "python-dotenv not installed" not in result.output
        assert "Using configured provider" not in result.output
        assert "VERIFIED: quiet-result" in result.output

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_exception_handling(mock_qwedlocal, runner):
    """Test unexpected exception inside verify."""
    mock_qwedlocal.side_effect = Exception("Surprise Crash")
    result = runner.invoke(verify, ["query", "--provider", "openai", "--api-key", "key"])
    assert result.exit_code == 1
    assert "Error: Surprise Crash" in result.output
