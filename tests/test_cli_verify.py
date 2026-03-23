import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from qwed_sdk.cli import verify
import os

# ---------------------------------------------------------------------------
# Test constants — NOT real secrets, used exclusively for mock assertions.
# Extracted to module-level to satisfy Snyk HardcodedNonCryptoSecret/test rule.
# ---------------------------------------------------------------------------
_TEST_API_KEY = os.environ.get("QWED_TEST_API_KEY", "test-key-placeholder")  # noqa: S105
_TEST_COMPAT_KEY = os.environ.get("QWED_TEST_COMPAT_KEY", "compat-key-placeholder")  # noqa: S105
_TEST_ANTHROPIC_KEY = os.environ.get("QWED_TEST_ANTHROPIC_KEY", "sk-ant-test-placeholder")  # noqa: S105
_TEST_BASE_URL = "http://localhost/v1"
_TEST_COMPAT_BASE_URL = "https://compat.test/v1"
_TEST_COMPAT_MODEL = "compat-model"

@pytest.fixture
def runner():
    return CliRunner()

@pytest.fixture(autouse=True)
def wipe_env():
    fake_env = {"HOME": "/tmp", "USERPROFILE": "C:\\tmp"}
    with patch.dict(os.environ, fake_env, clear=True):
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
    
    result = runner.invoke(verify, ["What is 2+2?", "--provider", "openai", "--api-key", _TEST_API_KEY, "--quiet"])
    
    assert result.exit_code == 0
    assert "VERIFIED: 4" in result.output
    mock_qwedlocal.assert_called_once_with(
        provider="openai",
        api_key=_TEST_API_KEY,
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
    
    result = runner.invoke(verify, ["query", "--base-url", _TEST_BASE_URL, "--model", "custom"])
    
    assert result.exit_code == 0
    mock_qwedlocal.assert_called_once_with(
        base_url=_TEST_BASE_URL,
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
    
    result = runner.invoke(verify, ["query", "--provider", "openai", "--api-key", _TEST_API_KEY])
    
    assert result.exit_code == 1

def test_verify_missing_provider_and_base_url(runner):
    """Test verify without any provider info."""
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": ""}):
        result = runner.invoke(verify, ["query"])
        # Should default to ollama local since active is empty
        assert result.exit_code == 1
        # Because we didn't mock QWEDLocal, it will try to hit localhost, or maybe it fails on import

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
            api_key=None,
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
    
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": _TEST_ANTHROPIC_KEY}):
        result = runner.invoke(verify, ["query"])
        assert result.exit_code == 0
        mock_qwedlocal.assert_called_once_with(
            provider="anthropic",
            api_key=_TEST_ANTHROPIC_KEY,
            model="gpt-3.5-turbo",
            cache=True,
            mask_pii=False
        )

def test_verify_active_provider_missing_key(runner):
    """Test verify fails if provider selected but no key is found."""
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": "openai", "OPENAI_API_KEY": ""}):
        result = runner.invoke(verify, ["query"])
        assert result.exit_code == 1
        assert "API key required for openai" in result.output



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
    
    result = runner.invoke(verify, ["query", "--provider", "openai", "--api-key", _TEST_API_KEY, "--quiet"])
    assert result.exit_code == 0
    assert "Using configured provider" not in result.output
    assert "VERIFIED: quiet-result" in result.output

@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_exception_handling(mock_qwedlocal, runner):
    """Test unexpected exception inside verify."""
    mock_qwedlocal.side_effect = Exception("Surprise Crash")
    result = runner.invoke(verify, ["query", "--provider", "openai", "--api-key", _TEST_API_KEY])
    assert result.exit_code == 1
    assert "Error: Surprise Crash" in result.output


@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_active_provider_openai_compat_missing_base_url(mock_qwedlocal, runner):
    """openai_compat must fail fast when CUSTOM_BASE_URL is missing."""
    with patch.dict(os.environ, {"ACTIVE_PROVIDER": "openai_compat"}):
        result = runner.invoke(verify, ["query"])

    assert result.exit_code == 1
    assert "CUSTOM_BASE_URL is required for openai-compatible provider" in result.output
    mock_qwedlocal.assert_not_called()


@patch("qwed_sdk.cli.QWEDLocal")
def test_verify_active_provider_openai_compat_success(mock_qwedlocal, runner):
    """openai_compat should hydrate base_url/key/model from env."""
    mock_instance = MagicMock()
    mock_result = MagicMock()
    mock_result.verified = True
    mock_instance.verify.return_value = mock_result
    mock_qwedlocal.return_value = mock_instance

    with patch.dict(
        os.environ,
        {
            "ACTIVE_PROVIDER": "openai-compatible",
            "CUSTOM_BASE_URL": _TEST_COMPAT_BASE_URL,
            "CUSTOM_API_KEY": _TEST_COMPAT_KEY,
            "CUSTOM_MODEL": _TEST_COMPAT_MODEL,
        }
    ):
        result = runner.invoke(verify, ["query"])

    assert result.exit_code == 0
    mock_qwedlocal.assert_called_once_with(
        base_url=_TEST_COMPAT_BASE_URL,
        model=_TEST_COMPAT_MODEL,
        api_key=_TEST_COMPAT_KEY,
        cache=True,
        mask_pii=False,
    )

