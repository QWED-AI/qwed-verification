import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from qwed_sdk.cli import init
import sys

@pytest.fixture
def runner():
    return CliRunner()

def test_init_no_core(runner):
    """Test when qwed core is missing."""
    with patch.dict(sys.modules, {'qwed_new.providers.registry': None}):
        result = runner.invoke(init)
        assert result.exit_code == 1
        assert "QWED core not found" in result.output

@patch("qwed_new.providers.registry.list_providers")
@patch("qwed_new.providers.credential_store.write_env_file")
@patch("qwed_new.providers.credential_store.verify_gitignore")
@patch("qwed_new.providers.key_validator.validate_key_format")
@patch("qwed_new.providers.key_validator.test_connection")
def test_init_success_openai(mock_test, mock_validate, mock_verify, mock_write, mock_list, runner):
    """Test successful initialization of standard provider with connection test."""
    mock_provider = MagicMock()
    mock_provider.name = "OpenAI"
    mock_provider.slug = "openai"
    mock_provider.key_hint = "sk-proj-..."
    mock_provider.install_cmd = "pip install openai"
    mock_provider.auth_type = "API_KEY"
    mock_provider.key_pattern = r"^sk-proj-"
    
    mock_env = MagicMock()
    mock_env.name = "OPENAI_API_KEY"
    mock_env.description = "OpenAI API Key"
    mock_env.required = True
    mock_env.default = None
    mock_provider.env_vars = [mock_env]
    
    from qwed_new.providers.registry import AuthType
    mock_provider.auth_type = AuthType.API_KEY
    
    mock_list.return_value = [mock_provider]
    mock_verify.return_value = True
    mock_write.return_value = "/path/to/.env"
    mock_validate.return_value = (True, "Format OK")
    mock_test.return_value = (True, "Connection OK")
    
    # Input: 1 (OpenAI), sk-test-key (Key), y (test conn), y (set default)
    result = runner.invoke(init, input="1\nsk-test-key\ny\ny\n")
    
    assert result.exit_code == 0
    assert "Selected: OpenAI" in result.output
    assert "Connection OK" in result.output
    assert "Written to /path/to/.env" in result.output

@patch("qwed_new.providers.registry.list_providers")
@patch("qwed_new.providers.credential_store.write_env_file")
@patch("qwed_new.providers.credential_store.verify_gitignore")
@patch("qwed_new.providers.credential_store.add_env_to_gitignore")
@patch("qwed_new.providers.key_validator.test_connection")
@patch("qwed_new.providers.key_validator.validate_key_format")
def test_init_missing_gitignore_add_yes(mock_validate, mock_test, mock_add, mock_verify, mock_write, mock_list, runner):
    """Test gitignore warning and user says yes to add."""
    mock_provider = MagicMock()
    mock_provider.name = "Ollama"
    mock_provider.slug = "ollama"
    mock_provider.key_hint = ""
    mock_provider.install_cmd = None
    mock_provider.env_vars = []
    
    from qwed_new.providers.registry import AuthType
    mock_provider.auth_type = AuthType.LOCAL
    
    mock_list.return_value = [mock_provider]
    mock_verify.return_value = False
    mock_add.return_value = True
    mock_write.return_value = ".env"
    mock_test.return_value = (True, "OK")
    mock_validate.return_value = (True, "OK")
    
    # Input: 1 (Ollama), y (set default), y (add to gitignore)
    result = runner.invoke(init, input="1\ny\ny\n")
    assert result.exit_code == 0
    assert "NOT found in .gitignore!" in result.output
    assert "Added .env to .gitignore" in result.output

@patch("qwed_new.providers.registry.list_providers")
@patch("qwed_new.providers.credential_store.verify_gitignore")
@patch("qwed_new.providers.credential_store.add_env_to_gitignore")
@patch("qwed_new.providers.key_validator.test_connection")
@patch("qwed_new.providers.key_validator.validate_key_format")
def test_init_missing_gitignore_add_no(mock_validate, mock_test, mock_add, mock_verify, mock_list, runner):
    """Test gitignore warning and user says NO to add -> aborts."""
    mock_provider = MagicMock()
    mock_provider.name = "Ollama"
    mock_provider.slug = "ollama"
    mock_provider.env_vars = []
    from qwed_new.providers.registry import AuthType
    mock_provider.auth_type = AuthType.LOCAL
    
    mock_list.return_value = [mock_provider]
    mock_verify.return_value = False
    mock_test.return_value = (True, "OK")
    mock_validate.return_value = (True, "OK")
    
    # Input: 1 (Ollama), y (set default), n (don't add to gitignore)
    result = runner.invoke(init, input="1\ny\nn\n")
    assert result.exit_code == 1
    assert "refusing to write secrets without .gitignore protection" in result.output

@patch("qwed_new.providers.registry.list_providers")
def test_init_invalid_choice(mock_list, runner):
    """Test invalid provider choice."""
    mock_provider = MagicMock()
    mock_provider.name = "Ollama"
    mock_list.return_value = [mock_provider]
    
    # Input: 2 (out of bounds)
    result = runner.invoke(init, input="2\n")
    assert result.exit_code == 1
    assert "Invalid choice" in result.output

@patch("qwed_new.providers.registry.list_providers")
@patch("qwed_new.providers.credential_store.verify_gitignore")
@patch("qwed_new.providers.key_validator.validate_key_format")
@patch("qwed_new.providers.key_validator.test_connection")
def test_init_connection_fail_abort(mock_test, mock_validate, mock_verify, mock_list, runner):
    """Test connection test fails and user aborts."""
    mock_provider = MagicMock()
    mock_provider.name = "OpenAI"
    mock_provider.slug = "openai"
    mock_env = MagicMock()
    mock_env.name = "OPENAI_API_KEY"
    mock_provider.env_vars = [mock_env]
    from qwed_new.providers.registry import AuthType
    mock_provider.auth_type = AuthType.API_KEY
    mock_provider.key_pattern = r"^.*"
    mock_list.return_value = [mock_provider]
    
    mock_validate.return_value = (True, "OK")
    mock_test.return_value = (False, "Auth Failed")
    
    # Input: 1 (OpenAI), sk-test, y (test conn), n (continue anyway? NO)
    result = runner.invoke(init, input="1\nsk-test\ny\nn\n")
    assert result.exit_code == 1
    assert "Auth Failed" in result.output


@patch("qwed_new.providers.registry.list_providers")
@patch("qwed_new.providers.credential_store.write_env_file")
@patch("qwed_new.providers.credential_store.verify_gitignore")
@patch("qwed_new.providers.key_validator.validate_key_format")
@patch("qwed_new.providers.key_validator.test_connection")
def test_init_yaml_provider_maps_to_openai_compat(
    mock_test, mock_validate, mock_verify, mock_write, mock_list, runner
):
    """yaml-* providers should persist as ACTIVE_PROVIDER=openai_compat."""
    mock_provider = MagicMock()
    mock_provider.name = "My YAML Provider"
    mock_provider.slug = "yaml-my-provider"
    mock_provider.key_hint = ""
    mock_provider.install_cmd = None
    mock_provider.env_vars = []

    from qwed_new.providers.registry import AuthType

    mock_provider.auth_type = AuthType.LOCAL

    mock_list.return_value = [mock_provider]
    mock_verify.return_value = True
    mock_validate.return_value = (True, "OK")
    mock_test.return_value = (True, "OK")
    mock_write.return_value = ".env"

    result = runner.invoke(init, input="1\ny\n")

    assert result.exit_code == 0
    mock_write.assert_called_once_with({}, active_provider="openai_compat")
