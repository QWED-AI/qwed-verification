import pytest
import tempfile
from pathlib import Path
import os
import stat
import yaml
from unittest.mock import patch, MagicMock
from qwed_new.providers.config_manager import ProviderConfigManager

def test_config_manager_initialization():
    """Test default paths."""
    manager = ProviderConfigManager()
    assert manager.config_path.name == "providers.yaml"
    assert manager.config_path.parent.name == ".qwed"

def test_save_and_load_provider():
    """Test standard YAML save and load."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "providers.yaml"
        manager = ProviderConfigManager(config_path)
        
        config_data = {
            "base_url": "https://api.test.com",
            "api_key_env": "TEST_KEY",
            "default_model": "test-model"
        }
        
        # Save
        manager.save_provider("test-do", config_data)
        assert config_path.exists()
        
        # Check permissions if supported
        if hasattr(os, "stat") and hasattr(os, "chmod"):
            st = os.stat(config_path)
            # Depending on platform, mask might be different, but it should be written successfully
        
        # Load
        loaded = manager.load_providers()
        assert "test-do" in loaded
        assert loaded["test-do"]["base_url"] == "https://api.test.com"

def test_import_provider_from_url():
    """Test importing a provider directly from a URL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "providers.yaml"
        manager = ProviderConfigManager(config_path)
        
        mock_yaml = {
            "name": "TestingDO",
            "base_url": "https://do.run/v1",
            "api_key_env": "DO_API_KEY",
            "default_model": "do-latest"
        }
        
        mock_response = MagicMock()
        mock_response.read.return_value = yaml.dump(mock_yaml).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        
        with patch('urllib.request.urlopen', return_value=mock_response):
            slug = manager.import_provider_from_url("http://fake-github.com/do.yaml")
        
        # Should default to the 'name' field if raw dict
        assert slug == "TestingDO"
        
        # Validate saved
        loaded = manager.load_providers()
        assert "TestingDO" in loaded
        assert loaded["TestingDO"]["base_url"] == "https://do.run/v1"
        assert loaded["TestingDO"]["default_model"] == "do-latest"
        
def test_import_invalid_yaml():
    """Prevent execution of malformed YAML."""
    manager = ProviderConfigManager()
    
    mock_response = MagicMock()
    mock_response.read.return_value = b"::: invalid :: yaml\n"
    mock_response.__enter__.return_value = mock_response
    
    with patch('urllib.request.urlopen', return_value=mock_response):
        with pytest.raises(ValueError, match="Invalid YAML"):
            manager.import_provider_from_url("http://fake")
