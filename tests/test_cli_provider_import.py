import builtins
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from qwed_sdk.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@patch("qwed_new.providers.config_manager.ProviderConfigManager")
def test_provider_import_success(mock_manager_cls, runner):
    manager = MagicMock()
    manager.import_provider_from_url.return_value = "do"
    mock_manager_cls.return_value = manager

    result = runner.invoke(cli, ["provider", "import", "https://example.com/do.yaml"])

    assert result.exit_code == 0
    assert "Successfully imported provider 'do'" in result.output
    manager.import_provider_from_url.assert_called_once_with("https://example.com/do.yaml")


@patch("qwed_new.providers.config_manager.ProviderConfigManager")
def test_provider_import_failure(mock_manager_cls, runner):
    manager = MagicMock()
    manager.import_provider_from_url.side_effect = ValueError("bad yaml")
    mock_manager_cls.return_value = manager

    result = runner.invoke(cli, ["provider", "import", "https://example.com/bad.yaml"])

    assert result.exit_code == 1
    assert "Failed to import provider: bad yaml" in result.output


def test_provider_import_core_import_error(runner):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "qwed_new.providers.config_manager":
            raise ImportError("simulated missing module")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        result = runner.invoke(cli, ["provider", "import", "https://example.com/do.yaml"])

    assert result.exit_code == 1
    assert "Core config manager not found" in result.output
