import builtins
import os
import urllib.error
from unittest.mock import MagicMock, patch

import pytest
import yaml

from qwed_new.providers.config_manager import ProviderConfigManager


def _mock_http_response(payload: str) -> MagicMock:
    response = MagicMock()
    response.read.return_value = payload.encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


def test_config_manager_unsupported_scheme():
    manager = ProviderConfigManager()
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        manager.import_provider_from_url("file:///etc/passwd")


def test_config_manager_url_error():
    manager = ProviderConfigManager()
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("test")):
        with pytest.raises(ValueError, match="Failed to fetch URL"):
            manager.import_provider_from_url("https://example.com")


def test_config_manager_yaml_error():
    manager = ProviderConfigManager()
    response = _mock_http_response("providers:\n  test: [")
    with patch("urllib.request.urlopen", return_value=response):
        with patch("yaml.safe_load", side_effect=yaml.YAMLError("bad yaml")):
            with pytest.raises(ValueError, match="Invalid YAML syntax"):
                manager.import_provider_from_url("https://example.com")


def test_config_manager_invalid_yaml_structure(tmp_path):
    manager = ProviderConfigManager(tmp_path / "providers.yaml")
    response = _mock_http_response("- not\n- a\n- mapping\n")
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="Invalid YAML structure"):
            manager.import_provider_from_url("https://example.com/provider.yaml")


def test_config_manager_empty_providers_block(tmp_path):
    manager = ProviderConfigManager(tmp_path / "providers.yaml")
    response = _mock_http_response("providers: {}\n")
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="No providers found in YAML"):
            manager.import_provider_from_url("https://example.com/provider.yaml")


def test_config_manager_missing_required_fields(tmp_path):
    manager = ProviderConfigManager(tmp_path / "providers.yaml")
    response = _mock_http_response("name: demo-only\n")
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="Missing required fields"):
            manager.import_provider_from_url("https://example.com/provider.yaml")


def test_config_manager_import_nested_providers_block(tmp_path):
    config_path = tmp_path / "providers.yaml"
    manager = ProviderConfigManager(config_path)

    response = _mock_http_response(
        yaml.dump(
            {
                "providers": {
                    "demo": {
                        "base_url": "https://api.demo.test/v1",
                        "api_key_env": "DEMO_KEY",
                    }
                }
            }
        )
    )

    with patch("urllib.request.urlopen", return_value=response):
        slug = manager.import_provider_from_url("https://example.com/demo.yaml")

    assert slug == "demo"
    loaded = manager.load_providers()
    assert loaded["demo"]["base_url"] == "https://api.demo.test/v1"
    assert loaded["demo"]["models_endpoint"] == "/models"
    assert loaded["demo"]["auth_prefix"] == "Bearer"


def test_config_manager_sanitizes_direct_format_slug(tmp_path):
    config_path = tmp_path / "providers.yaml"
    manager = ProviderConfigManager(config_path)
    response = _mock_http_response(
        yaml.dump(
            {
                "name": " Demo / Provider !! ",
                "base_url": "https://api.demo.test/v1",
                "api_key_env": "DEMO_KEY",
            }
        )
    )

    with patch("urllib.request.urlopen", return_value=response):
        slug = manager.import_provider_from_url("https://example.com/demo.yaml")

    assert slug == "demo-provider"
    loaded = manager.load_providers()
    assert "demo-provider" in loaded


def test_config_manager_falls_back_when_slug_conflicts_with_builtin(tmp_path):
    config_path = tmp_path / "providers.yaml"
    manager = ProviderConfigManager(config_path)
    response = _mock_http_response(
        yaml.dump(
            {
                "providers": {
                    "openai": {
                        "base_url": "https://api.shadow.test/v1",
                        "api_key_env": "SHADOW_KEY",
                    }
                }
            }
        )
    )

    with patch("urllib.request.urlopen", return_value=response):
        slug = manager.import_provider_from_url("https://example.com/openai.yaml")

    assert slug == "imported-provider"
    loaded = manager.load_providers()
    assert "imported-provider" in loaded
    assert "openai" not in loaded


def test_config_manager_invalid_save():
    manager = ProviderConfigManager()
    with pytest.raises(ValueError, match="Invalid provider configuration"):
        manager.save_provider("", {})
    with pytest.raises(ValueError, match="Invalid provider configuration"):
        manager.save_provider("test", "not a dict")


def test_config_manager_ensure_config_dir_creates_nested_path(tmp_path):
    config_path = tmp_path / "nested" / ".qwed" / "providers.yaml"
    manager = ProviderConfigManager(config_path)
    assert not config_path.parent.exists()

    manager._ensure_config_dir()

    assert config_path.parent.exists()


def test_config_manager_load_providers_graceful_on_invalid_root_type(tmp_path):
    config_path = tmp_path / "providers.yaml"
    config_path.write_text("- item1\n- item2\n", encoding="utf-8")
    manager = ProviderConfigManager(config_path)

    assert manager.load_providers() == {}


def test_config_manager_save_provider_handles_registry_import_error(tmp_path):
    config_path = tmp_path / "providers.yaml"
    manager = ProviderConfigManager(config_path)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "qwed_new.providers.registry":
            raise ImportError("forced import error")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        manager.save_provider(
            "demo",
            {"base_url": "https://api.demo.test/v1", "api_key_env": "DEMO_KEY"},
        )

    assert config_path.exists()


def test_config_manager_secure_write_cleanup_when_replace_fails(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("POSIX-only branch")

    config_path = tmp_path / "providers.yaml"
    manager = ProviderConfigManager(config_path)
    payload = {"providers": {"x": {"base_url": "https://x", "api_key_env": "X"}}}

    with patch("qwed_new.providers.config_manager.os.replace", side_effect=OSError("replace failed")):
        with patch("qwed_new.providers.config_manager.os.close", side_effect=OSError("already closed")):
            with patch("qwed_new.providers.config_manager.os.unlink", side_effect=OSError("unlink failed")):
                with pytest.raises(OSError, match="replace failed"):
                    manager._write_secure(payload)


def test_registry_dynamic_provider_happy_path():
    import qwed_new.providers.registry as registry_module

    class DummyManager:
        def load_providers(self):
            return {
                "do": {
                    "base_url": "https://inference.do-ai.run/v1",
                    "api_key_env": "DO_API_KEY",
                    "default_model": "do-latest",
                }
            }

    with patch("qwed_new.providers.config_manager.ProviderConfigManager", DummyManager):
        if hasattr(registry_module._get_dynamic_providers, "cache_clear"):
            registry_module._get_dynamic_providers.cache_clear()
        dynamic = registry_module._get_dynamic_providers()

    assert "yaml-do" in dynamic
    meta = dynamic["yaml-do"]
    assert meta.default_model == "do-latest"
    assert meta.env_vars[0].default == "https://inference.do-ai.run/v1"
    assert meta.env_vars[0].name == "CUSTOM_BASE_URL"
    assert meta.env_vars[1].name == "CUSTOM_API_KEY"
    assert meta.env_vars[2].name == "CUSTOM_MODEL"
    assert "DO_API_KEY" in meta.key_hint


def test_registry_dynamic_exception():
    import qwed_new.providers.registry as registry_module

    class FailingManager:
        def load_providers(self):
            raise RuntimeError("Fake parsing failure")

    with patch("qwed_new.providers.config_manager.ProviderConfigManager", FailingManager):
        if hasattr(registry_module._get_dynamic_providers, "cache_clear"):
            registry_module._get_dynamic_providers.cache_clear()
        res = registry_module._get_dynamic_providers()

    assert res == {}
