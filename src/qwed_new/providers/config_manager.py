"""
Universal Provider Config Manager.

Reads and writes custom LLM provider endpoints to a local YAML file
with strict 0600 permissions and secrets-separation per PR #85.
"""

import os
import re
import yaml
import stat
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Optional, Any
import logging

logger = logging.getLogger("qwed.providers.config")

class ProviderConfigManager:
    """Manages custom LLM providers stored in a YAML configuration file."""
    
    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            self.config_path = Path.home() / ".qwed" / "providers.yaml"
        else:
            self.config_path = config_path
            
    def _ensure_config_dir(self):
        """Ensure the ~/.qwed directory exists with appropriate permissions."""
        if not self.config_path.parent.exists():
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            # Restrict directory to owner if created
            if hasattr(os, "chmod"):
                os.chmod(self.config_path.parent, stat.S_IRWXU)
                
    def load_providers(self) -> Dict[str, Any]:
        """Load all providers from the config file."""
        if not self.config_path.exists():
            return {}
            
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("providers", {}) if data else {}
        except Exception as e:
            logger.debug(f"Failed to load providers YAML: {type(e).__name__}")
            return {}

    def _write_secure(self, data: Dict[str, Any]) -> None:
        """Atomically write YAML with strict 0600 permissions."""
        self._ensure_config_dir()
        
        yaml_content = yaml.dump(data, default_flow_style=False, sort_keys=False)
        parent_dir = str(self.config_path.parent)
        
        if hasattr(os, "O_NOFOLLOW"):
            # Universal robust 0600 write (from PR 85)
            fd, tmp_path = tempfile.mkstemp(dir=parent_dir, prefix=".providers.", suffix=".tmp")
            
            try:
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                logger.debug(f"fchmod failed on temp file: {type(e).__name__}")
            
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(yaml_content)
                os.replace(tmp_path, self.config_path)
            except Exception as e:
                logger.debug(f"Failed to write providers config: {type(e).__name__}")
                try:
                    os.close(fd)
                except OSError as close_err:
                    logger.debug(f"Non-fatal error closing temp file descriptor: {close_err}")
                try:
                    if Path(tmp_path).exists():
                        os.unlink(tmp_path)
                except OSError as cleanup_err:
                    logger.debug(f"Non-fatal error removing temp file: {cleanup_err}")
                raise
        else:
            # Fallback for Windows
            with open(self.config_path, "w", encoding="utf-8") as f:
                f.write(yaml_content)

    def save_provider(self, slug: str, config: Dict[str, Any]) -> None:
        """Save a new provider configuration."""
        if not slug or not isinstance(config, dict):
            raise ValueError("Invalid provider configuration")
            
        data = {"providers": self.load_providers()}
        data["providers"][slug] = config
        
        self._write_secure(data)
        
        # Invalidate the runtime registry cache so long-running engines see the new config
        try:
            from qwed_new.providers.registry import _get_dynamic_providers
            if hasattr(_get_dynamic_providers, "cache_clear"):
                _get_dynamic_providers.cache_clear()
        except ImportError as e:
            logger.debug(f"Registry module unavailable; skipping cache invalidation: {e}")
        
    def import_provider_from_url(self, url: str) -> str:
        """
        Download and validate a community provider YAML.
        Returns the imported provider slug.
        """
        def _sanitize_slug(raw_slug: Any) -> str:
            slug = re.sub(r"[^a-z0-9]+", "-", str(raw_slug or "").strip().lower())
            slug = re.sub(r"-{2,}", "-", slug).strip("-")
            if not slug:
                slug = "imported-provider"

            # Keep custom slugs from shadowing canonical built-in providers.
            try:
                from qwed_new.providers.registry import PROVIDER_REGISTRY
                if slug in PROVIDER_REGISTRY:
                    slug = "imported-provider"
            except Exception:
                pass

            return slug

        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only http/https allowed.")
            
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'QWED-CLI'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                
            data = yaml.safe_load(content)
            
            if not isinstance(data, dict):
                raise ValueError("Invalid YAML structure")
                
            # Allow importing raw dict directly, or nested "providers" block
            if "providers" in data:
                slugs = list(data["providers"].keys())
                if not slugs:
                    raise ValueError("No providers found in YAML")
                raw_slug = slugs[0]
                slug = _sanitize_slug(raw_slug)
                config = data["providers"][raw_slug]
            else:
                # Direct format
                config = data
                slug = _sanitize_slug(config.get("name", "imported-provider"))
            
            # Validate security fields
            required_fields = ["base_url", "api_key_env"]
            missing = [f for f in required_fields if f not in config]
            if missing:
                raise ValueError(f"Missing required fields: {', '.join(missing)}")
                
            # Construct strict dict to prevent arbitrary injection
            clean_config = {
                "base_url": str(config["base_url"]),
                "api_key_env": str(config["api_key_env"]),
                "default_model": str(config.get("default_model", "gpt-4o-mini")),
                "models_endpoint": str(config.get("models_endpoint", "/models")),
                "auth_header": str(config.get("auth_header", "Authorization")),
                "auth_prefix": str(config.get("auth_prefix", "Bearer"))
            }
            
            self.save_provider(slug, clean_config)
            return slug
            
        except urllib.error.URLError as e:
            raise ValueError(f"Failed to fetch URL: {type(e).__name__}") from e
        except yaml.YAMLError as e:
            raise ValueError("Invalid YAML syntax in community file") from e
