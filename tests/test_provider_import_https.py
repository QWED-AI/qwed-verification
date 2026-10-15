"""#229: provider YAML imported from a URL is executable config (endpoints, auth,
processing logic, a credential-exfiltrating CUSTOM_API_KEY). Over http:// a
network MITM can substitute it, so import_provider_from_url must reject cleartext
and accept only https:// — before any fetch."""
from unittest.mock import patch

import pytest

from qwed_new.providers.config_manager import ProviderConfigManager


def _mgr(tmp_path):
    return ProviderConfigManager(tmp_path / "providers.yaml")


def test_http_url_is_rejected_before_any_fetch(tmp_path):
    mgr = _mgr(tmp_path)
    with patch("urllib.request.urlopen") as fake_open:
        with pytest.raises(ValueError, match="https"):
            mgr.import_provider_from_url("http://example.com/provider.yaml")
        fake_open.assert_not_called()


@pytest.mark.parametrize("url", [
    "ftp://example.com/provider.yaml",
    "file:///etc/passwd",
    "gopher://example.com/",
])
def test_non_https_schemes_are_rejected(tmp_path, url):
    mgr = _mgr(tmp_path)
    with patch("urllib.request.urlopen") as fake_open:
        with pytest.raises(ValueError, match="scheme"):
            mgr.import_provider_from_url(url)
        fake_open.assert_not_called()


class _SchemeGatePassed(Exception):
    """Sentinel: raised from the SSRF stage to prove https cleared the scheme gate."""


def test_https_url_clears_the_scheme_gate(tmp_path):
    # https must NOT be rejected by the scheme check. Stop the flow at the next
    # stage (the SSRF validator) with a sentinel so no real network call runs.
    mgr = _mgr(tmp_path)
    with patch("qwed_new.core.url_guard.validate_fetch_url", side_effect=_SchemeGatePassed):
        with pytest.raises(_SchemeGatePassed):
            mgr.import_provider_from_url("https://example.com/provider.yaml")
