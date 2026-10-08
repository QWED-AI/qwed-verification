"""SSRF guard tests (issue #423).

The guard inspects literal-IP hosts only and never resolves DNS, so these
tests run fully offline: unresolvable names pass the helper (documented
residual), literal bad IPs raise before any fetch.
"""

import urllib.error
import urllib.request

import pytest

from qwed_new.core.url_guard import (
    MAX_REDIRECTS,
    _RedirectLimitHandler,
    limited_redirects,
    validate_fetch_url,
)


class TestValidateFetchUrl:
    def test_metadata_ips_rejected(self):
        for url in (
            "http://169.254.169.254/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/",
            "http://[::ffff:169.254.169.254]/",
        ):
            with pytest.raises(ValueError, match="[Mm]etadata|non-public"):
                validate_fetch_url(url)

    def test_metadata_rejected_even_when_local_allowed(self):
        with pytest.raises(ValueError, match="[Mm]etadata"):
            validate_fetch_url("http://169.254.169.254/", allow_local=True)

    def test_loopback_and_private_rejected_by_default(self):
        for url in (
            "http://127.0.0.1:8080/hook",
            "http://10.0.0.5/x",
            "http://172.16.9.9/x",
            "http://192.168.1.20/x",
            "http://[::1]/x",
        ):
            with pytest.raises(ValueError, match="non-public"):
                validate_fetch_url(url)

    def test_allow_local_permits_private_but_not_metadata(self):
        assert (
            validate_fetch_url("http://127.0.0.1:8080/hook", allow_local=True)
            == "http://127.0.0.1:8080/hook"
        )
        assert (
            validate_fetch_url("http://192.168.1.20/x", allow_local=True)
            == "http://192.168.1.20/x"
        )
        with pytest.raises(ValueError, match="[Mm]etadata"):
            validate_fetch_url("http://169.254.169.254/", allow_local=True)

    def test_non_http_schemes_rejected(self):
        for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x/"):
            with pytest.raises(ValueError, match="Unsupported URL scheme"):
                validate_fetch_url(url)

    def test_dns_names_pass_through_unresolved(self):
        # Deliberate: no getaddrinfo here (offline-safe, mock-safe). DNS
        # names are accepted; only literal IPs are judged.
        assert (
            validate_fetch_url("https://example.com/provider.yaml")
            == "https://example.com/provider.yaml"
        )
        assert validate_fetch_url("http://fake") == "http://fake"


class TestRedirectLimitHandler:
    def _req(self, url="http://example.com/"):
        return urllib.request.Request(url)

    def test_excess_redirects_raise(self):
        handler = _RedirectLimitHandler()
        req = self._req()
        headers = {}
        for _ in range(MAX_REDIRECTS):
            req = handler.redirect_request(req, None, 302, "Found", headers, "http://example.com/")
            assert req is not None
        with pytest.raises(urllib.error.HTTPError, match="[Tt]oo many redirects"):
            handler.redirect_request(req, None, 302, "Found", headers, "http://example.com/")

    def test_blocked_redirect_target_rejected(self):
        handler = _RedirectLimitHandler()
        with pytest.raises(ValueError, match="[Mm]etadata|non-public"):
            handler.redirect_request(
                self._req(), None, 302, "Found", {}, "http://169.254.169.254/"
            )

    def test_limited_redirects_restores_global_opener(self):
        import urllib.request as urlrequest

        before = urlrequest._opener
        with limited_redirects():
            assert urlrequest._opener is not before or urlrequest._opener is not None
        assert urlrequest._opener is before


class TestProviderImportGuard:
    def test_metadata_url_fails_before_fetch(self, tmp_path):
        from unittest.mock import patch

        from qwed_new.providers.config_manager import ProviderConfigManager

        manager = ProviderConfigManager(tmp_path / "providers.yaml")
        with patch("urllib.request.urlopen") as fake_open:
            with pytest.raises(ValueError):
                manager.import_provider_from_url("http://169.254.169.254/")
            fake_open.assert_not_called()


class TestAlertingWebhookGuard:
    def test_bad_webhook_url_disabled(self, monkeypatch):
        from qwed_new.core.alerting import AlertManager

        monkeypatch.setenv("SLACK_WEBHOOK_URL", "http://169.254.169.254/hook")
        assert AlertManager().slack_webhook_url is None

    def test_good_webhook_url_kept(self, monkeypatch):
        from qwed_new.core.alerting import AlertManager

        monkeypatch.setenv(
            "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X"
        )
        assert (
            AlertManager().slack_webhook_url
            == "https://hooks.slack.com/services/T/B/X"
        )

    def test_unset_webhook_stays_unset(self, monkeypatch):
        from qwed_new.core.alerting import AlertManager

        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        assert AlertManager().slack_webhook_url is None
