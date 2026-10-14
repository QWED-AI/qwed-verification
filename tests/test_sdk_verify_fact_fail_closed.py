"""#326: QWEDClient.verify_fact must fail closed when the verification service is
unreachable or unresponsive. Absence of verification is UNVERIFIABLE, never
VERIFIED — a local PII scan is one guard, not the fact check."""
import os

import httpx
import pytest

from qwed_sdk.client import QWEDClient

# Not a real key: the tests monkeypatch _request, so no key is ever used.
_PLACEHOLDER_KEY = os.environ.get("QWED_TEST_API_KEY", "placeholder")


def _client():
    return QWEDClient(api_key=_PLACEHOLDER_KEY, base_url="http://localhost:8000")


@pytest.mark.parametrize("exc", [
    httpx.ConnectError("connection refused"),
    httpx.ConnectTimeout("connect timed out"),
    httpx.ReadTimeout("read timed out"),
])
def test_verify_fact_is_unverifiable_when_service_unreachable(monkeypatch, exc):
    client = _client()

    # The local PII scan passes (no PII in the claim), then the remote call fails.
    def unreachable(*args, **kwargs):
        raise exc

    monkeypatch.setattr(client, "_request", unreachable)

    result = client.verify_fact("The sky is blue.", "General knowledge.")

    assert result.status == "UNVERIFIABLE"
    assert result.is_verified is False


def test_verify_fact_does_not_report_verified_offline(monkeypatch):
    client = _client()

    def unreachable(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(client, "_request", unreachable)

    result = client.verify_fact("2 + 2 = 5", "Arithmetic.")

    # The old behaviour returned VERIFIED/is_verified=True here — the fail-open.
    assert result.status != "VERIFIED"
    assert result.is_verified is False
