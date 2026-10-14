"""#326: QWEDClient.verify_fact must fail closed when the verification service is
unreachable. Absence of verification is UNVERIFIABLE, never VERIFIED — a local
PII scan is one guard, not the fact check."""
import httpx

from qwed_sdk.client import QWEDClient


def test_verify_fact_is_unverifiable_when_service_unreachable(monkeypatch):
    client = QWEDClient(api_key="qwed_test", base_url="http://localhost:8000")

    # The local PII scan passes (no PII in the claim), then the remote call fails.
    def unreachable(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(client, "_request", unreachable)

    result = client.verify_fact("The sky is blue.", "General knowledge.")

    assert result.status == "UNVERIFIABLE"
    assert result.is_verified is False


def test_verify_fact_does_not_report_verified_offline(monkeypatch):
    client = QWEDClient(api_key="qwed_test", base_url="http://localhost:8000")
    monkeypatch.setattr(client, "_request", lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("down")))

    result = client.verify_fact("2 + 2 = 5", "Arithmetic.")

    # The old behaviour returned VERIFIED/is_verified=True here — the fail-open.
    assert result.status != "VERIFIED"
    assert result.is_verified is False
