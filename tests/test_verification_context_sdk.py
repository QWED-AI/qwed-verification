from qwed_sdk.client import QWEDClient


def test_sdk_verification_context_methods_call_endpoints(monkeypatch):
    client = QWEDClient(api_key="qwed_test")
    calls = []

    def _fake_request(method, endpoint, **kwargs):
        calls.append((method, endpoint, kwargs.get("json")))
        return {}

    monkeypatch.setattr(client, "_request", _fake_request)

    client.create_verification_context_from_diagnostic(
        diagnostic={"status": "UNVERIFIABLE"},
        query="mean of a == 2",
        verifier="TestVerifier",
    )
    client.validate_verification_context({"spec_version": "1.0"})
    client.resolve_verification_context({"spec_version": "1.0"})

    assert calls[0][1] == "/verification-context/from-diagnostic"
    assert calls[1][1] == "/verification-context/validate"
    assert calls[2][1] == "/verification-context/resolve"
