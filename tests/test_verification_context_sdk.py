import secrets

from qwed_sdk.client import QWEDClient


def test_sdk_verification_context_methods_call_endpoints(monkeypatch):
    api_key = f"qwed-test-{secrets.token_hex(8)}"
    client = QWEDClient(api_key=api_key)
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

    assert calls == [
        (
            "POST",
            "/verification-context/from-diagnostic",
            {
                "diagnostic": {"status": "UNVERIFIABLE"},
                "query": "mean of a == 2",
                "verifier": "TestVerifier",
                "verifier_version": None,
                "attestation_token": None,
            },
        ),
        ("POST", "/verification-context/validate", {"document": {"spec_version": "1.0"}}),
        ("POST", "/verification-context/resolve", {"document": {"spec_version": "1.0"}}),
    ]
