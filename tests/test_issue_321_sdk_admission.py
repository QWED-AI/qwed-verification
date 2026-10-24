"""#321: the Python SDK verifies the admission an attestation signs.

The server signs its admission into the token (``qwed.admission``) on a
route that decides one. The client's verify_attestation checks the answer's
``admission`` is the one signed, so an answer edited to say ADMIT, or one
whose token signs no admission, is refused; an answer without an admission
needs a token that signs none.
"""

import asyncio
import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.core import attestation as server_attestation
from qwed_new.core.attestation import AttestationService
from qwed_new.core.attestation import VerificationResult as ServerResult
from qwed_new.core.tenant_context import TenantContext
from qwed_sdk import (
    AttestationError,
    QWEDAsyncClient,
    QWEDClient,
    VerificationResult,
    verify_attestation,
)
from qwed_sdk.attestation import check_admission

PROOF = "sha256:" + "e" * 64
QUERY = "2+2=4"


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture
def server():
    service = AttestationService(key_continuity_policy="configured", private_key_pem=_pem(), validity_seconds=3600)
    jwks = {"keys": [{**k, "alg": "ES256", "use": "sig"} for k in service.get_issuer_info()["public_keys"]]}
    return service, jwks


def _token(service, admission=None):
    result = ServerResult(status="VERIFIED", verified=True, engine="math")
    return service.create_attestation(result, QUERY, proof_hash=PROOF, store=False, admission=admission).jwt_token


def _client(jwks):
    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=jwks)))
    return client


def _answer(token, admission=None):
    answer = {"status": "VERIFIED", "attestation": token, "proof_ref": PROOF}
    if admission is not None:
        answer["admission"] = admission
    return answer


@pytest.mark.parametrize("admission", ["ADMIT", "BLOCKED", None])
def test_an_answer_whose_admission_is_signed_verifies(server, admission):
    service, jwks = server

    claims = _client(jwks).verify_attestation(_answer(_token(service, admission), admission))

    assert claims["qwed"].get("admission") == admission


@pytest.mark.parametrize("signed, carried", [
    ("BLOCKED", "ADMIT"),   # an answer edited to say ADMIT
    (None, "ADMIT"),        # a token that signs no admission
    ("ADMIT", None),        # an answer that dropped its admission
    ("ADMIT", "UNKNOWN"),
])
def test_an_answer_whose_admission_is_not_signed_is_refused(server, signed, carried):
    service, jwks = server
    answer = _answer(_token(service, signed), carried)

    with pytest.raises(AttestationError, match="another admission"):
        _client(jwks).verify_attestation(answer)


def test_a_typed_result_carries_its_admission(server):
    service, jwks = server
    typed = VerificationResult.from_dict(_answer(_token(service, "ADMIT"), "ADMIT"))
    edited = VerificationResult.from_dict(_answer(_token(service, "BLOCKED"), "ADMIT"))
    client = _client(jwks)

    assert typed.admission == "ADMIT"
    assert client.verify_attestation(typed)["qwed"]["admission"] == "ADMIT"
    with pytest.raises(AttestationError, match="another admission"):
        client.verify_attestation(edited)
    assert VerificationResult.from_dict({"status": "VERIFIED", "admission": 1}).admission is None


def test_the_async_client_checks_the_admission_too(server):
    service, jwks = server
    edited = _answer(_token(service, "BLOCKED"), "ADMIT")

    async def run():
        async with QWEDAsyncClient(api_key="k", base_url="http://qwed.test") as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=jwks)))
            client._jwks_fetched_at = time.monotonic()
            await client.verify_attestation(edited)

    with pytest.raises(AttestationError, match="another admission"):
        asyncio.run(run())


def test_verify_attestation_checks_an_admission_given_to_it(server):
    service, jwks = server
    token = _token(service, "BLOCKED")

    assert verify_attestation(token, jwks, proof_ref=PROOF, admission="BLOCKED")["qwed"]["admission"] == "BLOCKED"
    assert verify_attestation(token, jwks, proof_ref=PROOF)["qwed"]["admission"] == "BLOCKED"
    with pytest.raises(AttestationError, match="another admission"):
        verify_attestation(token, jwks, proof_ref=PROOF, admission="ADMIT")


def test_check_admission_reads_only_the_qwed_claims():
    check_admission({"qwed": {"admission": "ADMIT"}}, "ADMIT")
    check_admission({"qwed": {}}, None)
    check_admission({}, None)
    with pytest.raises(AttestationError):
        check_admission({"admission": "ADMIT", "qwed": {}}, "ADMIT")


# ---------------------------------------------------------------- end to end

@pytest.fixture
def live(isolated_audit_chain, monkeypatch):
    monkeypatch.setattr(server_attestation, "_default_service", None)
    monkeypatch.setenv(server_attestation.SIGNING_KEY_ENV, _pem().decode())
    tenant = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")
    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = lambda: None
    monkeypatch.setattr(api_main, "check_rate_limit", lambda *a, **k: None)
    client = QWEDClient(api_key="k", base_url="http://testserver")
    client._client = TestClient(api_main.app)
    try:
        yield client
    finally:
        api_main.app.dependency_overrides.clear()


@pytest.mark.parametrize("expression, admission", [("2+2=4", "ADMIT"), ("2+2=5", "BLOCKED")])
def test_a_live_answers_admission_verifies(live, expression, admission):
    result = live.verify_math(expression)

    assert result.status == "VERIFIED"
    assert result.admission == admission
    assert live.verify_attestation(result, query=expression)["qwed"]["admission"] == admission


def test_a_live_blocked_answer_edited_to_admit_is_refused(live):
    # 2+2=5 is proven false: VERIFIED, BLOCKED. Saying ADMIT does not make it so.
    answer = live.verify_math("2+2=5").result
    answer["admission"] = "ADMIT"

    with pytest.raises(AttestationError, match="another admission"):
        live.verify_attestation(answer)
