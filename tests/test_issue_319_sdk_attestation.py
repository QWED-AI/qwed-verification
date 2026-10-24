"""#319 (part 3): the Python SDK reads and verifies attestations.

The server now returns ``attestation`` with every VERIFIED answer and
publishes its key at ``/.well-known/jwks.json``. The SDK keeps the token on
VerificationResult and verifies it: the ES256 signature with the key its
``kid`` names, the issuer and expiry, a VERIFIED status, and that it is this
answer's token (``proof_hash`` is the answer's ``proof_ref``; optionally,
``query_hash`` is the statement's).

Tokens are issued at test time, by the server's own code; none is stored in
the repository.
"""

import asyncio
import time

import httpx
import jwt
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
from qwed_sdk.attestation import UnknownKeyError, statement_hash

PROOF = "sha256:" + "e" * 64
QUERY = "2+2=4"


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture
def server():
    """A server-side service with a configured key, and its JWKS."""
    service = AttestationService(key_continuity_policy="configured", private_key_pem=_pem(), validity_seconds=3600)
    jwks = {"keys": [{**k, "alg": "ES256", "use": "sig"} for k in service.get_issuer_info()["public_keys"]]}
    return service, jwks


def _token(service, status="VERIFIED", proof_hash=PROOF, query=QUERY, issued_at=None):
    result = ServerResult(status=status, verified=True, engine="math")
    return service.create_attestation(result, query, proof_hash=proof_hash, issued_at=issued_at, store=False).jwt_token


# ---------------------------------------------------------------- verify_attestation

def test_a_genuine_attestation_verifies(server):
    service, jwks = server

    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF, query=QUERY)

    assert claims["qwed"]["proof_hash"] == PROOF
    assert claims["qwed"]["query_hash"] == statement_hash(QUERY)


def test_another_answers_token_is_refused(server):
    service, jwks = server

    with pytest.raises(AttestationError, match="another answer"):
        verify_attestation(_token(service), jwks, proof_ref="sha256:" + "f" * 64)


def test_a_token_for_another_statement_is_refused(server):
    service, jwks = server

    with pytest.raises(AttestationError, match="another statement"):
        verify_attestation(_token(service), jwks, proof_ref=PROOF, query="2+2=5")


def test_a_token_that_does_not_attest_verified_is_refused(server):
    service, jwks = server

    with pytest.raises(AttestationError, match="VERIFIED"):
        verify_attestation(_token(service, status="BLOCKED"), jwks, proof_ref=PROOF)


def test_an_expired_token_is_refused(server):
    service, jwks = server
    token = _token(service, issued_at=int(time.time()) - 7200)  # lived 3600 s

    with pytest.raises(AttestationError, match="expired"):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_a_token_from_another_key_is_refused(server):
    _, jwks = server
    stranger = AttestationService(key_continuity_policy="configured", private_key_pem=_pem())

    # Its kid is its own thumbprint, which this JWKS does not hold.
    with pytest.raises(UnknownKeyError):
        verify_attestation(_token(stranger), jwks, proof_ref=PROOF)


def test_a_token_signed_by_another_key_under_the_right_kid_is_refused(server):
    service, jwks = server
    forger = ec.generate_private_key(ec.SECP256R1())
    claims = jwt.decode(_token(service), options={"verify_signature": False})
    forged = jwt.encode(claims, forger, algorithm="ES256",
                        headers={"kid": service.key_id, "typ": "qwed-attestation+jwt"})

    with pytest.raises(AttestationError, match="signature"):
        verify_attestation(forged, jwks, proof_ref=PROOF)


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_a_token_naming_another_algorithm_is_refused_before_any_key_is_used(server, alg):
    service, jwks = server
    claims = jwt.decode(_token(service), options={"verify_signature": False})
    header = {"kid": service.key_id, "typ": "qwed-attestation+jwt"}
    token = jwt.encode(claims, "k" * 32, algorithm="HS256", headers=header) if alg == "HS256" else \
        jwt.encode(claims, None, algorithm="none", headers=header)

    with pytest.raises(AttestationError, match="ES256"):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_another_issuer_is_refused(server):
    service, jwks = server

    with pytest.raises(AttestationError, match="claims"):
        verify_attestation(_token(service), jwks, proof_ref=PROOF, issuer="did:example:other")


@pytest.mark.parametrize("token", ["", "not.a.jwt", None])
def test_no_token_or_a_malformed_one_is_refused(server, token):
    _, jwks = server

    with pytest.raises(AttestationError):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_a_jwks_key_that_is_not_es256_p256_is_refused(server):
    service, jwks = server
    bad = {"keys": [{**jwks["keys"][0], "crv": "P-384"}]}

    with pytest.raises(AttestationError, match="ES256 P-256"):
        verify_attestation(_token(service), bad, proof_ref=PROOF)


# ---------------------------------------------------------------- the result type

def test_a_result_keeps_its_attestation_and_proof_ref():
    typed = VerificationResult.from_dict({"status": "VERIFIED", "attestation": "t", "proof_ref": PROOF})
    untyped = VerificationResult.from_dict({"status": "BLOCKED", "attestation": 1})

    assert (typed.attestation, typed.proof_ref) == ("t", PROOF)
    assert (untyped.attestation, untyped.proof_ref) == (None, None)


# ---------------------------------------------------------------- the client, against the server

@pytest.fixture
def live(isolated_audit_chain, monkeypatch):
    """A QWEDClient talking to the app in process, with a configured key."""
    monkeypatch.setattr(server_attestation, "_default_service", None)
    monkeypatch.setenv(server_attestation.SIGNING_KEY_ENV, _pem().decode())
    tenant = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")

    def _mock_session():
        from unittest.mock import MagicMock
        return MagicMock()

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    monkeypatch.setattr(api_main, "check_rate_limit", lambda *a, **k: None)
    client = QWEDClient(api_key="k", base_url="http://testserver")
    client._client = TestClient(api_main.app)
    try:
        yield client
    finally:
        api_main.app.dependency_overrides.clear()


def test_the_client_verifies_a_live_answer_end_to_end(live):
    result = live.verify_math(QUERY)

    assert result.status == "VERIFIED"
    claims = live.verify_attestation(result, query=QUERY)
    assert claims["qwed"]["proof_hash"] == result.proof_ref


def test_the_client_refuses_a_live_answer_whose_proof_ref_was_changed(live):
    answer = live.verify_math(QUERY).result
    answer["proof_ref"] = "sha256:" + "0" * 64

    with pytest.raises(AttestationError, match="another answer"):
        live.verify_attestation(answer)


def test_the_client_fetches_the_jwks_again_when_the_kid_is_unknown(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        # The first fetch is stale (an old key); the second has the new one.
        body = {"keys": []} if len(calls) == 1 else jwks
        return httpx.Response(200, json=body)

    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    claims = client.verify_attestation({"attestation": _token(service), "proof_ref": PROOF})

    assert claims["qwed"]["proof_hash"] == PROOF
    assert calls == ["/.well-known/jwks.json", "/.well-known/jwks.json"]


def test_the_client_reuses_the_jwks_within_its_lifetime(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    answer = {"attestation": _token(service), "proof_ref": PROOF}

    client.verify_attestation(answer)
    client.verify_attestation(answer)

    assert len(calls) == 1


def test_the_async_client_verifies_too(server):
    service, jwks = server

    async def run():
        async with QWEDAsyncClient(api_key="k", base_url="http://qwed.test") as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=jwks)))
            return await client.verify_attestation({"attestation": _token(service), "proof_ref": PROOF}, query=QUERY)

    assert asyncio.run(run())["qwed"]["proof_hash"] == PROOF
