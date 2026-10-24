"""#319 (part 2): attestation tokens are delivered, and verifiable.

Every VERIFIED result was signed and its token checked inside the server
(#320), then dropped: no response carried it and nothing published the key,
so a consumer could not tell a genuine QWED verdict from a forged one.

Now a VERIFIED result that passes the trust step carries its token
(``attestation``) in the response, and ``GET /.well-known/jwks.json``
publishes the public key that verifies it. Revocation is held per process,
so delivered tokens are short-lived instead: ``QWED_ATTESTATION_TTL_SECONDS``,
24 hours by default, from 60 seconds to 30 days.
"""

import hashlib
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.api.verification_context_routes import (
    DiagnosticVerificationContextRequest,
    create_verification_context_from_diagnostic,
)
from qwed_new.core import attestation, trust
from qwed_new.core.attestation import (
    SIGNING_KEY_ENV,
    SIGNING_KEY_FILE_ENV,
    TTL_ENV,
    AttestationConfigError,
    AttestationResult,
    AttestationStatus,
    get_attestation_service,
    jwk_thumbprint,
)
from qwed_new.core.diagnostics import (
    DiagnosticResult,
    DiagnosticStatus,
    merge_diagnostic_result,
)
from qwed_new.core.tenant_context import TenantContext

TENANT = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")
PROOF = "sha256:" + "d" * 64


@pytest.fixture
def fresh_service(monkeypatch):
    """No default service yet, and none of the settings set."""
    monkeypatch.setattr(attestation, "_default_service", None)
    for name in (SIGNING_KEY_ENV, SIGNING_KEY_FILE_ENV, TTL_ENV):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def client(isolated_audit_chain, fresh_service):
    def _mock_session():
        return MagicMock()

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: TENANT
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _jwks_key(client, kid):
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    return jwt.PyJWK(next(k for k in keys if k["kid"] == kid)).key


def _verify(client, token):
    """What a consumer does: the key the token's kid names, from the JWKS."""
    kid = jwt.get_unverified_header(token)["kid"]
    return jwt.decode(token, _jwks_key(client, kid), algorithms=["ES256"])


# ---------------------------------------------------------------- delivery

@pytest.mark.parametrize("expression, admission", [("2+2=4", "ADMIT"), ("2+2=5", "BLOCKED")])
def test_a_verified_response_carries_a_token_a_consumer_can_verify(client, expression, admission):
    body = client.post("/verify/math", json={"expression": expression}).json()

    assert body["status"] == "VERIFIED"
    assert body["admission"] == admission  # a disproven identity is attested too
    claims = _verify(client, body["attestation"])
    assert claims["qwed"]["result"]["status"] == "VERIFIED"
    assert claims["qwed"]["proof_hash"] == body["proof_ref"]
    assert claims["qwed"]["query_hash"] == "sha256:" + hashlib.sha256(expression.encode()).hexdigest()


def test_a_response_that_is_not_verified_carries_no_token(client):
    body = client.post("/verify/math", json={"expression": "1/2(3+1)"}).json()

    assert body["status"] == "BLOCKED"
    assert "attestation" not in body


def test_a_verified_result_whose_signing_fails_carries_no_token(client, monkeypatch):
    def fail(**kwargs):
        return AttestationResult(status=AttestationStatus.BLOCKED, token=None, error_code="SIGNING_FAILURE", error="x")

    monkeypatch.setattr(trust, "create_verification_attestation", fail)

    body = client.post("/verify/math", json={"expression": "2+2=4"}).json()

    assert body["status"] == "BLOCKED"
    assert "attestation" not in body


def test_a_batch_item_carries_its_token(client):
    body = client.post("/verify/batch", json={"items": [
        {"query": "2 + 2 = 4", "type": "math"},
        {"query": "2 + 2 = 5", "type": "math"},
    ]}).json()
    proven, not_equal = (item["result"] for item in body["items"])

    assert _verify(client, proven["attestation"])["qwed"]["proof_hash"] == proven["proof_ref"]
    assert not_equal["status"] == "UNVERIFIABLE"
    assert "attestation" not in not_equal


# ---------------------------------------------------------------- the JWKS

def test_the_jwks_is_public_and_cacheable(fresh_service):
    response = TestClient(api_main.app).get("/.well-known/jwks.json")  # no API key

    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    (key,) = response.json()["keys"]
    assert {key["kty"], key["crv"], key["alg"], key["use"]} == {"EC", "P-256", "ES256", "sig"}
    assert "d" not in key  # the private scalar never leaves


def test_with_a_configured_key_the_jwks_names_it_by_its_thumbprint(fresh_service):
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fresh_service.setenv(SIGNING_KEY_ENV, pem.decode())

    (key,) = TestClient(api_main.app).get("/.well-known/jwks.json").json()["keys"]

    assert key["kid"] == f"did:qwed:node:local#{jwk_thumbprint(private.public_key())}"


def test_the_jwks_says_nothing_when_the_key_is_unavailable(fresh_service):
    fresh_service.setattr("qwed_new.api.attestation_routes.get_attestation_service", _raise)

    response = TestClient(api_main.app).get("/.well-known/jwks.json")

    assert response.status_code == 503
    assert response.json() == {"detail": "attestation key unavailable"}


def _raise():
    raise AttestationConfigError("internal detail")


# ---------------------------------------------------------------- lifetime

def test_a_token_lasts_24_hours_by_default(client):
    claims = _verify(client, client.post("/verify/math", json={"expression": "2+2=4"}).json()["attestation"])

    assert claims["exp"] - claims["iat"] == 24 * 60 * 60


def test_the_lifetime_can_be_set(fresh_service):
    fresh_service.setenv(TTL_ENV, "3600")
    token = attestation.create_verification_attestation(
        status="VERIFIED", verified=True, engine="math", query="q", proof_hash=PROOF,
    ).token
    claims = jwt.decode(token, options={"verify_signature": False})

    assert claims["exp"] - claims["iat"] == 3600


@pytest.mark.parametrize("value", ["0", "59", str(30 * 24 * 60 * 60 + 1), "abc", "-5", "1.5", "3600s"])
def test_an_unusable_lifetime_stops_the_service(fresh_service, value):
    fresh_service.setenv(TTL_ENV, value)

    with pytest.raises(AttestationConfigError):
        get_attestation_service()
    assert attestation._default_service is None


@pytest.mark.parametrize("value", ["60", str(30 * 24 * 60 * 60)])
def test_the_lifetime_bounds_are_inclusive(fresh_service, value):
    fresh_service.setenv(TTL_ENV, value)

    assert get_attestation_service().validity_seconds == int(value)


def test_the_server_does_not_start_with_an_unusable_lifetime(fresh_service):
    fresh_service.setenv(TTL_ENV, "forever")
    for step in ("_enforce_environment_integrity", "create_db_and_tables", "get_audit_logger", "_migrate_agent_tokens"):
        fresh_service.setattr(api_main, step, lambda: None)

    with pytest.raises(AttestationConfigError):
        api_main.on_startup()


# ---------------------------------------------------------------- the token is the server's alone

def _verified(**fields):
    return DiagnosticResult(status=DiagnosticStatus.VERIFIED, agent_message="m", developer_fields=fields, proof_ref=PROOF)


def test_only_a_verified_result_carries_a_token():
    with pytest.raises(ValueError):
        DiagnosticResult(status=DiagnosticStatus.UNVERIFIABLE, agent_message="m", attestation="t")
    with pytest.raises(ValueError):
        DiagnosticResult(status=DiagnosticStatus.VERIFIED, agent_message="m", proof_ref=PROOF, attestation="")


def test_a_result_without_a_token_keeps_its_shape():
    assert "attestation" not in _verified().to_dict()


def test_a_token_is_never_read_from_input():
    dr = DiagnosticResult.from_dict({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF, "attestation": "forged"})

    assert dr.attestation is None


def test_developer_fields_cannot_put_a_token_in_a_response():
    merged = merge_diagnostic_result(_verified(attestation="forged"))

    assert "attestation" not in merged


def test_a_caller_diagnostic_never_brings_its_own_token():
    payload = DiagnosticVerificationContextRequest(
        query="q", verifier="TestVerifier",
        diagnostic={"status": "UNVERIFIABLE", "agent_message": "m", "attestation": "forged",
                    "developer_fields": {"attestation": "forged"}},
    )
    evidence = create_verification_context_from_diagnostic(payload, tenant=TENANT, session=None)["context"]["evidence"]["evidence"]

    assert "attestation" not in evidence
    assert evidence["developer_fields"]["caller_supplied"]["developer_fields"] == {"attestation": "forged"}


def test_with_attestation_keeps_every_other_field():
    # Built field by field (Sonar could not type dataclasses.replace), so a
    # field added to DiagnosticResult and not copied there fails this.
    import dataclasses

    original = _verified(note="n")
    delivered = original.with_attestation("token")

    def every_field_but_the_token(result):
        return {name: value for name, value in dataclasses.asdict(result).items() if name != "attestation"}

    assert delivered.attestation == "token"
    assert every_field_but_the_token(delivered) == every_field_but_the_token(original)
    # Every field is compared, so an added one that is not copied fails here.
    assert set(dataclasses.asdict(delivered)) == {f.name for f in dataclasses.fields(DiagnosticResult)}


def test_with_attestation_still_refuses_a_result_that_is_not_verified():
    unverified = DiagnosticResult(status=DiagnosticStatus.UNVERIFIABLE, agent_message="m")

    with pytest.raises(ValueError):
        unverified.with_attestation("token")
