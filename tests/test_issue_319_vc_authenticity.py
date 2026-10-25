"""#319: a Verification Context document is signed by the server that issued it.

A document's ``proof_ref`` is an unkeyed commitment: anyone can build a
document, an ADMIT one included, whose ``proof_ref`` resolves. So
/verification-context/from-diagnostic now returns a spec v1.1 document whose
``attestation`` (an ES256 JWT of type ``qwed-context+jwt``) signs the hash
of the whole document with its verdict, admission and ``proof_ref``. The
SDK verifies it against the server's JWKS, and its validate and resolve
require it by default.

Tokens are issued at test time, by the server's own code; none is stored in
the repository.
"""

import asyncio
import copy
import json
import re
import time
from pathlib import Path

import httpx
import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from qwed_new.api.verification_context_routes import (
    DiagnosticVerificationContextRequest,
    VerificationContextDocumentRequest,
    create_verification_context_from_diagnostic,
    resolve_verification_context,
    validate_verification_context,
)
from qwed_new.core import attestation
from qwed_new.core.attestation import (
    CONTEXT_TOKEN_TYPE,
    SIGNING_KEY_ENV,
    SIGNING_KEY_FILE_ENV,
    TTL_ENV,
    AttestationService,
    VerificationResult,
    create_verification_attestation,
    get_attestation_service,
)
from qwed_new.core.diagnostics import (
    DiagnosticResult,
    DiagnosticStatus,
    compute_proof_ref,
    enforce_trust_decision,
)
from qwed_new.core.tenant_context import TenantContext
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    compute_document_hash,
    compute_document_proof_ref,
    document_attestation_mismatch,
    load_schema,
    resolve_document_proof_ref,
    validate_document,
)
from qwed_new.core.verification_context_attestation import attest_document
from qwed_sdk import QWEDAsyncClient, QWEDClient
from qwed_sdk import client as client_module
from qwed_sdk.attestation import (
    AttestationError,
    KeyMismatchError,
    KeysUnavailableError,
    verify_document_attestation,
)

TENANT = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")
QUERY = "mean of a == 2"
PROOF = compute_proof_ref({"observed": 2})
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fresh_service(monkeypatch):
    monkeypatch.setattr(attestation, "_default_service", None)
    for name in (SIGNING_KEY_ENV, SIGNING_KEY_FILE_ENV, TTL_ENV):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def jwks(fresh_service):
    """The JWKS of the server's own service, as /.well-known/jwks.json has it."""
    keys = get_attestation_service().get_issuer_info()["public_keys"]
    return {"keys": [{**key, "alg": "ES256", "use": "sig"} for key in keys]}


def _verdict_token(admission=None):
    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="stats", query=QUERY, proof_hash=PROOF, admission=admission,
    )
    assert issued.is_issued, issued.error
    return issued.token


def _document(diagnostic=None, attestation_token=None):
    payload = DiagnosticVerificationContextRequest(
        query=QUERY,
        verifier="TestVerifier",
        diagnostic=diagnostic or {"status": "UNVERIFIABLE", "agent_message": "m"},
        attestation_token=attestation_token,
    )
    return create_verification_context_from_diagnostic(payload, tenant=TENANT, session=None)


def _admitted():
    return _document({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}, _verdict_token("ADMIT"))


def _unsigned(document):
    unsigned = {key: value for key, value in copy.deepcopy(document).items() if key != "attestation"}
    unsigned["spec_version"] = "1.0"
    return unsigned


def _context_claims(token):
    is_valid, claims, error = get_attestation_service().verify_attestation(token, token_type=CONTEXT_TOKEN_TYPE)
    assert is_valid, error
    return claims


# ---------------------------------------------------------------- the server signs

def test_from_diagnostic_returns_a_signed_v1_1_document(fresh_service):
    document = _admitted()
    claims = _context_claims(document["attestation"])["qwed"]

    assert document["spec_version"] == "1.1"
    assert claims == {
        "version": "1.1",
        "document_hash": compute_document_hash(document),
        "verdict": "VERIFIED",
        "admission": "ADMIT",
        "proof_ref": document["context"]["evidence"]["proof_ref"],
    }
    validate_document(document)
    assert resolve_document_proof_ref(document)


def test_a_document_that_is_not_verified_is_signed_too(fresh_service):
    # A DENY document is the server's record as well; signing it lets a
    # consumer tell it from one someone else built.
    document = _document()
    claims = _context_claims(document["attestation"])["qwed"]

    assert (document["verdict"], claims["verdict"]) == ("UNVERIFIABLE", "UNVERIFIABLE")
    assert claims["admission"] == "DENY"
    assert claims["proof_ref"] is None


def test_the_server_validates_and_resolves_a_signed_document(fresh_service):
    document = _admitted()
    request = VerificationContextDocumentRequest(document=document)

    assert validate_verification_context(request, tenant=TENANT, session=None) == {"valid": True}
    assert resolve_verification_context(request, tenant=TENANT, session=None) == {"resolved": True}


@pytest.mark.parametrize("failure", [RuntimeError("no key"), attestation.SigningKeyError("unusable key")])
def test_a_document_that_cannot_be_signed_is_a_500(fresh_service, failure):
    def broken():
        raise failure

    fresh_service.setattr("qwed_new.core.verification_context_attestation.get_attestation_service", broken)

    with pytest.raises(HTTPException) as failed:
        _document()

    assert failed.value.status_code == 500
    assert failed.value.detail == "attestation signing failed"


def test_attesting_does_not_change_the_document_given(fresh_service):
    unsigned = _unsigned(_document())
    before = copy.deepcopy(unsigned)

    signed = attest_document(unsigned)

    assert unsigned == before
    assert _unsigned(signed) == unsigned


@pytest.mark.parametrize("document", [{"spec_version": "1.0"}, "not a document"])
def test_only_a_valid_document_is_attested(fresh_service, document):
    with pytest.raises(VerificationContextValidationError):
        attest_document(document)


def test_a_signed_document_is_not_signed_again(fresh_service):
    with pytest.raises(VerificationContextValidationError, match="v1.0"):
        attest_document(_document())


# ---------------------------------------------------------------- the tokens

def _service():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return AttestationService(key_continuity_policy="configured", private_key_pem=pem, validity_seconds=3600)


HASH = "sha256:" + "d" * 64


@pytest.mark.parametrize(
    ("fields", "refusal"),
    [
        ({"document_hash": "d" * 64}, "document_hash"),
        ({"document_hash": None}, "document_hash"),
        ({"verdict": "PROVEN"}, "verdict"),
        ({"verdict": ["VERIFIED"]}, "verdict"),
        ({"admission": "BLOCKED"}, "admission"),
        ({"admission": {"ADMIT": 1}}, "admission"),
        ({"proof_ref": None}, "needs a proof_ref"),
        ({"verdict": "BLOCKED", "admission": "DENY"}, "no proof_ref"),
        ({"verdict": "BLOCKED", "admission": "ADMIT", "proof_ref": None}, "is DENY"),
    ],
)
def test_fields_the_schema_refuses_are_not_signed(fields, refusal):
    signed = {"document_hash": HASH, "verdict": "VERIFIED", "admission": "ADMIT", "proof_ref": PROOF, **fields}

    with pytest.raises(ValueError, match=refusal):
        _service().create_context_attestation(**signed)


def test_a_documents_token_is_not_a_verdicts_nor_the_reverse():
    service = _service()
    document_token = service.create_context_attestation(
        document_hash=HASH, verdict="VERIFIED", admission="ADMIT", proof_ref=PROOF,
    )
    verdict_token = service.create_attestation(
        VerificationResult(status="VERIFIED", verified=True, engine="stats"), QUERY, proof_hash=PROOF, store=False,
    ).jwt_token

    assert service.verify_attestation(document_token)[0] is False
    assert service.verify_attestation(verdict_token, token_type=CONTEXT_TOKEN_TYPE)[0] is False
    assert service.verify_attestation(document_token, token_type=CONTEXT_TOKEN_TYPE)[0] is True
    assert service.verify_attestation(verdict_token)[0] is True


def test_a_documents_token_does_not_pass_the_trust_step(fresh_service):
    token = get_attestation_service().create_context_attestation(
        document_hash=HASH, verdict="VERIFIED", admission="ADMIT", proof_ref=PROOF,
    )
    result = DiagnosticResult(
        status=DiagnosticStatus.VERIFIED, agent_message="ok", developer_fields={"is_valid": True}, proof_ref=PROOF,
    )

    enforced = enforce_trust_decision(result, attestation_token=token, require_attestation=True, query=QUERY)

    assert enforced.status is DiagnosticStatus.BLOCKED


def test_a_documents_token_lasts_as_long_as_a_verdicts():
    service = _service()  # validity_seconds=3600
    token = service.create_context_attestation(
        document_hash=HASH, verdict="VERIFIED", admission="ADMIT", proof_ref=PROOF,
    )

    is_valid, claims, _error = service.verify_attestation(token, token_type=CONTEXT_TOKEN_TYPE)

    assert is_valid
    assert claims["exp"] - claims["iat"] == 3600
    assert claims["sub"] == HASH


# ---------------------------------------------------------------- the hash and the schema

def test_the_document_hash_binds_every_field_but_the_attestation(fresh_service):
    document = _admitted()
    digest = compute_document_hash(document)

    assert compute_document_hash({**document, "attestation": "x.y.z"}) == digest
    for path, value in [
        (("spec_version",), "1.0"),
        (("verdict",), "BLOCKED"),
        (("object", "formal_statement"), "mean of a == 3"),
        (("context", "decision", "admission"), "DENY"),
        (("context", "proof", "verifier"), "Lean"),
        (("context", "evidence", "evidence", "agent_message"), "changed"),
    ]:
        changed = copy.deepcopy(document)
        target = changed
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        assert compute_document_hash(changed) != digest, path


def test_the_document_hash_needs_a_document():
    with pytest.raises(VerificationContextValidationError):
        compute_document_hash(["not", "a", "document"])


def test_a_v1_1_document_must_carry_an_attestation(fresh_service):
    document = _document()

    with pytest.raises(VerificationContextValidationError, match="attestation"):
        validate_document({key: value for key, value in document.items() if key != "attestation"})


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b", "a.b.c.d", "a.b.c d", 7, "a.b." + "c" * 8192])
def test_a_v1_1_attestation_must_be_a_compact_jwt(fresh_service, token):
    with pytest.raises(VerificationContextValidationError):
        validate_document({**_document(), "attestation": token})


def test_a_v1_0_document_carries_no_attestation(fresh_service):
    document = _document()

    with pytest.raises(VerificationContextValidationError):
        validate_document({**document, "spec_version": "1.0"})


def test_an_unknown_spec_version_is_still_refused(fresh_service):
    with pytest.raises(VerificationContextValidationError, match="spec_version"):
        validate_document({**_unsigned(_document()), "spec_version": "2.0"})


def test_the_v1_1_schema_is_published_with_the_spec():
    published = json.loads(
        (REPO_ROOT / "spec" / "v1.1" / "schemas" / "verification-context.schema.json").read_text(encoding="utf-8")
    )

    jsonschema.Draft202012Validator.check_schema(published)
    assert published == load_schema("1.1")
    assert published["$id"].endswith("/v1.1")
    assert load_schema()["properties"]["spec_version"]["const"] == "1.0"


def test_the_claims_must_name_this_document(fresh_service):
    document = _admitted()
    claims = _context_claims(document["attestation"])["qwed"]

    assert document_attestation_mismatch(document, claims) is None
    assert document_attestation_mismatch(document, None) == "attestation signs no document"
    assert document_attestation_mismatch({"spec_version": "1.1"}, claims) == "document is not a Verification Context"
    for claim in ("document_hash", "verdict", "admission", "proof_ref"):
        missing = {key: value for key, value in claims.items() if key != claim}
        assert claim in document_attestation_mismatch(document, missing)


# ---------------------------------------------------------------- the SDK verifies

def test_the_sdk_verifies_a_documents_attestation(jwks):
    document = _admitted()

    claims = verify_document_attestation(document, jwks)

    assert claims["qwed"]["document_hash"] == compute_document_hash(document)


@pytest.mark.parametrize(
    ("path", "value", "differs"),
    [
        (("object", "formal_statement"), "mean of a == 3", "document_hash"),
        (("context", "evidence", "evidence", "agent_message"), "forged", "document_hash"),
        (("context", "proof", "verifier"), "Lean", "document_hash"),
    ],
)
def test_the_sdk_refuses_a_changed_document(jwks, path, value, differs):
    document = _admitted()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(AttestationError, match=differs):
        verify_document_attestation(document, jwks)


def test_the_sdk_refuses_another_documents_attestation(jwks):
    admitted = _admitted()
    denied = _document()

    with pytest.raises(AttestationError, match="another document"):
        verify_document_attestation({**denied, "attestation": admitted["attestation"]}, jwks)


def test_the_sdk_refuses_a_forged_admit_with_a_resolving_proof_ref(jwks):
    # The forgery #319 is about: take a signed DENY document, make it ADMIT,
    # and recompute its proof_ref, which anyone can. It still resolves.
    document = _document({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}, _verdict_token())
    assert document["context"]["decision"]["admission"] == "DENY"

    document["context"]["decision"]["admission"] = "ADMIT"
    document["context"]["evidence"]["proof_ref"] = compute_document_proof_ref(document)
    assert resolve_document_proof_ref(document)

    with pytest.raises(AttestationError, match="another document"):
        verify_document_attestation(document, jwks)


def test_the_sdk_refuses_a_verdicts_token_in_a_document(jwks):
    document = {**_admitted(), "attestation": _verdict_token("ADMIT")}

    with pytest.raises(AttestationError, match=re.escape(CONTEXT_TOKEN_TYPE)):
        verify_document_attestation(document, jwks)


@pytest.mark.parametrize("document", [{"spec_version": "1.0"}, {"attestation": ""}, {"attestation": 7}, "text"])
def test_the_sdk_needs_an_attestation(jwks, document):
    with pytest.raises(AttestationError, match="no attestation"):
        verify_document_attestation(document, jwks)


def test_the_sdk_refuses_a_document_signed_by_another_key(jwks):
    document = _admitted()
    other = _service()
    document["attestation"] = other.create_context_attestation(
        document_hash=compute_document_hash(document), verdict="VERIFIED", admission="ADMIT",
        proof_ref=document["context"]["evidence"]["proof_ref"],
    )

    with pytest.raises(KeyMismatchError):
        verify_document_attestation(document, jwks)


def test_the_sdk_refuses_an_expired_document(jwks):
    document = _unsigned(_document())
    document["spec_version"] = "1.1"
    document["attestation"] = get_attestation_service().create_context_attestation(
        document_hash=compute_document_hash(document), verdict="UNVERIFIABLE", admission="DENY",
        proof_ref=None, issued_at=1000,
    )

    with pytest.raises(AttestationError, match="expired"):
        verify_document_attestation(document, jwks)


# ---------------------------------------------------------------- the clients require it

def _client(jwks, endpoint_calls):
    """A client whose keys are ``jwks`` (or unavailable, for None) and whose
    API calls are recorded."""
    def handler(request):
        if request.url.path == "/.well-known/jwks.json":
            if jwks is None:
                return httpx.Response(503)
            return httpx.Response(200, json=jwks)
        endpoint_calls.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"valid": True, "resolved": True})

    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


@pytest.mark.parametrize(
    ("method", "key"), [("validate_verification_context", "valid"), ("resolve_verification_context", "resolved")],
)
def test_validate_and_resolve_require_an_attestation_by_default(jwks, method, key):
    calls = []
    client = _client(jwks, calls)

    unsigned = getattr(client, method)(_unsigned(_document()))
    forged = getattr(client, method)({**_document(), "verdict": "BLOCKED"})
    signed = getattr(client, method)(_document())

    assert unsigned == {key: False, "error": client_module.ATTESTATION_REQUIRED}
    assert forged == {key: False, "error": client_module.ATTESTATION_INVALID}
    assert signed[key] is True
    # Only the signed document reached the server.
    assert [path for path, _body in calls] == [f"/verification-context/{method.split('_')[0]}"]


@pytest.mark.parametrize("method", ["validate_verification_context", "resolve_verification_context"])
def test_require_attestation_false_checks_the_server_alone(method):
    calls = []
    client = _client(None, calls)  # no keys are fetched

    getattr(client, method)({"spec_version": "1.0"}, require_attestation=False)

    assert calls == [(f"/verification-context/{method.split('_')[0]}", {"document": {"spec_version": "1.0"}})]


def test_keys_that_cannot_be_fetched_decide_nothing(fresh_service):
    calls = []
    client = _client(None, calls)

    with pytest.raises(KeysUnavailableError):
        client.resolve_verification_context(_document())

    assert calls == []


def test_an_unsigned_document_is_refused_before_any_key_is_fetched():
    calls = []
    client = _client(None, calls)

    assert client.validate_verification_context({"spec_version": "1.0"})["error"] == "attestation_required"
    with pytest.raises(AttestationError, match="no attestation"):
        client.verify_document_attestation({"spec_version": "1.0"})


def test_the_client_fetches_the_keys_again_after_a_rotation(jwks):
    # The cached keys are older than the document's key: a key the JWKS does
    # not hold is fetched again, as for a verdict's token.
    document = _admitted()
    stale = {"keys": [{**jwks["keys"][0], **_other_coordinates()}]}
    fetched = []

    def handler(request):
        fetched.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    client._jwks = stale
    client._jwks_fetched_at = client._jwks_attempted_at = time.monotonic() - 60

    claims = client.verify_document_attestation(document)

    assert claims["qwed"]["verdict"] == "VERIFIED"
    assert fetched == ["/.well-known/jwks.json"]


def _other_coordinates():
    other = _service().get_issuer_info()["public_keys"][0]
    return {"x": other["x"], "y": other["y"]}


def test_the_async_client_requires_an_attestation_too(jwks):
    calls = []

    def handler(request):
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(200, json=jwks)
        calls.append(request.url.path)
        return httpx.Response(200, json={"valid": True, "resolved": True})

    async def run():
        client = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            return (
                await client.validate_verification_context(_unsigned(_document())),
                await client.resolve_verification_context({**_document(), "verdict": "BLOCKED"}),
                await client.resolve_verification_context(_document()),
                await client.validate_verification_context({"spec_version": "1.0"}, require_attestation=False),
            )
        finally:
            await client._client.aclose()

    unsigned, forged, signed, unchecked = asyncio.run(run())

    assert unsigned == {"valid": False, "error": "attestation_required"}
    assert forged == {"resolved": False, "error": "attestation_invalid"}
    assert signed == {"valid": True, "resolved": True}
    assert unchecked["valid"] is True
    assert calls == ["/verification-context/resolve", "/verification-context/validate"]


def test_the_async_client_refetches_after_a_rotation(jwks):
    document = _admitted()
    stale = {"keys": [{**jwks["keys"][0], **_other_coordinates()}]}

    async def run():
        client = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=jwks)))
        client._jwks = stale
        client._jwks_fetched_at = client._jwks_attempted_at = time.monotonic() - 60
        try:
            return await client.verify_document_attestation(document)
        finally:
            await client._client.aclose()

    assert asyncio.run(run())["qwed"]["admission"] == "ADMIT"


def test_the_async_client_reports_keys_it_cannot_fetch(fresh_service):
    async def run():
        client = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(503)))
        try:
            return await client.resolve_verification_context(_document())
        finally:
            await client._client.aclose()

    with pytest.raises(KeysUnavailableError):
        asyncio.run(run())


def test_a_key_mismatch_within_30_seconds_is_invalid_without_a_fetch(jwks):
    # Keys fetched 10 s ago: a document none of them verifies does not make
    # the client fetch again, so a stream of forged documents is not a
    # stream of requests. The document is reported invalid.
    stale = {"keys": [{**jwks["keys"][0], **_other_coordinates()}]}
    fetched = []

    def handler(request):
        fetched.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    client._jwks = stale
    client._jwks_fetched_at = client._jwks_attempted_at = time.monotonic() - 10

    assert client.resolve_verification_context(_admitted()) == {"resolved": False, "error": "attestation_invalid"}
    assert fetched == []


def test_the_async_client_does_not_refetch_within_30_seconds(jwks):
    stale = {"keys": [{**jwks["keys"][0], **_other_coordinates()}]}
    fetched = []

    def handler(request):
        fetched.append(request.url.path)
        return httpx.Response(200, json=jwks)

    async def run():
        client = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client._jwks = stale
        client._jwks_fetched_at = client._jwks_attempted_at = time.monotonic() - 10
        try:
            return await client.validate_verification_context(_admitted())
        finally:
            await client._client.aclose()

    assert asyncio.run(run()) == {"valid": False, "error": "attestation_invalid"}
    assert fetched == []
