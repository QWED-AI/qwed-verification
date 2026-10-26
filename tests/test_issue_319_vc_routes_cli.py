"""#319: the server's validate and resolve routes, and the CLI's, check a
Verification Context document's attestation too.

#517 signed every document from-diagnostic returns and made the Python
SDK require the signature. The API routes and the ``qwed context`` CLI
commands still answered on the schema and ``proof_ref`` alone, so a caller
not using the SDK could take a forged document, an ``ADMIT`` one whose
``proof_ref`` was recomputed, as ``resolved``. Now:

- ``/verification-context/validate`` and ``/resolve`` take
  ``require_attestation`` (default true) and verify the attestation with the
  server's own key before answering;
- ``qwed context validate`` and ``resolve`` verify it with the keys of
  ``--jwks-file`` or ``--server``, and ``--no-require-attestation`` keeps the
  old checks.

Tokens are issued at test time, by the server's own code; none is stored in
the repository.
"""

import copy
import json

import httpx
import pytest
from click.testing import CliRunner
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
    SIGNING_KEY_ENV,
    SIGNING_KEY_FILE_ENV,
    TTL_ENV,
    AttestationService,
    create_verification_attestation,
    get_attestation_service,
)
from qwed_new.core.diagnostics import compute_proof_ref
from qwed_new.core.tenant_context import TenantContext
from qwed_new.core.verification_context import compute_document_hash, compute_document_proof_ref
from qwed_new.core.verification_context_attestation import (
    ATTESTATION_INVALID,
    ATTESTATION_REQUIRED,
    document_attestation_refusal,
)
from qwed_sdk.cli import cli

TENANT = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")
QUERY = "mean of a == 2"
PROOF = compute_proof_ref({"observed": 2})


@pytest.fixture
def fresh_service(monkeypatch):
    monkeypatch.setattr(attestation, "_default_service", None)
    for name in (SIGNING_KEY_ENV, SIGNING_KEY_FILE_ENV, TTL_ENV):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def jwks(fresh_service):
    keys = get_attestation_service().get_issuer_info()["public_keys"]
    return {"keys": [{**key, "alg": "ES256", "use": "sig"} for key in keys]}


def _document(diagnostic=None, attestation_token=None):
    payload = DiagnosticVerificationContextRequest(
        query=QUERY,
        verifier="TestVerifier",
        diagnostic=diagnostic or {"status": "UNVERIFIABLE", "agent_message": "m"},
        attestation_token=attestation_token,
    )
    return create_verification_context_from_diagnostic(payload, tenant=TENANT, session=None)


def _admitted():
    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="stats", query=QUERY, proof_hash=PROOF, admission="ADMIT",
    )
    return _document({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}, issued.token)


def _forged_admit():
    """The forgery #319 is about: a signed DENY document made ADMIT, with
    its proof_ref recomputed, which anyone can do. It still resolves."""
    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="stats", query=QUERY, proof_hash=PROOF,
    )
    document = _document({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}, issued.token)
    document["context"]["decision"]["admission"] = "ADMIT"
    document["context"]["evidence"]["proof_ref"] = compute_document_proof_ref(document)
    return document


def _unsigned(document):
    unsigned = {key: value for key, value in copy.deepcopy(document).items() if key != "attestation"}
    unsigned["spec_version"] = "1.0"
    return unsigned


def _other_service():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return AttestationService(key_continuity_policy="configured", private_key_pem=pem, validity_seconds=3600)


def _validate(document, **fields):
    request = VerificationContextDocumentRequest(document=document, **fields)
    return validate_verification_context(request, tenant=TENANT, session=None)


def _resolve(document, **fields):
    request = VerificationContextDocumentRequest(document=document, **fields)
    return resolve_verification_context(request, tenant=TENANT, session=None)


# ---------------------------------------------------------------- the routes

def test_the_routes_require_an_attestation_by_default(fresh_service):
    assert VerificationContextDocumentRequest(document={}).require_attestation is True


def test_a_signed_document_validates_and_resolves(fresh_service):
    document = _admitted()

    assert _validate(document) == {"valid": True}
    assert _resolve(document) == {"resolved": True}


def test_an_unsigned_document_is_refused(fresh_service):
    document = _unsigned(_admitted())

    assert _validate(document) == {"valid": False, "error": ATTESTATION_REQUIRED}
    assert _resolve(document) == {"resolved": False, "error": ATTESTATION_REQUIRED}


def test_a_forged_admit_that_resolves_is_refused(fresh_service):
    document = _forged_admit()

    assert _resolve(document, require_attestation=False) == {"resolved": True}
    assert _resolve(document) == {"resolved": False, "error": ATTESTATION_INVALID}
    assert _validate(document) == {"valid": False, "error": ATTESTATION_INVALID}


def test_a_document_signed_by_another_key_is_refused(fresh_service):
    document = _admitted()
    document["attestation"] = _other_service().create_context_attestation(
        document_hash=compute_document_hash(document), verdict="VERIFIED", admission="ADMIT",
        proof_ref=document["context"]["evidence"]["proof_ref"],
    )

    assert _resolve(document) == {"resolved": False, "error": ATTESTATION_INVALID}


def test_a_verdicts_token_in_a_document_is_refused(fresh_service):
    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="stats", query=QUERY, proof_hash=PROOF, admission="ADMIT",
    )
    document = {**_admitted(), "attestation": issued.token}

    assert _validate(document) == {"valid": False, "error": ATTESTATION_INVALID}


@pytest.mark.parametrize("token", ["", 7, None])
def test_an_attestation_that_is_not_a_token_is_required(fresh_service, token):
    assert document_attestation_refusal({**_admitted(), "attestation": token}) == ATTESTATION_REQUIRED


def test_require_attestation_false_keeps_the_old_checks(fresh_service):
    document = _unsigned(_document())

    assert _validate(document, require_attestation=False) == {"valid": True}
    assert _resolve(document, require_attestation=False) == {"resolved": False}  # not VERIFIED


def test_a_key_that_cannot_be_loaded_is_a_500(fresh_service):
    def broken():
        raise attestation.SigningKeyError("unusable key")

    document = _document()
    fresh_service.setattr("qwed_new.core.verification_context_attestation.get_attestation_service", broken)
    request = VerificationContextDocumentRequest(document=document)

    with pytest.raises(HTTPException) as failed:
        validate_verification_context(request, tenant=TENANT, session=None)

    assert failed.value.status_code == 500
    assert failed.value.detail == "attestation verification failed"


# ---------------------------------------------------------------- the CLI

def _write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


def _run(*args):
    result = CliRunner().invoke(cli, ["context", *args])
    return result.exit_code, (json.loads(result.output) if result.exit_code in (0, 1) else result.output)


@pytest.mark.parametrize(("command", "key"), [("validate", "valid"), ("resolve", "resolved")])
def test_the_cli_verifies_a_signed_document_with_a_jwks_file(tmp_path, jwks, command, key):
    document = _write(tmp_path, "doc.json", _admitted())
    keys = _write(tmp_path, "jwks.json", jwks)

    assert _run(command, "--jwks-file", keys, document) == (0, {key: True})


@pytest.mark.parametrize(("command", "key"), [("validate", "valid"), ("resolve", "resolved")])
def test_the_cli_refuses_a_forged_document(tmp_path, jwks, command, key):
    document = _write(tmp_path, "doc.json", _forged_admit())
    keys = _write(tmp_path, "jwks.json", jwks)

    assert _run(command, "--jwks-file", keys, document) == (1, {key: False, "error": "attestation_invalid"})


def test_the_cli_requires_an_attestation_by_default(tmp_path, fresh_service):
    document = _write(tmp_path, "doc.json", _unsigned(_document()))

    assert _run("validate", document) == (1, {"valid": False, "error": "attestation_required"})
    assert _run("validate", "--no-require-attestation", document) == (0, {"valid": True})


def test_the_cli_needs_keys_to_check_a_signed_document(tmp_path, fresh_service):
    document = _write(tmp_path, "doc.json", _admitted())

    assert _run("resolve", document) == (1, {"resolved": False, "error": "attestation_keys_required"})


def test_the_cli_takes_one_source_of_keys(tmp_path, jwks):
    document = _write(tmp_path, "doc.json", _admitted())
    keys = _write(tmp_path, "jwks.json", jwks)

    exit_code, output = _run("validate", "--jwks-file", keys, "--server", "http://qwed.test", document)

    assert exit_code == 2
    assert "not both" in output


def test_the_cli_reports_a_jwks_file_it_cannot_read(tmp_path, fresh_service):
    document = _write(tmp_path, "doc.json", _admitted())
    keys = tmp_path / "jwks.json"
    keys.write_text("{", encoding="utf-8")

    assert _run("validate", "--jwks-file", str(keys), document) == (
        1, {"valid": False, "error": "attestation_keys_unavailable"},
    )


def test_the_cli_fetches_the_servers_keys(tmp_path, jwks, monkeypatch):
    document = _write(tmp_path, "doc.json", _admitted())
    fetched = []

    def get(url, **kwargs):
        fetched.append(url)
        return httpx.Response(200, json=jwks, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", get)

    assert _run("resolve", "--server", "http://qwed.test/", document) == (0, {"resolved": True})
    assert fetched == ["http://qwed.test/.well-known/jwks.json"]


@pytest.mark.parametrize("failure", [
    lambda url: httpx.Response(503, request=httpx.Request("GET", url)),
    lambda url: httpx.Response(200, content=b"not json", request=httpx.Request("GET", url)),
])
def test_the_cli_reports_server_keys_it_cannot_fetch(tmp_path, fresh_service, monkeypatch, failure):
    document = _write(tmp_path, "doc.json", _admitted())
    monkeypatch.setattr(httpx, "get", lambda url, **kwargs: failure(url))

    assert _run("resolve", "--server", "http://qwed.test", document) == (
        1, {"resolved": False, "error": "attestation_keys_unavailable"},
    )


def test_the_cli_reports_a_server_it_cannot_reach(tmp_path, fresh_service, monkeypatch):
    document = _write(tmp_path, "doc.json", _admitted())

    def unreachable(url, **kwargs):
        raise httpx.ConnectError("refused", request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", unreachable)

    assert _run("validate", "--server", "http://qwed.test", document) == (
        1, {"valid": False, "error": "attestation_keys_unavailable"},
    )


# ---------------------------------------------------------------- end to end

def _mock_session():
    from unittest.mock import MagicMock

    return MagicMock()


@pytest.fixture
def api(isolated_audit_chain, fresh_service):
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from qwed_new.api import main as api_main

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: TENANT
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"), \
                patch("qwed_new.api.verification_context_routes.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def test_over_http_a_document_the_server_issued_is_checked_end_to_end(api, tmp_path, monkeypatch):
    # The server signs a document; over HTTP, validate and resolve take it
    # with no flag sent, refuse it once edited, and the CLI verifies it with
    # the server's published keys.
    document = api.post("/verification-context/from-diagnostic", json={
        "query": QUERY, "verifier": "TestVerifier",
        "diagnostic": {"status": "UNVERIFIABLE", "agent_message": "m"},
    }).json()
    forged = {**document, "verdict": "BLOCKED"}

    assert document["spec_version"] == "1.1"
    assert api.post("/verification-context/validate", json={"document": document}).json() == {"valid": True}
    assert api.post("/verification-context/validate", json={"document": forged}).json() == {
        "valid": False, "error": "attestation_invalid",
    }
    assert api.post("/verification-context/resolve", json={
        "document": _unsigned(document), "require_attestation": False,
    }).json() == {"resolved": False}

    monkeypatch.setattr(httpx, "get", lambda url, **kwargs: api.get(httpx.URL(url).path))
    path = _write(tmp_path, "doc.json", document)

    assert _run("validate", "--server", "http://testserver", path) == (0, {"valid": True})
    assert _run("validate", "--server", "http://testserver", _write(tmp_path, "forged.json", forged)) == (
        1, {"valid": False, "error": "attestation_invalid"},
    )


# ---------------------------------------------------------------- #523 review

def _signed_with_header(document, header):
    """``document`` with an attestation the server's own key signs, under
    ``header`` (typ and alg added), whose claims are otherwise right."""
    import time as _time

    import jwt

    service = get_attestation_service()
    digest = compute_document_hash(document)
    now = int(_time.time())
    payload = {
        "iss": service.issuer_did, "sub": digest, "iat": now, "exp": now + 600, "jti": "att_review",
        "qwed": {
            "version": "1.1", "document_hash": digest, "verdict": document["verdict"],
            "admission": document["context"]["decision"]["admission"],
            "proof_ref": document["context"]["evidence"]["proof_ref"],
        },
    }
    token = jwt.encode(
        payload, service._ensure_key_pair().private_key_pem, algorithm="ES256",
        headers={"typ": "qwed-context+jwt", **header},
    )
    if "kid" not in header:
        # PyJWT adds no kid of its own; make sure none is there.
        assert "kid" not in jwt.get_unverified_header(token)
    return {**document, "attestation": token}


def test_the_server_accepts_a_token_naming_its_key(fresh_service):
    document = _admitted()
    kid = get_attestation_service()._ensure_key_pair().key_id

    assert _resolve(_signed_with_header(document, {"kid": kid})) == {"resolved": True}


@pytest.mark.parametrize("header", [{}, {"kid": "another-key"}, {"kid": ""}])
def test_the_server_refuses_a_token_that_does_not_name_its_key(fresh_service, header):
    # #523 review: spec v1.1 section 4 has the verified header name the key
    # that verified it, as the SDKs check.
    document = _signed_with_header(_admitted(), header)

    assert _resolve(document) == {"resolved": False, "error": ATTESTATION_INVALID}


def test_a_token_with_a_header_too_deep_to_parse_is_invalid_not_a_500(fresh_service):
    # #523 review: a RecursionError from the token's header is the caller's
    # malformed token, not the server's failure. PyJWT 2.15 reports it as a
    # DecodeError itself; PyJWT 2.8, the floor, lets it through.
    import base64

    def segment(raw):
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    header = segment('{"alg":"ES256","x":' + "[" * 1500 + "]" * 1500 + "}")
    token = f"{header}.{segment('{}')}.{segment('sig')}"
    assert len(token) <= 8192
    document = {**_admitted(), "attestation": token}

    assert _resolve(document) == {"resolved": False, "error": ATTESTATION_INVALID}
    assert _validate(document) == {"valid": False, "error": ATTESTATION_INVALID}


def test_a_recursion_error_from_pyjwt_is_invalid_not_a_500(fresh_service, monkeypatch):
    # The same, whatever PyJWT is installed: the server's own check.
    import jwt

    document = _admitted()

    def deep(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(jwt.PyJWT, "decode_complete", deep)

    assert _resolve(document) == {"resolved": False, "error": ATTESTATION_INVALID}


@pytest.mark.parametrize("command", ["validate", "resolve"])
def test_both_key_sources_are_refused_even_without_the_check(tmp_path, jwks, command):
    # #523 review: the usage error must not depend on --require-attestation.
    document = _write(tmp_path, "doc.json", _unsigned(_document()))
    keys = _write(tmp_path, "jwks.json", jwks)

    exit_code, output = _run(
        command, "--no-require-attestation", "--jwks-file", keys, "--server", "http://qwed.test", document,
    )

    assert exit_code == 2
    assert "not both" in output


@pytest.mark.parametrize(("command", "key"), [("validate", "valid"), ("resolve", "resolved")])
def test_a_document_too_deep_to_parse_is_an_unreadable_file(tmp_path, command, key):
    path = tmp_path / "deep.json"
    path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")

    assert _run(command, "--no-require-attestation", str(path)) == (1, {key: False, "error": "invalid_document_file"})


def test_a_malformed_server_url_is_keys_unavailable(tmp_path, fresh_service):
    # #523 review: httpx.InvalidURL is neither an HTTPError nor a ValueError.
    document = _write(tmp_path, "doc.json", _admitted())

    assert _run("resolve", "--server", "http://localhost:bad", document) == (
        1, {"resolved": False, "error": "attestation_keys_unavailable"},
    )


@pytest.mark.parametrize("token", ["\ud800.e30.x", "a\udfff.e30.x", "é.e30.x"])
def test_a_token_that_is_not_ascii_is_invalid_not_a_500(fresh_service, token):
    # #523 review: a compact JWT is base64url, so ASCII. PyJWT encodes the
    # token as UTF-8 first, and an unpaired surrogate raised
    # UnicodeEncodeError, a ValueError the route turned into a 500.
    document = {**_admitted(), "attestation": token}

    assert _resolve(document) == {"resolved": False, "error": ATTESTATION_INVALID}


@pytest.mark.parametrize("token", ["\ud800.e30.x", "é.e30.x"])
def test_the_sdk_and_cli_refuse_a_token_that_is_not_ascii(tmp_path, jwks, token):
    # The same hole in the SDK verifier: UnicodeEncodeError escaped instead
    # of an AttestationError, so the clients' and the CLI's checks crashed.
    from qwed_sdk.attestation import AttestationError, verify_attestation, verify_document_attestation

    document = {**_admitted(), "attestation": token}

    with pytest.raises(AttestationError, match="not a JWT"):
        verify_document_attestation(document, jwks)
    with pytest.raises(AttestationError, match="not a JWT"):
        verify_attestation(token, jwks, proof_ref=PROOF)
    path = _write(tmp_path, "doc.json", document)
    keys = _write(tmp_path, "jwks.json", jwks)
    assert _run("validate", "--jwks-file", keys, path) == (1, {"valid": False, "error": "attestation_invalid"})
