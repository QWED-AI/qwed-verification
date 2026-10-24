"""#321: the attestation signs the server's admission, and a signed ADMIT is
the provenance /verification-context/from-diagnostic admits on.

A token bound the verdict's status, ``proof_ref`` and statement, but not the
admission, which rests on more than those (``is_valid``, and for natural
language that the translation was verified). So a consumer could check a
verdict but not the server's ADMIT or BLOCKED, and from-diagnostic, which
must not take the caller's ``is_valid``, could only say DENY.

Now a route that decides an admission signs it as ``qwed.admission``, the
trust step checks the fresh token carries it, and from-diagnostic admits a
VERIFIED diagnostic whose token, checked against its status, ``proof_ref``
and query, signs ADMIT.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.api.verification_context_routes import (
    ATTESTED_ADMIT,
    DiagnosticVerificationContextRequest,
    _admitting_engine,
    create_verification_context_from_diagnostic,
)
from qwed_new.core import attestation
from qwed_new.core.attestation import (
    SIGNING_KEY_ENV,
    SIGNING_KEY_FILE_ENV,
    TTL_ENV,
    AttestationService,
    AttestationStatus,
    VerificationResult,
    create_verification_attestation,
    get_attestation_service,
    is_admission_claim,
)
from qwed_new.core.control_plane import natural_language_admission
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    DiagnosticStatus,
    admission_decision,
    compute_proof_ref,
    enforce_trust_decision,
)
from qwed_new.core.tenant_context import TenantContext
from qwed_new.core.trust import attest_and_enforce

TENANT = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")
QUERY = "mean of a == 2"
PROOF = compute_proof_ref({"observed": 2})


@pytest.fixture
def fresh_service(monkeypatch):
    monkeypatch.setattr(attestation, "_default_service", None)
    for name in (SIGNING_KEY_ENV, SIGNING_KEY_FILE_ENV, TTL_ENV):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _mock_session():
    return MagicMock()


@pytest.fixture
def client(isolated_audit_chain, fresh_service):
    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: TENANT
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _claims(token):
    """The token's verified claims, as a consumer reads them."""
    is_valid, claims, error = get_attestation_service().verify_attestation(token)
    assert is_valid, error
    return claims


def _token(admission=None, query=QUERY, proof_hash=PROOF):
    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="stats", query=query, proof_hash=proof_hash, admission=admission,
    )
    assert issued.is_issued, issued.error
    return issued.token


def _verified(**fields):
    return DiagnosticResult(
        status=DiagnosticStatus.VERIFIED,
        agent_message="ok",
        developer_fields={"constraint_id": "test.verified", **fields},
        proof_ref=PROOF,
    )


# ---------------------------------------------------------------- signing

@pytest.mark.parametrize("admission", ["ADMIT", "BLOCKED"])
def test_the_admission_is_signed(fresh_service, admission):
    assert _claims(_token(admission))["qwed"]["admission"] == admission


def test_a_route_that_decides_none_signs_none(fresh_service):
    assert "admission" not in _claims(_token())["qwed"]


@pytest.mark.parametrize("admission", ["DENY", "admit", "", 1, [], ["ADMIT"], {}])
def test_any_other_admission_is_refused(fresh_service, admission):
    # An unhashable value is refused like any other, not with TypeError
    # (#514 review).
    service = AttestationService()
    result = VerificationResult(status="VERIFIED", verified=True, engine="math")

    with pytest.raises(ValueError, match="ADMIT or BLOCKED"):
        service.create_attestation(result, QUERY, proof_hash=PROOF, admission=admission, store=False)
    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="math", query=QUERY, proof_hash=PROOF, admission=admission,
    )
    assert issued.status is AttestationStatus.BLOCKED
    assert issued.error_code == "INVALID_ADMISSION"
    assert not is_admission_claim(admission)


def test_the_admission_claims_are_admit_and_blocked():
    assert is_admission_claim("ADMIT")
    assert is_admission_claim("BLOCKED")


# ---------------------------------------------------------------- the trust step

def test_the_trust_step_checks_the_signed_admission(fresh_service):
    signed_blocked = _token("BLOCKED")

    kept = enforce_trust_decision(_verified(), attestation_token=signed_blocked, query=QUERY, admission="BLOCKED")
    refused = enforce_trust_decision(_verified(), attestation_token=signed_blocked, query=QUERY, admission="ADMIT")
    unsigned = enforce_trust_decision(_verified(), attestation_token=_token(), query=QUERY, admission="ADMIT")

    assert kept.status is DiagnosticStatus.VERIFIED
    for blocked in (refused, unsigned):
        assert blocked.status is DiagnosticStatus.BLOCKED
        assert blocked.developer_fields["constraint_id"] == "trust_gate.claims_admission_mismatch"


@pytest.mark.parametrize("fields, rule, expected", [
    ({"is_valid": True}, admission_decision, "ADMIT"),
    ({"is_valid": False}, admission_decision, "BLOCKED"),
    # Natural language: admitted only when the translation was verified too.
    ({"is_valid": True, "query_semantics_verified": True}, natural_language_admission, "ADMIT"),
    ({"is_valid": True}, natural_language_admission, "BLOCKED"),
])
def test_attest_and_enforce_signs_the_routes_admission(fresh_service, fields, rule, expected):
    dr = attest_and_enforce(_verified(**fields), engine="math", query=QUERY, admission=rule)

    assert dr.status is DiagnosticStatus.VERIFIED
    assert rule(dr).value == expected
    assert _claims(dr.attestation)["qwed"]["admission"] == expected


def test_attest_and_enforce_without_a_rule_signs_no_admission(fresh_service):
    dr = attest_and_enforce(_verified(is_valid=True), engine="logic", query=QUERY)

    assert "admission" not in _claims(dr.attestation)["qwed"]


# ---------------------------------------------------------------- the routes

@pytest.mark.parametrize("route, body", [
    ("/verify/math", {"expression": "2+2=4"}),
    ("/verify/math", {"expression": "2+2=5"}),  # proven false: VERIFIED, BLOCKED
    ("/verify/code", {"code": "print(1 + 1)", "language": "python"}),
    ("/verify/code", {"code": "import os\nos.system('rm -rf /')", "language": "python"}),
    ("/verify/sql", {"query": "SELECT name FROM users WHERE id = 1",
                     "schema_ddl": "CREATE TABLE users (id INT, name TEXT)", "dialect": "sqlite"}),
    ("/verify/sql", {"query": "DROP TABLE users", "schema_ddl": "CREATE TABLE users (id INT)", "dialect": "sqlite"}),
])
def test_a_routes_token_signs_the_admission_it_returns(client, route, body):
    # Each case reaches VERIFIED, the unsafe ones with admission BLOCKED: a
    # failure to sign or check the token would be BLOCKED, and fails here
    # (#514 review).
    response = client.post(route, json=body).json()

    assert response["status"] == "VERIFIED", response
    assert response["admission"] in {"ADMIT", "BLOCKED"}
    assert _claims(response["attestation"])["qwed"]["admission"] == response["admission"]


def test_both_admissions_are_signed_on_a_route(client):
    admit = client.post("/verify/math", json={"expression": "2+2=4"}).json()
    blocked = client.post("/verify/math", json={"expression": "2+2=5"}).json()

    assert _claims(admit["attestation"])["qwed"]["admission"] == admit["admission"] == "ADMIT"
    assert _claims(blocked["attestation"])["qwed"]["admission"] == blocked["admission"] == "BLOCKED"


def test_a_batch_items_token_signs_the_items_admission(client):
    body = client.post("/verify/batch", json={"items": [
        {"query": "2 + 2 = 4", "type": "math"},
        {"query": "3 * 3 = 9", "type": "math"},
    ]}).json()

    for item in body["items"]:
        result = item["result"]
        assert result["status"] == "VERIFIED"
        assert _claims(result["attestation"])["qwed"]["admission"] == result["admission"] == "ADMIT"


# ---------------------------------------------------------------- from-diagnostic

def _document(diagnostic, attestation_token=None, query=QUERY):
    payload = DiagnosticVerificationContextRequest(
        query=query, verifier="TestVerifier", diagnostic=diagnostic, attestation_token=attestation_token,
    )
    return create_verification_context_from_diagnostic(payload, tenant=TENANT, session=None)


def test_a_token_that_signs_admit_admits_the_document(fresh_service):
    document = _document({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}, attestation_token=_token("ADMIT"))
    fields = document["context"]["evidence"]["evidence"]["developer_fields"]

    assert document["verdict"] == "VERIFIED"
    assert document["context"]["decision"]["admission"] == "ADMIT"
    assert fields["constraint_id"] == ATTESTED_ADMIT
    assert fields["attested_admission"] == "ADMIT"


def test_an_admitted_document_names_the_engine_that_signed_it(fresh_service):
    # #514 review: the caller chose the verifier, so a genuine token could
    # carry an ADMIT document naming a verifier that never checked it.
    payload = DiagnosticVerificationContextRequest(
        query=QUERY, verifier="Lean", verifier_version="9.9.9",
        diagnostic={"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF},
        attestation_token=_token("ADMIT"),  # signed by the "stats" engine
    )

    document = create_verification_context_from_diagnostic(payload, tenant=TENANT, session=None)
    context = document["context"]

    assert context["decision"]["admission"] == "ADMIT"
    assert context["proof"]["verifier"] == "stats"
    assert context["proof"]["verifier_version"] != "9.9.9"  # the server's own
    assert context["interpretation"]["theory"] == "stats verification"
    caller = context["evidence"]["evidence"]["developer_fields"]["caller_supplied"]
    assert (caller["verifier"], caller["verifier_version"]) == ("Lean", "9.9.9")


@pytest.mark.parametrize("token", [None, ""])
def test_no_token_names_no_admitting_engine(fresh_service, token):
    # The route asks only once the trust step has accepted a token; without
    # one there is nothing to read, and nothing is admitted.
    assert _admitting_engine(token) is None


def test_only_a_token_that_signs_admit_names_its_engine(fresh_service):
    assert _admitting_engine(_token("ADMIT")) == "stats"
    assert _admitting_engine(_token("BLOCKED")) is None
    assert _admitting_engine(_token()) is None


def test_a_denied_document_keeps_the_callers_verifier(fresh_service):
    # Not admitted, it vouches for nothing, so it records what was asked.
    document = _document({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}, attestation_token=_token())

    assert document["context"]["decision"]["admission"] == "DENY"
    assert document["context"]["proof"]["verifier"] == "TestVerifier"


@pytest.mark.parametrize("admission", ["BLOCKED", None])
def test_a_token_that_does_not_sign_admit_leaves_the_document_denied(fresh_service, admission):
    # The caller's is_valid is still ignored (#509).
    document = _document(
        {"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF, "developer_fields": {"is_valid": True}},
        attestation_token=_token(admission),
    )

    assert document["verdict"] == "VERIFIED"
    assert document["context"]["decision"]["admission"] == "DENY"


def test_a_signed_admit_for_another_answer_admits_nothing(fresh_service):
    # Signed ADMIT, but for another proof_ref, or another query: the trust
    # step blocks the diagnostic before its admission is read.
    other_proof = _token("ADMIT", proof_hash="sha256:" + "f" * 64)
    other_query = _token("ADMIT", query="mean of a == 3")

    for token in (other_proof, other_query):
        document = _document({"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}, attestation_token=token)
        assert document["verdict"] == "BLOCKED"
        assert document["context"]["decision"]["admission"] == "DENY"


def test_a_signed_admit_does_not_admit_a_diagnostic_that_is_not_verified(fresh_service):
    document = _document({"status": "UNVERIFIABLE", "agent_message": "m"}, attestation_token=_token("ADMIT"))

    assert document["verdict"] == "UNVERIFIABLE"
    assert document["context"]["decision"]["admission"] == "DENY"


def test_a_failure_to_read_the_admission_fails_loudly(fresh_service, monkeypatch):
    # Should reading the signed admission fail (the second read, after the
    # route's trust step), the request fails with a 500 rather than going on
    # as DENY: an enforcement failure is not suppressed (QWED_RULES.md
    # section 6, #514 review).
    token = _token("ADMIT")
    service = get_attestation_service()
    calls = []

    def flaky(token, **kwargs):
        calls.append(token)
        if len(calls) == 2:
            raise RuntimeError("key unavailable")
        return AttestationService.verify_attestation(service, token, **kwargs)

    monkeypatch.setattr(service, "verify_attestation", flaky)
    diagnostic = {"status": "VERIFIED", "agent_message": "m", "proof_ref": PROOF}

    with pytest.raises(HTTPException) as failed:
        _document(diagnostic, attestation_token=token)

    assert failed.value.status_code == 500
    assert len(calls) == 2


def test_a_live_answers_token_admits_its_document(client):
    # End to end: an answer from /verify/math, handed to from-diagnostic with
    # its own token, statement and proof_ref.
    answer = client.post("/verify/math", json={"expression": "2+2=4"}).json()

    document = client.post("/verification-context/from-diagnostic", json={
        "query": "2+2=4",
        "verifier": "QWED",
        "diagnostic": {"status": "VERIFIED", "agent_message": "m", "proof_ref": answer["proof_ref"]},
        "attestation_token": answer["attestation"],
    }).json()

    assert document["verdict"] == "VERIFIED"
    assert document["context"]["decision"]["admission"] == "ADMIT"


def test_the_signed_admissions_are_the_admission_decisions():
    assert {d.value for d in AdmissionDecision} == attestation.ADMISSION_CLAIMS
