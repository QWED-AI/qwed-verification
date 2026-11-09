"""#320, the /verify/logic part: the route returned VERIFIED for whatever
constraints the LLM wrote, and nothing kept it from being admitted.

An LLM translates the question into DSL constraints, and Z3 decides only those
constraints. Nothing checks that they mean what was asked: "Prove x > 5
implies x > 10" translated to ``(AND (GT x 5) (GT x 10))`` is satisfiable
(x = 11), so the route returned VERIFIED, signed it, decided no admission
and stored its audit row as verified.

The verdict now names its scope (``query_semantics_verified: false``,
``verification_scope: translated_expression_only`` and the DSL as
``translated_expression``), as the natural-language maths verdict does. The
route and batch logic items decide admission with
``natural_language_admission``, which is BLOCKED until the translation itself
is verified (#585); the attestation signs that admission and binds the DSL,
and the audit row is verified only when the result is admitted. The verdict
stays as produced.
"""

import hashlib
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api import main as api_main
from qwed_new.core.attestation import get_attestation_service
from qwed_new.core.models import VerificationLog
from qwed_new.core.tenant_context import TenantContext

QUESTION = "Prove that x > 5 implies x > 10"
MISTRANSLATION = "(AND (GT x 5) (GT x 10))"


@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")

    def _mock_session():
        # A plain function, not MagicMock itself: FastAPI would read MagicMock's
        # constructor parameters as query parameters.
        return MagicMock()

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _translated_to(dsl):
    """The translator of both the route's and the batch's control plane
    returns ``dsl``; Z3 then decides it for real."""
    translated = (dsl, None, "mock", None)
    return (
        patch.object(api_main.control_plane.logic_verifier, "translate_to_dsl", return_value=translated),
        patch.object(api_main.batch_service.control_plane.logic_verifier, "translate_to_dsl", return_value=translated),
    )


def _rows(engine):
    with Session(engine) as session:
        return session.exec(select(VerificationLog).order_by(VerificationLog.id)).all()


def _claims(token):
    is_valid, claims, error = get_attestation_service().verify_attestation(token)
    assert is_valid, error
    return claims


def test_a_mistranslated_question_is_verified_for_its_constraints_only(client, isolated_audit_chain):
    route_patch, _ = _translated_to(MISTRANSLATION)
    with route_patch:
        body = client.post("/verify/logic", json={"query": QUESTION}).json()

    # Z3's answer about the constraints stands: they are satisfiable.
    assert body["status"] == "VERIFIED"
    assert body["proof_ref"]
    # It is not an answer to the question, so it is not admitted for it.
    assert body["admission"] == "BLOCKED"
    fields = body["developer_fields"]
    assert fields["query_semantics_verified"] is False
    assert fields["verification_scope"] == "translated_expression_only"
    assert fields["translated_expression"] == MISTRANSLATION
    assert fields["query_interpretation_source"] == "llm_translation"

    (row,) = _rows(isolated_audit_chain)
    assert row.is_verified is False
    assert row.admission == "BLOCKED"


def test_the_attestation_signs_the_admission_and_binds_the_constraints(client):
    route_patch, _ = _translated_to(MISTRANSLATION)
    with route_patch:
        body = client.post("/verify/logic", json={"query": QUESTION}).json()

    qwed = _claims(body["attestation"])["qwed"]
    assert qwed["admission"] == "BLOCKED"
    assert qwed["query_hash"] == "sha256:" + hashlib.sha256(MISTRANSLATION.encode()).hexdigest()


@pytest.mark.parametrize("output", [
    {"status": "SAT", "model": {"x": "6"}, "dsl_code": "(GT x 5)"},
    {"status": "UNSAT", "dsl_code": "(AND (GT x 5) (LT x 3))"},
    {"status": "ERROR", "error": "Logic verification failed"},
    {"status": "BLOCKED", "error": "Security Policy Violation: x"},
    # A result that claims its semantics were verified is not trusted: only
    # the translation check of #585 may set that.
    {"status": "SAT", "model": {"x": "6"}, "dsl_code": "(GT x 5)", "query_semantics_verified": True},
])
def test_no_logic_result_is_admitted_or_stored_as_verified(client, isolated_audit_chain, output):
    async def fake(query, organization_id=None, preferred_provider=None):
        return dict(output)

    with patch.object(api_main.control_plane, "process_logic_query", fake):
        body = client.post("/verify/logic", json={"query": QUESTION}).json()

    assert body["admission"] == "BLOCKED"
    assert body["developer_fields"]["query_semantics_verified"] is False
    (row,) = _rows(isolated_audit_chain)
    assert row.is_verified is False
    assert row.admission == "BLOCKED"


def test_a_pipeline_error_is_blocked_and_not_admitted(client, isolated_audit_chain):
    async def broken(query, organization_id=None, preferred_provider=None):
        raise RuntimeError("engine down")

    with patch.object(api_main.control_plane, "process_logic_query", broken):
        body = client.post("/verify/logic", json={"query": QUESTION}).json()

    assert body["status"] == "BLOCKED"
    assert body["admission"] == "BLOCKED"
    (row,) = _rows(isolated_audit_chain)
    assert row.is_verified is False
    assert row.admission == "BLOCKED"


def test_a_batch_logic_item_is_admitted_by_the_same_rule(client, isolated_audit_chain):
    _, batch_patch = _translated_to(MISTRANSLATION)
    with batch_patch:
        body = client.post("/verify/batch", json={"items": [{"query": QUESTION, "type": "logic"}]}).json()

    result = body["items"][0]["result"]
    assert result["status"] == "VERIFIED"
    assert result["admission"] == "BLOCKED"
    assert result["developer_fields"]["translated_expression"] == MISTRANSLATION
    assert _claims(result["attestation"])["qwed"]["admission"] == "BLOCKED"

    (row,) = _rows(isolated_audit_chain)
    assert row.is_verified is False
    assert row.admission == "BLOCKED"
