"""#320, the RAG and process parts: VERIFIED from evidence the request supplies.

``/verify/rag`` compared the document labels on the chunks with a target label
and a threshold that the same request sends; the server holds no documents.
So chunks labelled with the target passed for any content, and
``max_drm_rate: "1"`` passed any chunks at all. ``/verify/process`` matched
four keywords (IRAC mode) or keywords the request names itself (milestones
mode). Each passing check came back VERIFIED, with a proof_ref, a signed
attestation and an audit row stored as verified, and the guard's ``verified``
flag was merged into the response's top level.

Neither guard can establish that the retrieval or the reasoning is right, so
both routes now return UNVERIFIABLE whatever their guard says. The guard's
result is advisory only, in ``advisory_checks``, and no ``verified`` key
reaches the response's top level.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api import main as api_main
from qwed_new.core.models import VerificationLog
from qwed_new.core.tenant_context import TenantContext


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


def _last_row(engine):
    with Session(engine) as session:
        return session.exec(select(VerificationLog).order_by(VerificationLog.id.desc())).first()


def _assert_advisory_only(body, constraint_id, guard_passed):
    assert body["status"] == "UNVERIFIABLE"
    assert body["proof_ref"] is None
    assert "attestation" not in body
    assert "verified" not in body
    assert body["constraint_id"] == constraint_id
    (check,) = body["advisory_checks"]
    assert check["advisory_only"] is True
    assert check["details"]["verified"] is guard_passed


# ---------------------------------------------------------------- RAG

LABEL_ECHO = {
    # Every chunk carries the label the request names, whatever it says.
    "target_document_id": "contract-2024",
    "chunks": [
        {"id": "c1", "text": "Anything at all", "metadata": {"document_id": "contract-2024"}},
        {"id": "c2", "text": "Unrelated text", "metadata": {"document_id": "contract-2024"}},
    ],
    "max_drm_rate": "0",
}
THRESHOLD_ONE = {
    # Every chunk is from another document, and the request allows that.
    "target_document_id": "contract-2024",
    "chunks": [
        {"id": "c1", "text": "x", "metadata": {"document_id": "other-1"}},
        {"id": "c2", "text": "y", "metadata": {"document_id": "other-2"}},
    ],
    "max_drm_rate": "1",
}


@pytest.mark.parametrize("payload", [LABEL_ECHO, THRESHOLD_ONE], ids=["label echo", "threshold of 1"])
def test_rag_evidence_the_request_supplies_is_advisory_only(client, isolated_audit_chain, payload):
    body = client.post("/verify/rag", json=payload).json()

    _assert_advisory_only(body, "api.rag.advisory_only", guard_passed=True)
    assert _last_row(isolated_audit_chain).is_verified is False


def test_a_rag_mismatch_is_still_unverifiable(client, isolated_audit_chain):
    payload = dict(THRESHOLD_ONE, max_drm_rate="0")

    body = client.post("/verify/rag", json=payload).json()

    _assert_advisory_only(body, "api.rag.guard_failed", guard_passed=False)
    assert body["agent_message"] == "RAG context mismatch detected"
    assert body["advisory_checks"][0]["details"]["mismatched_count"] == 2
    assert _last_row(isolated_audit_chain).is_verified is False


# ---------------------------------------------------------------- process

@pytest.mark.parametrize("payload", [
    {"trace": "issue rule application conclusion", "mode": "irac"},
    {"trace": "done", "mode": "milestones", "milestones": ["done"]},
], ids=["irac keywords", "milestones the request names"])
def test_process_keywords_are_advisory_only(client, isolated_audit_chain, payload):
    body = client.post("/verify/process", json=payload).json()

    _assert_advisory_only(body, "api.process.advisory_only", guard_passed=True)
    assert _last_row(isolated_audit_chain).is_verified is False


def test_a_process_check_that_fails_is_still_unverifiable(client, isolated_audit_chain):
    body = client.post("/verify/process", json={"trace": "only an issue here", "mode": "irac"}).json()

    _assert_advisory_only(body, "api.process.guard_failed", guard_passed=False)
    assert body["agent_message"] == "Process verification did not pass"
    assert _last_row(isolated_audit_chain).is_verified is False


# ---------------------------------------------------------------- errors

@pytest.mark.parametrize("route, payload, target", [
    ("/verify/rag", LABEL_ECHO, "qwed_sdk.guards.rag_guard.RAGGuard.verify_retrieval_context"),
    ("/verify/process", {"trace": "issue rule", "mode": "irac"},
     "qwed_new.guards.process_guard.ProcessVerifier.verify_irac_structure"),
])
def test_an_error_is_blocked_without_a_verified_flag(client, route, payload, target):
    with patch(target, side_effect=RuntimeError("guard down")):
        body = client.post(route, json=payload).json()

    assert body["status"] == "BLOCKED"
    assert "verified" not in body
    assert "guard down" not in str(body)
