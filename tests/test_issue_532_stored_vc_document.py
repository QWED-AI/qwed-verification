"""#532: the audit row of from-diagnostic stores the document as signed.

``/verification-context/from-diagnostic`` signs the document it returns
(spec 1.1, #319). The audit row stored a copy with personal data redacted
in every string, made after signing, so the stored copy no longer matched
its attestation and a consumer reading it back (the dashboard) could not
verify it. The row now stores the document as returned; only its ``query``
column is redacted.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api import main as api_main
from qwed_new.core.audit_logger import get_audit_logger
from qwed_new.core.models import VerificationLog
from qwed_new.core.tenant_context import TenantContext
from qwed_new.core.verification_context import compute_document_hash
from qwed_new.core.verification_context_attestation import document_attestation_refusal

ORG_ID = 1
EMAIL = "ops@example.org"
REQUEST = {
    "query": f"Refund for {EMAIL} matches the returned items",
    "verifier": "custom-checker",
    "diagnostic": {
        "status": "UNVERIFIABLE",
        "agent_message": f"Write to {EMAIL} for the receipt.",
    },
}


def _mock_session():
    # A plain function, not MagicMock itself: FastAPI would read MagicMock's
    # constructor parameters as query parameters.
    return MagicMock()


@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(organization_id=ORG_ID, organization_name="Org", tier="free", api_key="k")
    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.verification_context_routes.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


@pytest.fixture
def signed(client, isolated_audit_chain):
    """The document from-diagnostic returned, and its audit row."""
    response = client.post("/verification-context/from-diagnostic", json=REQUEST)
    assert response.status_code == 200
    with Session(isolated_audit_chain) as session:
        (row,) = session.exec(select(VerificationLog)).all()
    return response.json(), row


def test_the_returned_document_is_signed_and_holds_the_email(signed):
    document, _row = signed

    assert document_attestation_refusal(document) is None
    assert EMAIL in document["object"]["formalization"]["source_query"]


def test_the_row_stores_the_document_as_returned(signed):
    document, row = signed

    stored = json.loads(row.result)
    assert stored == document
    assert compute_document_hash(stored) == compute_document_hash(document)


def test_the_stored_document_verifies_against_its_attestation(signed):
    _document, row = signed

    assert document_attestation_refusal(json.loads(row.result)) is None


def test_validate_accepts_the_stored_document(client, signed):
    _document, row = signed

    response = client.post(
        "/verification-context/validate", json={"document": json.loads(row.result)}
    )

    assert response.json() == {"valid": True}


def test_the_query_column_is_still_redacted(signed):
    _document, row = signed

    assert EMAIL not in row.query
    assert "[EMAIL_REDACTED]" in row.query


def test_the_row_is_on_the_signed_audit_chain(signed, isolated_audit_chain):
    _document, row = signed

    with Session(isolated_audit_chain) as session:
        assert get_audit_logger().verify_log_entry(row.id, session)["valid"] is True
