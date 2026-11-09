"""#576: /verify/math without "=" returned VERIFIED and ADMIT for an
expression that makes no claim.

``2+2`` came back VERIFIED ("Expression evaluated", ``is_valid: true``), so
admission was ADMIT and the audit row was stored as verified, although the
input claims nothing: the route admitted whatever value the parser produced.
The same input as a batch math item was UNVERIFIABLE. Both now return
UNVERIFIABLE with ``math.no_claim``, ``is_valid: false`` and the computed
value as evidence; a caller who wants a check sends ``expression = value``.
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


@pytest.mark.parametrize("expression, field, value", [
    ("2+2", "value", 4.0),
    ("2+2", "exact_value", "4"),
    ("1/3 + 1/6", "exact_value", "1/2"),
    ("x + x", "simplified", "2*x"),
])
def test_an_expression_without_a_claim_is_not_verified_or_admitted(client, isolated_audit_chain, expression, field, value):
    body = client.post("/verify/math", json={"expression": expression}).json()

    assert body["status"] == "UNVERIFIABLE"
    assert body["admission"] == "BLOCKED"
    assert body["is_valid"] is False
    assert body["constraint_id"] == "math.no_claim"
    assert body["proof_ref"] is None
    assert "attestation" not in body
    assert "no equality or proof claim" in body["agent_message"]
    # The computed value is still there, as evidence for the caller.
    assert body[field] == value
    assert _last_row(isolated_audit_chain).is_verified is False


def test_the_same_expression_with_a_claim_is_still_verified_and_admitted(client):
    body = client.post("/verify/math", json={"expression": "2+2 = 4"}).json()

    assert body["status"] == "VERIFIED"
    assert body["admission"] == "ADMIT"
    assert body["is_valid"] is True


@pytest.mark.parametrize("expression", ["2+2", "x + x"])
def test_the_route_and_a_batch_item_agree(client, expression):
    route = client.post("/verify/math", json={"expression": expression}).json()
    batch = client.post("/verify/batch", json={"items": [{"query": expression, "type": "math"}]}).json()
    item = batch["items"][0]["result"]

    assert route["status"] == item["status"] == "UNVERIFIABLE"
    assert route["admission"] == item["admission"] == "BLOCKED"
    assert route["constraint_id"] == item["constraint_id"] == "math.no_claim"
