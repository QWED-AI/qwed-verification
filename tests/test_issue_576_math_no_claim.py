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
    # A complex value: "Expression is not numeric" had no constraint_id
    # (CodeRabbit on PR #603).
    ("I", "simplified", "I"),
    ("sqrt(-1)", "simplified", "I"),
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


def _batch_item(client, expression):
    batch = client.post("/verify/batch", json={"items": [{"query": expression, "type": "math"}]}).json()
    return batch["items"][0]["result"]


@pytest.mark.parametrize("expression", ["2+2", "x + x", "I"])
def test_the_route_and_a_batch_item_agree(client, expression):
    route = client.post("/verify/math", json={"expression": expression}).json()
    item = _batch_item(client, expression)

    assert route["status"] == item["status"] == "UNVERIFIABLE"
    assert route["admission"] == item["admission"] == "BLOCKED"
    assert route["constraint_id"] == item["constraint_id"] == "math.no_claim"


@pytest.mark.parametrize("expression, field, value", [
    ("1/0", "error", "Division by zero"),
    ("0/0", "error", "Division by zero"),
    ("oo", "error", "undefined"),
    ("6/2(1+2)", "warning", "ambiguous"),
])
def test_an_undefined_or_ambiguous_batch_item_is_blocked_as_on_the_route(client, expression, field, value):
    # A batch item was UNVERIFIABLE with math.no_claim, while the route
    # BLOCKED the same input (CodeAnt on PR #603). Both now run one function.
    route = client.post("/verify/math", json={"expression": expression}).json()
    item = _batch_item(client, expression)

    assert route["status"] == item["status"] == "BLOCKED"
    assert route["admission"] == item["admission"] == "BLOCKED"
    assert route[field] == item[field] == value
    assert route.get("constraint_id") is None
    assert item.get("constraint_id") is None
    assert item["query"] == expression
    assert item["type"] == "math"


@pytest.mark.parametrize("expression, field, value", [
    ("atan2(1, 1)", "simplified", "pi/4"),
    ("3atan2(1, 1)", "simplified", "3*pi/4"),
    ("12(3)", "exact_value", "36"),
    ("1.5(2)", "value", 3.0),
])
def test_a_number_before_a_bracket_is_a_product_but_a_function_name_is_not(client, expression, field, value):
    # Rewriting "2(3)" as "2*(3)" also turned atan2(1, 1) into
    # "atan2*(1, 1)", a parse error; since round 1 batch items take the same
    # path (Sentry on PR #603).
    route = client.post("/verify/math", json={"expression": expression}).json()
    item = _batch_item(client, expression)

    for result in (route, item):
        assert result["status"] == "UNVERIFIABLE"
        assert result["constraint_id"] == "math.no_claim"
        assert result[field] == value


def test_a_name_ending_in_a_digit_before_a_bracket_is_a_call_with_or_without_a_claim(client):
    # x2(3) was rewritten to x2*(3) without "=", but refused as an unknown
    # function with "=". Both are now refused.
    route = client.post("/verify/math", json={"expression": "x2(3)"}).json()
    item = _batch_item(client, "x2(3)")
    claim = client.post("/verify/math", json={"expression": "x2(3) = 3*x2"}).json()

    for result in (route, item, claim):
        assert result["status"] == "BLOCKED"
        assert result["admission"] == "BLOCKED"
        assert result["constraint_id"] == "math.parse_error"


@pytest.mark.parametrize("expression", ["1e400", "-1e400", "10**400"])
def test_a_value_past_the_float_range_is_kept_as_a_string(client, expression):
    # float() gave inf, which JSON cannot carry: the route answered 500, and
    # one such item made the whole batch answer 500 (Greptile on PR #603).
    route = client.post("/verify/math", json={"expression": expression})
    batch = client.post("/verify/batch", json={"items": [
        {"query": expression, "type": "math"},
        {"query": "1+1 = 2", "type": "math"},
    ]})

    assert route.status_code == 200
    assert batch.status_code == 200
    body = route.json()
    item, other = (entry["result"] for entry in batch.json()["items"])
    for result in (body, item):
        assert result["status"] == "UNVERIFIABLE"
        assert result["admission"] == "BLOCKED"
        assert result["constraint_id"] == "math.no_claim"
        assert "value" not in result
        assert result["exact_value"].lstrip("-").startswith("1")
    assert body["exact_value"] == item["exact_value"]
    # The other item in the batch is still answered.
    assert other["status"] == "VERIFIED"
    assert other["admission"] == "ADMIT"
