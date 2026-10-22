"""#494: batch logic and natural-language items return what their routes return.

``/verify/logic`` and ``/verify/natural_language`` turn the control plane's
dict into a DiagnosticResult, apply trust enforcement, and (natural language)
add the admission. ``/verify/batch`` returned the raw dict, so a batch caller
got ``SAT`` where a route caller got ``VERIFIED``, natural-language items had
no admission, and batch logic audit rows had no verdict (``verdict: null`` in
``/audit/logs``).

Both now use the same helpers (core/route_diagnostics.py), so a batch item's
result is the route's response for the same control-plane output.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api import main as api_main
from qwed_new.auth.audit_routes import stored_verdict
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.models import VerificationLog
from qwed_new.core.tenant_context import TenantContext

ORG_ID = 1

LOGIC_OUTPUTS = {
    "sat": {"status": "SAT", "model": {"x": "6"}, "dsl_code": "(GT x 5)"},
    "unsat": {"status": "UNSAT", "dsl_code": "(AND (GT x 5) (LT x 3))"},
    "error": {"status": "ERROR", "error": "Logic verification failed"},
}

NL_OUTPUTS = {
    "diagnostic": {"diagnostic": DiagnosticResult.unverifiable("not proven").to_dict()},
    # The usual successful path: the translated expression is proven, but the
    # translation's semantics are not, so VERIFIED is not admitted (#494 review).
    "proven_translation": {"diagnostic": DiagnosticResult.verified(
        "Identity verified",
        developer_fields={"is_valid": True, "query_semantics_verified": False},
        evidence={"left": "2+2", "right": "4"},
        proof_data="2+2=4",
    ).to_dict()},
    "not_math": {"status": "NOT_MATH_QUERY", "verification": {"status": "NOT_MATH_QUERY"}},
    "error": {"status": "ERROR"},
}


@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(organization_id=ORG_ID, organization_name="Org", tier="free", api_key="k")

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


def _same_control_plane(output, method):
    """Make the route's and the batch's control plane return ``output``."""
    async def fake(query, organization_id=None, preferred_provider=None):
        return dict(output)

    return (
        patch.object(api_main.control_plane, method, fake),
        patch.object(api_main.batch_service.control_plane, method, fake),
    )


def _route_and_batch(client, kind, output):
    method = "process_logic_query" if kind == "logic" else "process_natural_language"
    route_patch, batch_patch = _same_control_plane(output, method)
    with route_patch, batch_patch:
        route = client.post(f"/verify/{kind}", json={"query": "q"}).json()
        batch = client.post("/verify/batch", json={"items": [{"query": "q", "type": kind}]}).json()
    return route, batch["items"][0]


@pytest.mark.parametrize("case", sorted(LOGIC_OUTPUTS))
def test_a_batch_logic_item_returns_what_verify_logic_returns(client, case):
    route, item = _route_and_batch(client, "logic", LOGIC_OUTPUTS[case])

    assert item["status"] == "completed"
    assert item["result"] == route
    assert item["result"]["status"] in ("VERIFIED", "UNVERIFIABLE", "BLOCKED")


@pytest.mark.parametrize("case", sorted(NL_OUTPUTS))
def test_a_batch_natural_language_item_returns_what_its_route_returns(client, case):
    route, item = _route_and_batch(client, "natural_language", NL_OUTPUTS[case])

    assert item["status"] == "completed"
    assert item["result"] == route
    assert item["result"]["admission"] in ("ADMIT", "BLOCKED")


def test_a_proven_translation_stays_verified_and_is_not_admitted(client):
    route, item = _route_and_batch(client, "natural_language", NL_OUTPUTS["proven_translation"])

    assert item["result"] == route
    assert item["result"]["status"] == "VERIFIED"
    assert item["result"]["proof_ref"]
    assert item["result"]["admission"] == "BLOCKED"


def test_the_verdict_survives_a_truncated_batch_row(client, isolated_audit_chain):
    # Many fields: past the cap's overall budget the whole result becomes a
    # truncated preview, and its status with it.
    huge = dict(LOGIC_OUTPUTS["sat"], model={f"v{i}": "7" * 120 for i in range(3000)})
    batch_patch = _same_control_plane(huge, "process_logic_query")[1]
    with batch_patch:
        client.post("/verify/batch", json={"items": [{"query": "(GT x 5)", "type": "logic"}]})

    (row,) = _batch_rows(isolated_audit_chain)
    payload = json.loads(row.result)
    assert payload["details"].get("truncated") is True  # the result itself did not fit
    assert stored_verdict(row.result) == "VERIFIED"  # the verdict is kept beside the ids


def test_a_satisfiable_batch_logic_item_is_verified_not_sat(client):
    _, item = _route_and_batch(client, "logic", LOGIC_OUTPUTS["sat"])

    assert item["result"]["status"] == "VERIFIED"
    assert item["result"]["proof_ref"]


def _batch_rows(engine):
    with Session(engine) as session:
        return session.exec(select(VerificationLog).where(VerificationLog.domain.in_(["LOGIC", "MATH"]))).all()


def test_batch_rows_now_carry_a_verdict_and_the_natural_language_admission(client, isolated_audit_chain):
    logic_patch = _same_control_plane(LOGIC_OUTPUTS["sat"], "process_logic_query")[1]
    nl_patch = _same_control_plane(NL_OUTPUTS["diagnostic"], "process_natural_language")[1]
    with logic_patch, nl_patch:
        client.post("/verify/batch", json={"items": [
            {"query": "(GT x 5)", "type": "logic"},
            {"query": "what is 2+2", "type": "natural_language"},
        ]})

    rows = {json.loads(r.result)["batch_item_type"]: r for r in _batch_rows(isolated_audit_chain)}
    # /audit/logs reads the verdict from the stored result: no longer null.
    assert stored_verdict(rows["logic"].result) == "VERIFIED"
    assert rows["logic"].is_verified is True
    assert stored_verdict(rows["natural_language"].result) == "UNVERIFIABLE"
    assert rows["natural_language"].admission == "BLOCKED"
    assert rows["logic"].admission is None  # /verify/logic decides no admission
