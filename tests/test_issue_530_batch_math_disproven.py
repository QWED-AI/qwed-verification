"""#530: a batch math item gets the verdict /verify/math gives.

``_verify_batch_math`` decided on ``simplify(left - right) != 0`` and reported
a claim proven false as UNVERIFIABLE with no ``proof_ref``, while
/verify/math reports it VERIFIED with ``is_valid`` False and admission
BLOCKED (#437), and keeps a difference SymPy cannot decide UNVERIFIABLE. Both
now build the identity's verdict with ``math_identity_result``.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api.main import app, get_current_tenant, get_session
from qwed_new.core.batch import BatchItem, BatchVerificationService, VerificationType
from qwed_new.core.math_identity import math_identity_result


def _batch(expression):
    item = BatchItem(id="530", query=expression, verification_type=VerificationType.MATH)
    return BatchVerificationService()._verify_batch_math(item)


def _mock_session():
    # A named factory, not MagicMock itself: FastAPI reads a dependency's
    # signature, and MagicMock(*args, **kwargs) would become query params.
    return MagicMock()


@pytest.fixture
def client(isolated_audit_chain):
    tenant = MagicMock(organization_id=530, api_key=MagicMock(name="key"), user_id=1)
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("expression", ["2+2=5", "x + x = x", "10**30 = 10**30 + 1"])
def test_a_claim_proven_false_is_verified_and_denied(expression):
    result = _batch(expression)

    assert (result["status"], result["is_valid"], result["admission"]) == ("VERIFIED", False, "BLOCKED")
    assert result["proof_ref"].startswith("sha256:")
    assert result["agent_message"] == "Identity is false"


def test_a_true_identity_is_unchanged():
    result = _batch("2+2=4")

    assert (result["status"], result["is_valid"], result["admission"]) == ("VERIFIED", True, "ADMIT")
    assert result["proof_ref"].startswith("sha256:")


@pytest.mark.parametrize("expression", ["9**9**9**(x**2+8) = 1", "0.1 + 0.2 = 0.3"])
def test_an_undecided_difference_stays_unverifiable(expression):
    # SymPy cannot decide the first; the second only differs by Float
    # rounding residue, which proves nothing.
    result = _batch(expression)

    assert (result["status"], result["is_valid"], result["admission"]) == ("UNVERIFIABLE", False, "BLOCKED")
    assert result["proof_ref"] is None


def test_a_domain_restricted_identity_stays_unverifiable():
    result = _batch("x/x = 1")

    assert result["status"] == "UNVERIFIABLE"
    assert result["constraint_id"] == "math.domain_restricted_identity"


def test_the_batch_keeps_its_own_fields():
    result = _batch("2+2=5")

    assert (result["type"], result["query"]) == ("math", "2+2=5")
    assert result["diff"] == result["simplified_difference"] == "-1"


@pytest.mark.parametrize("expression", [
    "2+2=5",
    "2+2=4",
    "x + x = 2*x",
    "x + x = x",
    "x/x = 1",
    "0.1 + 0.2 = 0.3",
    "9**9**9**(x**2+8) = 1",
    "sin(x)**2 + cos(x)**2 = 1",
])
def test_the_batch_and_the_route_agree(client, expression):
    route = client.post("/verify/math", json={"expression": expression}).json()
    batch = _batch(expression)

    keys = ("status", "is_valid", "admission", "agent_message", "is_authoritative")
    assert {k: batch[k] for k in keys} == {k: route[k] for k in keys}
    assert (batch["proof_ref"] is None) == (route["proof_ref"] is None)


def test_the_shared_function_decides_without_signing():
    dr = math_identity_result("2+2=5")

    assert (dr.status.value, dr.developer_fields["is_valid"]) == ("VERIFIED", False)
    assert "attestation" not in dr.developer_fields
