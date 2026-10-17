"""Issue #437: a math claim proven false is a decided verdict.

A deterministic counter-proof is VERIFIED (truth was established) with
``is_valid`` False and admission DENY. It must never be reported as
UNVERIFIABLE ("inconclusive"), which means "could not be proven".
"""

import pathlib
from unittest.mock import MagicMock, patch

import pytest
import sympy
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api.main import app, get_current_tenant, get_session
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    DiagnosticStatus,
    admission_decision,
)
from qwed_new.core.models import VerificationLog
from qwed_new.core.verifier import (
    DISPROVEN_STATUS,
    INCONCLUSIVE_STATUS,
    VerificationEngine,
    symbolic_difference_status,
)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "expression, claimed",
    [
        ("2+2", 5),
        ("10**30", 10**30 + 1),
        ("2**64", 18446744073709551615),
    ],
)
def test_verify_math_disproven_claim(expression, claimed):
    result = VerificationEngine().verify_math(expression, claimed)
    assert result["status"] == DISPROVEN_STATUS
    assert result["is_correct"] is False


def test_verify_math_true_claim_still_verified():
    result = VerificationEngine().verify_math("2+2", 4)
    assert result["status"] == "VERIFIED"
    assert result["is_correct"] is True


def test_engine_source_no_longer_emits_correction_needed():
    source = pathlib.Path(VerificationEngine.__module__.replace(".", "/") + ".py")
    text = (pathlib.Path(__file__).resolve().parents[1] / "src" / source).read_text(encoding="utf-8")
    assert "CORRECTION_NEEDED" not in text


def test_wrong_derivative_is_disproven_by_exact_witness():
    # simplify(2*x - 3*x) = -x is undecided on its own; x = 1 is a witness.
    result = VerificationEngine().verify_derivative("x**2", "x", "3*x")
    assert result["status"] == DISPROVEN_STATUS


def test_correct_derivative_still_verified():
    result = VerificationEngine().verify_derivative("x**2", "x", "2*x")
    assert result["status"] == "VERIFIED"


def test_wrong_limit_is_disproven():
    result = VerificationEngine().verify_limit("sin(x)/x", "x", "0", "2")
    assert result["status"] == DISPROVEN_STATUS


def test_undecided_symbolic_difference_is_inconclusive_not_disproven():
    x = sympy.Symbol("x")
    undecided = sympy.Function("f")(x)  # no witness point evaluates to a number
    assert symbolic_difference_status(undecided) == INCONCLUSIVE_STATUS


def test_symbolic_difference_zero_is_verified():
    assert symbolic_difference_status(sympy.Integer(0)) == "VERIFIED"


# ---------------------------------------------------------------------------
# DiagnosticResult contract
# ---------------------------------------------------------------------------

def test_disproven_factory_is_verified_with_is_valid_false():
    dr = DiagnosticResult.disproven(
        "Claimed value is proven false",
        developer_fields={"is_valid": True, "calculated_value": 4},
        evidence={"expression": "2+2", "claimed_value": 5, "calculated_value": 4},
    )
    assert dr.status is DiagnosticStatus.VERIFIED
    assert dr.proof_ref and dr.proof_ref.startswith("sha256:")
    # is_valid is forced False even if the caller passed True.
    assert dr.developer_fields["is_valid"] is False
    assert admission_decision(dr) is AdmissionDecision.BLOCKED


def test_from_legacy_dict_refuses_disproven_without_evidence():
    with pytest.raises(ValueError, match="DISPROVEN"):
        DiagnosticResult.from_legacy_dict({"is_correct": False, "status": "DISPROVEN"}, engine="math")


# ---------------------------------------------------------------------------
# /verify/math endpoint
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    tenant = MagicMock(organization_id=437, api_key=MagicMock(name="key"), user_id=1)
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_session] = lambda: MagicMock()
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("expression", ["2+2=5", "10**30 = 10**30 + 1"])
def test_api_false_identity_is_verified_deny(client, expression, isolated_audit_chain):
    data = client.post("/verify/math", json={"expression": expression}).json()

    assert data["status"] == "VERIFIED"
    assert data["proof_ref"]
    assert data["is_valid"] is False
    assert data["admission"] == "BLOCKED"
    assert "inconclusive" not in data["agent_message"].lower()

    with Session(isolated_audit_chain) as session:
        (logged,) = session.exec(select(VerificationLog)).all()
    assert logged.is_verified is False


def test_api_true_identity_is_verified_admit(client, isolated_audit_chain):
    data = client.post("/verify/math", json={"expression": "2+2=4"}).json()

    assert data["status"] == "VERIFIED"
    assert data["is_valid"] is True
    assert data["admission"] == "ADMIT"

    with Session(isolated_audit_chain) as session:
        (logged,) = session.exec(select(VerificationLog)).all()
    assert logged.is_verified is True


def test_api_undecided_identity_stays_unverifiable(client, isolated_audit_chain):
    # Not an identity, but zero at every exact witness point, so the engine
    # cannot decide it: it must stay UNVERIFIABLE, never VERIFIED.
    expression = "x*(x-1)*(x-2)*(x+1)*(x-3)*(2*x-1) = 0"
    data = client.post("/verify/math", json={"expression": expression}).json()

    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None
    assert data["admission"] == "BLOCKED"
