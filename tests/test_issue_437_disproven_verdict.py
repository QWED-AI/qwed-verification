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
from qwed_new.core.safe_parser import (
    SafeParserError,
    check_closed_expression_cost,
    safe_parse_expr,
)
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
    assert dr.proof_ref
    assert dr.proof_ref.startswith("sha256:")
    # is_valid is forced False even if the caller passed True.
    assert dr.developer_fields["is_valid"] is False
    assert admission_decision(dr) is AdmissionDecision.BLOCKED


def test_from_legacy_dict_refuses_disproven_without_evidence():
    with pytest.raises(ValueError, match="DISPROVEN"):
        DiagnosticResult.from_legacy_dict({"is_correct": False, "status": "DISPROVEN"}, engine="math")


# ---------------------------------------------------------------------------
# /verify/math endpoint
# ---------------------------------------------------------------------------

def _mock_session():
    # A named factory, not MagicMock itself: FastAPI reads a dependency's
    # signature, and MagicMock(*args, **kwargs) would become query params.
    return MagicMock()


@pytest.fixture
def client():
    tenant = MagicMock(organization_id=437, api_key=MagicMock(name="key"), user_id=1)
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_session] = _mock_session
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
    # True for every positive integer n (the parser domain for n), but
    # simplify cannot show it and the witnesses inside that domain are all
    # zeros: undecided, so UNVERIFIABLE, never VERIFIED or a false disproof.
    expression = "Abs(sin(pi*n/2)) = sin(pi*n/2)**2"
    data = client.post("/verify/math", json={"expression": expression}).json()

    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None
    assert data["admission"] == "BLOCKED"


def test_api_polynomial_zero_at_every_witness_is_disproven(client, isolated_audit_chain):
    # Zero at all six witnesses but not identically zero: polynomial
    # equality is decidable, so this is a counter-proof, not "inconclusive".
    expression = "x*(x-1)*(x-2)*(x+1)*(x-3)*(2*x-1) = 0"
    data = client.post("/verify/math", json={"expression": expression}).json()

    assert data["status"] == "VERIFIED"
    assert data["is_valid"] is False
    assert data["admission"] == "BLOCKED"


def test_api_float_rounding_residue_is_not_a_disproof(client, isolated_audit_chain):
    # 0.1 + 0.2 - 0.3 is 5.55e-17 in binary floating point.
    data = client.post("/verify/math", json={"expression": "0.1 + 0.2 = 0.3"}).json()

    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None
    assert data["admission"] == "BLOCKED"


def test_undecided_matrix_equality_is_inconclusive(monkeypatch):
    # Matrix.equals returns None when it cannot decide: not a disproof.
    monkeypatch.setattr(sympy.Matrix, "equals", lambda self, other: None)
    result = VerificationEngine().verify_matrix_operation(
        "add", {"A": [[1, 0], [0, 1]], "B": [[1, 0], [0, 1]]}, [[2, 0], [0, 2]]
    )
    assert result["status"] == INCONCLUSIVE_STATUS
    assert result["is_correct"] is False


def test_nonzero_constant_difference_is_disproven():
    assert symbolic_difference_status(sympy.Integer(2)) == DISPROVEN_STATUS


# ---------------------------------------------------------------------------
# Witness substitution must not expand what safe_parser refuses to expand.
# A lazy symbolic power becomes an exact one at a witness point:
# 9**9**9**x at x=1 is a ~370M-digit integer. Unpatched, these hang.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "expression, expected",
    [
        # Every witness is over budget (or irrational in a tower): undecided.
        ("9**9**9**(x**2+8) - 1", INCONCLUSIVE_STATUS),
        ("9**9**9**(x/2+8) - 1", INCONCLUSIVE_STATUS),
        ("exp(exp(exp(exp(x)))) - 1", INCONCLUSIVE_STATUS),
        # x = 0 is an affordable witness (9**9**1 = 387420489): decided.
        ("9**9**9**x - 1", DISPROVEN_STATUS),
    ],
)
def test_witness_substitution_respects_expansion_budget(expression, expected):
    difference = sympy.simplify(safe_parse_expr(expression))
    assert symbolic_difference_status(difference) == expected


def _substituted(expression, point):
    expr = safe_parse_expr(expression)
    with sympy.evaluate(False):
        return expr.xreplace({sym: point for sym in expr.free_symbols})


@pytest.mark.parametrize(
    "expression, point",
    [
        ("9**9**9**x", 1),                  # exact integer tower
        ("(x + 1/2)**(9**9**x)", 1),         # rational base, huge exponent
        ("sqrt(2)**(9**9**x)", 1),           # irrational base, huge exponent
        ("factorial(x**x**x)", 3),           # factorial of 3**27
        ("(10**300*x)**(200*x)", 2),         # 301-digit base ** 400: over digit budget
        ("9**9**9**(x/2)", 1),               # irrational exponent in a tower
        ("exp(exp(exp(x)))", 1),             # exp tower
    ],
)
def test_closed_expression_gate_rejects_unaffordable_witnesses(expression, point):
    with pytest.raises(SafeParserError):
        check_closed_expression_cost(_substituted(expression, sympy.Integer(point)))


@pytest.mark.parametrize("expression", ["x**2 + 3*x", "sin(x)**2", "sqrt(x) + exp(x)", "factorial(x) / x"])
def test_closed_expression_gate_accepts_cheap_witnesses(expression):
    check_closed_expression_cost(_substituted(expression, sympy.Integer(3)))


def test_closed_expression_gate_rejects_free_symbols():
    with pytest.raises(SafeParserError, match="free symbols"):
        check_closed_expression_cost(safe_parse_expr("x + 1"))


def test_api_identity_bomb_is_unverifiable_not_expanded(client, isolated_audit_chain):
    data = client.post("/verify/math", json={"expression": "9**9**9**(x**2+8) = 1"}).json()

    assert data["status"] == "UNVERIFIABLE"
    assert data["admission"] == "BLOCKED"


def test_closed_expression_gate_rejects_product_over_digit_budget():
    # Each factor fits the budget on its own; their product does not.
    expression = " * ".join(f"(x + {k})**9999" for k in range(11))
    with pytest.raises(SafeParserError, match="unbounded"):
        check_closed_expression_cost(_substituted(expression, sympy.Integer(9)))


def test_witness_at_a_pole_is_skipped_not_raised():
    # 1/x at x = 0 folds to no exact value (zoo); the gate lets it through and
    # the non-finite value is ignored, so another witness decides.
    check_closed_expression_cost(_substituted("1/x", sympy.Integer(0)))
    assert symbolic_difference_status(safe_parse_expr("1/x")) == DISPROVEN_STATUS


# ---------------------------------------------------------------------------
# Domain, floats, polynomials and overflow
# ---------------------------------------------------------------------------

def _diff(lhs, rhs):
    return sympy.simplify(safe_parse_expr(lhs) - safe_parse_expr(rhs))


def test_witness_outside_symbol_domain_is_not_a_counterexample():
    # n is a positive integer; n = 1/2, 0, -1 are outside its domain.
    assert symbolic_difference_status(_diff("Abs(sin(pi*n/2))", "sin(pi*n/2)**2")) == INCONCLUSIVE_STATUS


def test_witness_inside_symbol_domain_still_disproves():
    assert symbolic_difference_status(_diff("n**2", "n")) == DISPROVEN_STATUS


@pytest.mark.parametrize("lhs, rhs", [("0.1 + 0.2", "0.3"), ("0.1*x + 0.2*x", "0.3*x")])
def test_float_residue_is_inconclusive(lhs, rhs):
    assert symbolic_difference_status(_diff(lhs, rhs)) == INCONCLUSIVE_STATUS


def test_exact_float_cancellation_still_verified():
    assert symbolic_difference_status(_diff("0.5 + 0.25", "0.75")) == "VERIFIED"


@pytest.mark.parametrize(
    "lhs, rhs, expected",
    [
        ("x*(x-1)*(x-2)*(x+1)*(x-3)*(2*x-1)", "0", DISPROVEN_STATUS),
        ("(x+1)**2", "x**2 + 2*x + 1", "VERIFIED"),
        ("(x+y)**3", "x**3 + y**3", DISPROVEN_STATUS),
    ],
)
def test_polynomial_difference_is_decided_exactly(lhs, rhs, expected):
    assert symbolic_difference_status(_diff(lhs, rhs)) == expected


def test_polynomial_over_expansion_bounds_falls_back_to_witnesses():
    # Degree 65 and a 4-variable degree-20 power are past the expansion
    # bounds; the witness search still decides them without expanding.
    assert symbolic_difference_status(_diff("(x+1)**65", "1")) == DISPROVEN_STATUS
    assert symbolic_difference_status(_diff("(a+b+c+d)**20", "1")) == DISPROVEN_STATUS


def test_polynomial_degree_bound_is_none_for_non_polynomial_nodes():
    from qwed_new.core.verifier import _polynomial_degree_bound

    x = sympy.Symbol("x")
    assert _polynomial_degree_bound(sympy.sin(x), {x}) is None
    assert _polynomial_degree_bound(x + sympy.sin(x), {x}) is None
    assert _polynomial_degree_bound(sympy.Pow(sympy.sin(x), 2, evaluate=False), {x}) is None


def test_overflowed_computation_is_not_a_counterexample():
    # sum([1e308, 1e308]) overflows to inf: a failed computation, not a disproof.
    result = VerificationEngine().verify_statistics([1e308, 1e308], "mean", 1e308)
    assert result["status"] == INCONCLUSIVE_STATUS


def test_nan_claim_is_not_a_counterexample():
    result = VerificationEngine().verify_statistics([1, 2, 3], "mean", float("nan"))
    assert result["status"] == INCONCLUSIVE_STATUS


def test_finite_mismatch_is_still_disproven():
    result = VerificationEngine().verify_statistics([1, 2, 3], "mean", 5)
    assert result["status"] == DISPROVEN_STATUS


def test_is_finite_value_types():
    from decimal import Decimal

    from qwed_new.core.verifier import _is_finite_value

    assert _is_finite_value(10**400) is True  # exact int, no float overflow
    assert _is_finite_value(True) is True
    assert _is_finite_value(Decimal("Infinity")) is False
    assert _is_finite_value(Decimal("1.5")) is True
    assert _is_finite_value(float("inf")) is False
    assert _is_finite_value(sympy.oo) is False
    assert _is_finite_value(sympy.Integer(3)) is True


# ---------------------------------------------------------------------------
# /verify/natural_language carries the control plane verdict through
# ---------------------------------------------------------------------------

def _nl_post(client, control_plane_result):
    from unittest.mock import AsyncMock

    with patch(
        "qwed_new.api.main.control_plane.process_natural_language",
        new_callable=AsyncMock,
        return_value=control_plane_result,
    ):
        return client.post("/verify/natural_language", json={"query": "What is 2+2?"}).json()


def _disproven_diagnostic():
    return DiagnosticResult.disproven(
        "Claimed value is proven false",
        developer_fields={"status": "DISPROVEN", "calculated_value": 4.0, "claimed_value": 5},
        evidence={"expression": "2+2", "claimed_value": 5, "calculated_value": 4.0},
    ).to_dict()


def test_natural_language_returns_counter_proof_with_admission(client, isolated_audit_chain):
    data = _nl_post(client, {
        "status": "VERIFIED",
        "verification": {"status": "DISPROVEN", "is_correct": False},
        "diagnostic": _disproven_diagnostic(),
    })

    assert data["status"] == "VERIFIED"
    assert data["proof_ref"]
    assert data["is_valid"] is False
    assert data["admission"] == "BLOCKED"

    with Session(isolated_audit_chain) as session:
        (logged,) = session.exec(select(VerificationLog)).all()
    assert logged.is_verified is False


def test_natural_language_malformed_diagnostic_is_blocked(client, isolated_audit_chain):
    # VERIFIED without proof_ref cannot be deserialized: fail closed.
    data = _nl_post(client, {"status": "VERIFIED", "diagnostic": {"status": "VERIFIED", "agent_message": "x"}})

    assert data["status"] == "BLOCKED"
    assert data["admission"] == "BLOCKED"
    assert data["constraint_id"] == "api.natural_language.malformed_diagnostic"


def test_natural_language_without_diagnostic_uses_fail_closed_mapping(client, isolated_audit_chain):
    data = _nl_post(client, {"status": "BLOCKED", "error": "Security Policy Violation"})

    assert data["status"] == "UNVERIFIABLE"
    assert data["admission"] == "BLOCKED"


@pytest.mark.asyncio
async def test_control_plane_attaches_enforced_diagnostic(monkeypatch):
    from tests.test_pr5_determinism_alignment import _build_cp

    cp = _build_cp(monkeypatch, claimed_answer=40.0)
    result = await cp.process_natural_language("What is 15% of 200?", organization_id=None)

    diagnostic = DiagnosticResult.from_dict(result["diagnostic"])
    assert diagnostic.status is DiagnosticStatus.VERIFIED
    assert diagnostic.developer_fields["is_valid"] is False
    assert result["admission"] == "BLOCKED"


@pytest.mark.asyncio
async def test_control_plane_sanitizer_rejection_blocks_the_verdict(monkeypatch):
    from tests.test_pr5_determinism_alignment import _build_cp

    cp = _build_cp(monkeypatch, claimed_answer=30.0)

    def _reject(result, output_type, organization_id):
        if output_type == "math":
            return {**result, "status": "ERROR", "error": "unsafe expression"}
        return result

    monkeypatch.setattr(cp.output_sanitizer, "sanitize_output", _reject)
    result = await cp.process_natural_language("What is 15% of 200?", organization_id=None)

    assert result["status"] == "ERROR"
    assert result["diagnostic"]["status"] == "BLOCKED"
    assert result["admission"] == "BLOCKED"


def test_undecided_closed_difference_is_inconclusive():
    # No free symbols and SymPy cannot decide is_zero: no witness to try.
    assert symbolic_difference_status(sympy.Function("f")(1)) == INCONCLUSIVE_STATUS


def test_translated_disproof_is_not_a_user_query_verdict():
    from qwed_new.core.control_plane import ControlPlane

    assert ControlPlane._determine_math_response_status({"status": DISPROVEN_STATUS}) == "INCONCLUSIVE"
