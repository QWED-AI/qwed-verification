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
    # An entry comparison SymPy cannot decide (equals -> None) is not a disproof.
    monkeypatch.setattr(sympy.Expr, "equals", lambda self, other, failing_expression=False: None)
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
    candidate = _substituted(expression, sympy.Integer(point))
    with pytest.raises(SafeParserError):
        check_closed_expression_cost(candidate)


@pytest.mark.parametrize("expression", ["x**2 + 3*x", "sin(x)**2", "sqrt(x) + exp(x)", "factorial(x) / x"])
def test_closed_expression_gate_accepts_cheap_witnesses(expression):
    check_closed_expression_cost(_substituted(expression, sympy.Integer(3)))


def test_closed_expression_gate_rejects_free_symbols():
    open_expression = safe_parse_expr("x + 1")
    with pytest.raises(SafeParserError, match="free symbols"):
        check_closed_expression_cost(open_expression)


def test_api_identity_bomb_is_unverifiable_not_expanded(client, isolated_audit_chain):
    data = client.post("/verify/math", json={"expression": "9**9**9**(x**2+8) = 1"}).json()

    assert data["status"] == "UNVERIFIABLE"
    assert data["admission"] == "BLOCKED"


def test_closed_expression_gate_rejects_product_over_digit_budget():
    # Each factor fits the budget on its own; their product does not.
    expression = " * ".join(f"(x + {k})**9999" for k in range(11))
    candidate = _substituted(expression, sympy.Integer(9))
    with pytest.raises(SafeParserError, match="unbounded"):
        check_closed_expression_cost(candidate)


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


# ---------------------------------------------------------------------------
# Polynomial coefficients may be irrational constants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "lhs, rhs",
    [
        # sqrt(5 + 2*sqrt(6)) == sqrt(2) + sqrt(3)
        ("x*(sqrt(2) + sqrt(3))", "x*sqrt(5 + 2*sqrt(6))"),
        # cos(pi/7) - cos(2*pi/7) + cos(3*pi/7) == 1/2
        ("x*(cos(pi/7) - cos(2*pi/7) + cos(3*pi/7))", "x/2"),
        ("x*sin(2)", "2*x*sin(1)*cos(1)"),
    ],
)
def test_true_identity_with_irrational_coefficient_is_never_disproven(lhs, rhs):
    assert symbolic_difference_status(_diff(lhs, rhs)) in ("VERIFIED", INCONCLUSIVE_STATUS)


def test_decided_irrational_coefficient_still_disproves():
    assert symbolic_difference_status(_diff("x*sqrt(2)", "x")) == DISPROVEN_STATUS


def test_api_true_identity_with_undecided_coefficient_is_unverifiable(client, isolated_audit_chain):
    expression = "x*(cos(pi/7) - cos(2*pi/7) + cos(3*pi/7)) = x/2"
    data = client.post("/verify/math", json={"expression": expression}).json()

    assert data["status"] == "UNVERIFIABLE"
    assert data["admission"] == "BLOCKED"


# ---------------------------------------------------------------------------
# The natural-language verdict says what the engine actually checked
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("claimed, holds", [(30.0, True), (40.0, False)])
async def test_control_plane_verdict_carries_translated_scope(monkeypatch, claimed, holds):
    from tests.test_pr5_determinism_alignment import _build_cp

    cp = _build_cp(monkeypatch, claimed_answer=claimed)
    result = await cp.process_natural_language("What is 15% of 200?", organization_id=None)

    fields = result["diagnostic"]["developer_fields"]
    assert result["diagnostic"]["status"] == "VERIFIED"
    assert fields["is_valid"] is holds
    assert fields["translated_expression"] == "0.15 * 200"
    assert fields["verification_scope"] == "translated_expression_only"
    assert fields["query_semantics_verified"] is False


def test_natural_language_response_exposes_translated_scope(client, isolated_audit_chain):
    diagnostic = DiagnosticResult.verified(
        "Expression verified successfully",
        developer_fields={
            "is_valid": True,
            "translated_expression": "0.15 * 200",
            "verification_scope": "translated_expression_only",
            "query_semantics_verified": False,
        },
        evidence={"expression": "0.15 * 200", "calculated_value": 30.0},
    ).to_dict()
    data = _nl_post(client, {"status": "VERIFIED", "diagnostic": diagnostic})

    assert data["admission"] == "ADMIT"
    assert data["translated_expression"] == "0.15 * 200"
    assert data["verification_scope"] == "translated_expression_only"
    assert data["query_semantics_verified"] is False


@pytest.mark.asyncio
async def test_control_plane_undecided_engine_result_is_not_admitted(monkeypatch):
    from tests.test_pr5_determinism_alignment import _build_cp

    cp = _build_cp(monkeypatch, claimed_answer=30.0)
    monkeypatch.setattr(
        cp.math_verifier,
        "verify_math",
        lambda expression, expected_value: {"status": INCONCLUSIVE_STATUS, "is_correct": False},
    )
    result = await cp.process_natural_language("What is 15% of 200?", organization_id=None)

    assert result["status"] == "UNVERIFIABLE"
    assert result["diagnostic"]["proof_ref"] is None
    assert result["admission"] == "BLOCKED"


# ---------------------------------------------------------------------------
# Matrix comparison with float entries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "operation, matrices, claimed, expected",
    [
        # Computed entries that are binary floats: relative tolerance.
        # 0.1 + 0.2 is 0.30000000000000004.
        ("add", {"A": [[0.1]], "B": [[0.2]]}, [[0.3]], "VERIFIED"),
        ("add", {"A": [[0.1]], "B": [[0.2]]}, [[0.9]], DISPROVEN_STATUS),
        ("multiply", {"A": [[0.1, 0.2]], "B": [[3], [1]]}, [[0.5]], "VERIFIED"),
        # One ulp off at 1e10 is inside a relative bound, not an absolute 1e-6.
        ("add", {"A": [[1e10 + 0.1]], "B": [[0.2]]}, [[1e10 + 0.3]], "VERIFIED"),
        # 2e-7 is not "close to" 0: there is no absolute 1e-6 window.
        ("add", {"A": [[1e-7]], "B": [[1e-7]]}, [[0]], DISPROVEN_STATUS),
        # Exact computed entries are compared exactly, never with a tolerance.
        ("add", {"A": [[1]], "B": [[2]]}, [[3.0000005]], DISPROVEN_STATUS),
        ("inverse", {"A": [[10000000]]}, [[0.0]], DISPROVEN_STATUS),
        # 1/3 truncated to 15 digits: inside the float rounding window, so it
        # cannot be told apart from rounding (undecided, still not admitted).
        ("inverse", {"A": [[3]]}, [[0.333333333333333]], INCONCLUSIVE_STATUS),
        ("inverse", {"A": [[2, 0], [0, 4]]}, [[0.5, 0], [0, 0.25]], "VERIFIED"),
        # A float elsewhere in the matrix must not round exact entries.
        ("transpose", {"A": [[10**18, 0.5]]}, [[10**18 + 1], [0.5]], DISPROVEN_STATUS),
        ("add", {"A": [[1, 2]], "B": [[3, 4]]}, [[4, 6]], "VERIFIED"),
        ("add", {"A": [[1, 2]], "B": [[3, 4]]}, [[4, 7]], DISPROVEN_STATUS),
        # A claimed matrix of the wrong shape is a decided disproof.
        ("add", {"A": [[1, 2]], "B": [[3, 4]]}, [[4, 6, 0]], DISPROVEN_STATUS),
        # Non-finite entries are failed computations or claims, not disproofs.
        ("add", {"A": [[float("inf")]], "B": [[1]]}, [[5]], INCONCLUSIVE_STATUS),
        ("add", {"A": [[float("nan")]], "B": [[1]]}, [[1]], INCONCLUSIVE_STATUS),
        ("add", {"A": [[1e308]], "B": [[1e308]]}, [[2e308]], INCONCLUSIVE_STATUS),
        # 1e308 + 1e308 is finite in SymPy; it must not overflow into a match.
        ("add", {"A": [[1e308]], "B": [[1e308]]}, [[1.0]], DISPROVEN_STATUS),
    ],
)
def test_matrix_comparison_handles_float_residue(operation, matrices, claimed, expected):
    result = VerificationEngine().verify_matrix_operation(operation, matrices, claimed)
    assert result["status"] == expected
    assert result["is_correct"] is (expected == "VERIFIED")


def test_float_entry_comparison_is_undecided_for_non_numeric_or_nan():
    from qwed_new.core.verifier import _floats_close

    assert _floats_close(sympy.Float(1.0), sympy.Symbol("x")) is None
    assert _floats_close(sympy.Float(1.0), sympy.nan) is None
    assert _floats_close(sympy.Float(1.0), sympy.Float(1.0)) is True


# ---------------------------------------------------------------------------
# Exact results that are not doubles, tiny values, failing witnesses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "matrices, claimed, expected",
    [
        # 1/3 is not a double: its correctly rounded double is the best claim.
        ({"A": [[3]]}, [[1 / 3]], "VERIFIED"),
        ({"A": [[2, 1], [1, 2]]}, [[2 / 3, -1 / 3], [-1 / 3, 2 / 3]], "VERIFIED"),
        # Inside the rounding window but not the nearest double: undecided.
        ({"A": [[3]]}, [[0.33333333333333326]], INCONCLUSIVE_STATUS),
        # Far outside it: decided.
        ({"A": [[3]]}, [[0.3]], DISPROVEN_STATUS),
    ],
)
def test_inverse_with_non_double_exact_entries(matrices, claimed, expected):
    result = VerificationEngine().verify_matrix_operation("inverse", matrices, claimed)
    assert result["status"] == expected


def test_relative_bound_is_not_swamped_for_small_values():
    from qwed_new.core.verifier import _floats_close

    # Boltzmann constant vs a 5-digit truncation: 3e-5 relative error.
    assert _floats_close(sympy.Float(1.380649e-23), sympy.Float(1.3806e-23)) is False
    # Cancellation residue against an exact zero claim is still rounding.
    assert _floats_close(sympy.Float(5.551115123125783e-17), sympy.Integer(0)) is True


def test_nearest_double_rejects_non_rational_and_overflow():
    from qwed_new.core.verifier import _nearest_double

    assert _nearest_double(sympy.sqrt(2)) is None
    assert _nearest_double(sympy.Integer(10) ** 400) is None
    assert _nearest_double(sympy.Rational(1, 3)) == 1 / 3


def test_witness_that_sympy_cannot_evaluate_is_skipped():
    # d/dx Abs(x) for a complex x leaves Derivative(re(x), x), which cannot be
    # taken with respect to a number: inconclusive, not an engine error.
    result = VerificationEngine().verify_derivative("Abs(x)", "x", "1")
    assert result["status"] == INCONCLUSIVE_STATUS



@pytest.mark.parametrize(
    "matrix, claimed, expected",
    [
        # 10**18 + 1 is not a double; its claim of 1e18 (the same double as
        # 1000000000000000001.0) is undecided: never accepted, never disproven.
        ([[10**18 + 1]], [[1e18]], INCONCLUSIVE_STATUS),
        ([[10**18 + 1]], [[1000000000000000001.0]], INCONCLUSIVE_STATUS),
        ([[10**18]], [[1e18]], "VERIFIED"),
        # 2**60 is a double: a float claim whose double is exactly it holds.
        ([[2**60]], [[1152921504606846976.0]], "VERIFIED"),
        # Outside the rounding: decided.
        ([[10**18 + 1]], [[1.0000000000000002e18]], DISPROVEN_STATUS),
    ],
)
def test_exact_integers_are_never_matched_through_rounding(matrix, claimed, expected):
    result = VerificationEngine().verify_matrix_operation("transpose", {"A": matrix}, claimed)
    assert result["status"] == expected


@pytest.mark.parametrize(
    "cash_flows, claimed, expected",
    [
        # Tiny cash flows: an absolute NPV bound used to stop at the 0.1 guess.
        ([-0.0001, 0.00012], 0.2, "VERIFIED"),
        ([-0.0001, 0.00012], 0.1, DISPROVEN_STATUS),
        ([-100, 120], 0.2, "VERIFIED"),
        # NPV is exactly 0 at the initial guess.
        ([-100, 110], 0.1, "VERIFIED"),
    ],
)
def test_irr_converges_on_rate_step_not_npv_residual(cash_flows, claimed, expected):
    result = VerificationEngine().verify_irr(cash_flows, claimed)
    assert result["status"] == expected
    assert result["converged"] is True



def test_irr_solver_reports_stall_and_non_convergence():
    # A single cash flow has a zero derivative: stall, not a root.
    assert VerificationEngine._find_irr_newton([5])["reason"] == "derivative_stall"
    # (1 - u)**2 + 1e-4 has no real root: Newton never settles.
    result = VerificationEngine._find_irr_newton([1, -2, 1.0001])
    assert result["converged"] is False
    assert result["reason"] == "max_iterations"



@pytest.mark.parametrize(
    "matrices, claimed, expected",
    [
        # Inputs are read as the decimals written, so the sum is exact.
        ({"A": [[0.5]], "B": [[1e9]]}, [[1000000001.0]], DISPROVEN_STATUS),
        ({"A": [[0.5]], "B": [[1e9]]}, [[1000000000.5]], "VERIFIED"),
        # A non-zero exact result is never accepted as an exact-zero claim.
        ({"A": [[1e-13]], "B": [[0.0]]}, [[0.0]], INCONCLUSIVE_STATUS),
    ],
)
def test_elementwise_matrix_results_are_exact(matrices, claimed, expected):
    result = VerificationEngine().verify_matrix_operation("add", matrices, claimed)
    assert result["status"] == expected


@pytest.mark.parametrize(
    "args, kwargs, expected",
    [
        # Exact legal definitions: correct claims hold even with a strict tolerance.
        ((1, "lb", "kg", 0.45359237), {"tolerance": 1e-9}, "VERIFIED"),
        ((1, "gal", "l", 3.785411784), {"tolerance": 1e-9}, "VERIFIED"),
        ((1, "cup", "ml", 236.5882365), {"tolerance": 0}, "VERIFIED"),
        ((1, "km", "m", 999), {}, DISPROVEN_STATUS),
        # Different dimensions never produce a verdict.
        ((1, "m", "kg", 1), {}, "BLOCKED"),
        ((1, "km", "m", float("nan")), {}, INCONCLUSIVE_STATUS),
        ((0, "m", "km", 0), {}, "VERIFIED"),
    ],
)
def test_unit_conversion_is_exact_and_dimension_checked(args, kwargs, expected):
    assert VerificationEngine().verify_unit_conversion(*args, **kwargs)["status"] == expected



@pytest.mark.parametrize(
    "args, kwargs",
    [
        ((1, "furlong", "m", 201.168), {}),
        ((1, "m", "furlong", 0.005), {}),
        # An invalid tolerance is rejected, never used.
        ((1, "km", "m", 1000), {"tolerance": -1}),
    ],
)
def test_unit_conversion_rejects_unknown_units_and_bad_tolerance(args, kwargs):
    result = VerificationEngine().verify_unit_conversion(*args, **kwargs)
    assert result["status"] == "ERROR"
    assert result["is_correct"] is False



@pytest.mark.parametrize(
    "matrix, claimed, expected",
    [
        ([[1, 2], [3, 4]], -2, "VERIFIED"),
        ([[1, 2], [3, 4]], -2.0, "VERIFIED"),
        # An absolute 1e-6 window used to accept this wrong claim.
        ([[1, 2], [3, 4]], -2.0000001, DISPROVEN_STATUS),
        ([[0.1, 0.2], [0.3, 0.4]], -0.02, "VERIFIED"),
        # Large magnitude: exact, so no ulp residue can flip the verdict.
        ([[1e10 + 0.1, 0], [0, 1]], 1e10 + 0.1, "VERIFIED"),
        ([[float("inf"), 0], [0, 1]], 1, INCONCLUSIVE_STATUS),
    ],
)
def test_determinant_is_exact(matrix, claimed, expected):
    result = VerificationEngine().verify_matrix_operation("determinant", {"A": matrix}, claimed)
    assert result["status"] == expected



@pytest.mark.parametrize(
    "integrand, claimed, lower, upper, expected",
    [
        # Exact on both sides: decided exactly.
        ("x**2", "1/3", "0", "1", "VERIFIED"),
        ("x**2", "1/4", "0", "1", DISPROVEN_STATUS),
        ("2", "8000000002", "0", "4000000000", DISPROVEN_STATUS),
        # Float claims: 1e-6 tolerance, evaluated in SymPy precision.
        ("x**2", "0.333333", "0", "1", "VERIFIED"),
        ("x**2", "0.3", "0", "1", DISPROVEN_STATUS),
        ("sin(x)/x", "0.946083", "0", "1", "VERIFIED"),
        # A divergent integral is not a counter-proof.
        ("1/x", "1", "1", "oo", INCONCLUSIVE_STATUS),
        # Off by 2 at 8e9: far outside the double spacing (~1e-6), decided.
        ("2", "8000000002.0", "0", "4000000000", DISPROVEN_STATUS),
        # A 17-digit claim may be a double's repr (parsed at 60 bits): off by
        # 1e-4 at 1e12 is within one double ulp, so it stays undecided.
        ("1", "1000000000000.0001", "0", "10**12", INCONCLUSIVE_STATUS),
        # The repr of the double nearest 10**12*pi is not a counter-proof.
        ("1", "3141592653589.793", "0", "10**12*pi", INCONCLUSIVE_STATUS),
        # 10**400 + 1 vs a 1e400 claim: rounding before subtracting used to
        # make this VERIFIED; it cannot be established cheaply, so undecided.
        ("10**300*10**100 + 1", "Float(10**400, 50)", "0", "1", INCONCLUSIVE_STATUS),
    ],
)
def test_definite_integral_verdicts(integrand, claimed, lower, upper, expected):
    result = VerificationEngine().verify_integral(integrand, "x", claimed, lower_bound=lower, upper_bound=upper)
    assert result["status"] == expected


def test_definite_integral_rounding_window_is_undecided():
    from qwed_new.core.verifier import _scalar_status

    exact = sympy.Rational(87960930222080009765725, 10000000000)
    # 1e-3 off at 8.8e12 with a double claim: beyond the 1e-6 tolerance,
    # inside the double's rounding.
    assert _scalar_status(exact, sympy.Float(8796093022208.001)) == INCONCLUSIVE_STATUS
    # The same value given at 30 digits is precise enough to decide.
    assert _scalar_status(exact, sympy.Float("8796093022208.001", 30)) == DISPROVEN_STATUS
    assert _scalar_status(sympy.Symbol("x"), sympy.Float(1.0)) == INCONCLUSIVE_STATUS
    assert _scalar_status(sympy.nan, sympy.Float(1.0)) == INCONCLUSIVE_STATUS



@pytest.mark.parametrize(
    "matrix, claimed, expected",
    [
        # Large irrational eigenvalues: exact roots, difference at full precision.
        ([[2 * 10**9, 10**9], [10**9, 10**9]], [381966011.25010514, 2618033988.7498946], "VERIFIED"),
        ([[1, 2], [3, 4]], [-0.3722813232690143, 5.372281323269014], "VERIFIED"),
        ([[2, 0], [0, 3]], [2, 4], DISPROVEN_STATUS),
        # 1e-4 off at 1e12: beyond 1e-6, within the claim's double spacing.
        ([[10**12, 0], [0, 1]], [1, 1000000000000.0001], INCONCLUSIVE_STATUS),
        # Rotation matrix: eigenvalues are +-i; matching only real parts used
        # to accept [0, 0].
        ([[0, -1], [1, 0]], [0, 0], DISPROVEN_STATUS),
    ],
)
def test_eigenvalues_compared_exactly(matrix, claimed, expected):
    result = VerificationEngine().verify_matrix_operation("eigenvalues", {"A": matrix}, claimed)
    assert result["status"] == expected


@pytest.mark.parametrize(
    "args, kwargs, expected",
    [
        # 300 - 273.15 is 26.850000000000023 in binary floats.
        ((300, "k", "c", 26.85), {"tolerance": 0}, "VERIFIED"),
        ((32, "f", "c", 0), {"tolerance": 0}, "VERIFIED"),
        ((100, "c", "f", 200), {}, DISPROVEN_STATUS),
        ((0, "c", "f", float("nan")), {}, INCONCLUSIVE_STATUS),
        # Invalid tolerance is rejected before the temperature branch.
        ((0, "c", "f", 32), {"tolerance": -1}, "ERROR"),
        ((0, "c", "f", 32), {"tolerance": float("nan")}, "ERROR"),
    ],
)
def test_temperature_conversion_is_decimal_and_validated(args, kwargs, expected):
    assert VerificationEngine().verify_unit_conversion(*args, **kwargs)["status"] == expected



def test_scalar_status_is_undecided_when_the_difference_is_not_numeric():
    from qwed_new.core.verifier import _scalar_status

    x = sympy.Symbol("x")
    # An unevaluated integral whose value cannot be computed numerically.
    unevaluable = sympy.Integral(sympy.Function("g")(x), (x, 0, 1))
    assert _scalar_status(unevaluable, sympy.Float(1.0)) == INCONCLUSIVE_STATUS



@pytest.mark.parametrize(
    "actual, claimed, expected",
    [
        # Subtracting a Float used to round the exact side first, so these
        # one-ulp-off claims came out as a difference of 0 and VERIFIED.
        (sympy.Integer(2**53 + 1), sympy.Float(9007199254740992.0), INCONCLUSIVE_STATUS),
        (sympy.Integer(10**17 + 8), sympy.Float(1e17), INCONCLUSIVE_STATUS),
        (sympy.Integer(2**53 + 3), sympy.Float(9007199254740992.0), DISPROVEN_STATUS),
        (sympy.Integer(2**53), sympy.Float(9007199254740992.0), "VERIFIED"),
        # Past the precision cap: a gross mismatch is still decided...
        (sympy.Integer(2 * 10**200), sympy.Float(1e200), DISPROVEN_STATUS),
        # ...but agreement is never decided there.
        (sympy.Integer(10**200), sympy.Float(1e200), INCONCLUSIVE_STATUS),
    ],
)
def test_scalar_status_subtracts_exactly_and_decides_gross_mismatches(actual, claimed, expected):
    from qwed_new.core.verifier import _scalar_status

    assert _scalar_status(actual, claimed) == expected


def test_definite_integral_gross_mismatch_at_huge_magnitude_is_disproven():
    result = VerificationEngine().verify_integral("2", "x", "1e200", lower_bound="0", upper_bound="10**200")
    assert result["status"] == DISPROVEN_STATUS



def test_scalar_status_is_undecided_when_the_difference_cannot_be_evaluated(monkeypatch):
    from qwed_new.core import verifier

    real_parts = verifier._decimal_parts

    def parts_without_difference(entry, precision=30):
        # Magnitudes evaluate (precision 30); the full-precision difference does not.
        return real_parts(entry, precision) if precision == 30 else None

    monkeypatch.setattr(verifier, "_decimal_parts", parts_without_difference)
    status = verifier._scalar_status(sympy.Integer(10**20), sympy.Float(1e20))
    assert status == INCONCLUSIVE_STATUS



def test_value_that_underflows_to_zero_never_accepts_a_zero_claim():
    from qwed_new.core.verifier import _exact_vs_float_claim

    # 1e-400 is non-zero but its nearest double is 0.0.
    assert _exact_vs_float_claim(sympy.Rational(1, 10**400), sympy.Float(0.0)) is None
    assert _exact_vs_float_claim(sympy.Integer(0), sympy.Float(0.0)) is True


def test_coarse_comparison_is_undecided_without_numeric_sides():
    from decimal import Decimal

    from qwed_new.core.verifier import _coarse_scalar_status

    x = sympy.Symbol("x")
    window = Decimal(1)
    assert _coarse_scalar_status(x, sympy.Float(1.0), window) == INCONCLUSIVE_STATUS
    assert _coarse_scalar_status(sympy.Integer(1), x, window) == INCONCLUSIVE_STATUS



def test_float_spacing_follows_the_least_precise_float():
    from decimal import Decimal

    from qwed_new.core.verifier import _float_spacing

    assert _float_spacing(sympy.Integer(1)) == Decimal(2) ** -52
    assert _float_spacing(sympy.Float(1.0)) == Decimal(2) ** -52
    # A 16-17 digit string may be a double's repr: double spacing.
    assert _float_spacing(sympy.Float("1000000000000.0001")) == Decimal(2) ** -52
    # Clearly more precise than any double: narrower.
    assert _float_spacing(sympy.Float("1.5", 30)) < Decimal(2) ** -52
