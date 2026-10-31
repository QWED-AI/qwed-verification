"""#522: /verify/math reads diff() and refuses d/dx notation.

``diff(x**2, x) == 2*x`` came back BLOCKED as an internal error, because the
parser did not know ``diff``, and ``d/dx(x^2) = 2x`` came back VERIFIED as
proven false, because ``d`` and ``dx`` were read as symbols. The parser now
evaluates ``diff`` and ``Derivative`` within one order budget per parse,
refuses Leibniz notation, and /verify/math reports anything the parser
refuses as ``math.parse_error``, not as an internal error. The domain check
reads each evaluated derivative too, since it can be singular where the text
it differentiates is not.
"""

from unittest.mock import MagicMock, patch

import pytest
import sympy
from fastapi.testclient import TestClient

from qwed_new.api.main import app, get_current_tenant, get_session
from qwed_new.core import verifier
from qwed_new.core.batch import BatchItem, BatchVerificationService, VerificationType
from qwed_new.core.math_identity import math_identity_result
from qwed_new.core.safe_parser import (
    DERIVATIVE_NOTATION_MESSAGE,
    DerivativeNotationError,
    SafeParserError,
    safe_parse_expr,
)
from qwed_new.core.verifier import identity_domains_match

x, y = sympy.symbols("x y")


def _mock_session():
    # A named factory, not MagicMock itself: FastAPI reads a dependency's
    # signature, and MagicMock(*args, **kwargs) would become query params.
    return MagicMock()


@pytest.fixture
def client(isolated_audit_chain):
    tenant = MagicMock(organization_id=522, api_key=MagicMock(name="key"), user_id=1)
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(("text", "expected"), [
    ("diff(x**2, x)", 2 * x),
    ("diff(x^2, x)", 2 * x),
    ("Derivative(x**2, x)", 2 * x),
    ("diff(x**3, x, 2)", 6 * x),
    ("diff(sin(x), x)", sympy.cos(x)),
    ("diff(x*y, x)", y),
    ("diff(x**2)", 2 * x),
    ("2diff(x**2, x)", 4 * x),
    ("diff(x**4, x, 3)", 24 * x),
    ("diff(diff(x**4, x), x, 2)", 24 * x),
    ("diff(x**2, x, 0)", x**2),
    ("diff(x**2, x) y", 2 * x * y),
    ("sqrt(diff(x**2, x))", sympy.sqrt(2 * x)),
    # Implicit multiplication: a reciprocal or a root expands nothing (Gitar
    # on PR #558).
    ("2x/diff(x**2, x)", 1),
    ("sqrt(diff(x**2, x)) 2", 2 * sympy.sqrt(2 * x)),
    # ^ binds as SymPy reads it, not with Python's XOR precedence (Sentry on
    # PR #558): the derivative is not inside a power here.
    ("diff(x^3, x) - 3*x^2", 0),
])
def test_diff_and_derivative_are_evaluated(text, expected):
    assert safe_parse_expr(text) == expected


@pytest.mark.parametrize("text", [
    # The gates read diff() as symbolic, but it evaluates first:
    # 2**(diff(10000*x, x)**9) would be 2**(10000**9) (Greptile on PR #558).
    "2**(diff(10000*x, x)**9)",
    "diff(9**9999*x, x)**9999",
    "2^(diff(10000x, x))^9",
    "factorial(diff(10**6*x, x))",
    "diff(x**2, x)**2",
    # An order SymPy cannot read unevaluated must not skip the gates (Sentry
    # on PR #558).
    "2^(diff(10000x, x, 1+0))^9",
    "diff(x**2, x)^(1/2) y",
    # ^ on the Python path.
    "2^(diff(10000*x, x))^9",
])
def test_a_derivative_cannot_feed_an_eager_expansion(text):
    with pytest.raises(SafeParserError, match="A derivative cannot appear in a power"):
        safe_parse_expr(text)


@pytest.mark.parametrize("text", [
    "diff(x**5, x, 4)",
    "diff(diff(x**5, x, 2), x, 2)",
    "diff(x**2, x) + diff(x**3, x, 3)",
    "diff(x**2, x, 10**9)",
    "Derivative(x**2, x, y, y, y)",
])
def test_the_derivative_order_is_bounded_across_the_expression(text):
    with pytest.raises(SafeParserError, match="Derivative order exceeds"):
        safe_parse_expr(text)


@pytest.mark.parametrize("text", [
    "d/dx(x^2)",
    "dy/dx",
    "d^2y/dx^2",
    "d2y/dx2",
    "2d/dx(x^2)",
    "d / d x",
    "x + d/dt(t**2)",
    # Gitar, CodeAnt, Greptile and CodeRabbit on PR #558.
    "d(x^2)/dx",
    "d(sin(x))/dx",
    "d/dtheta(theta**2)",
    "dy/dtheta",
    "x/(dx)",
    "d/d(x)(x^2)",
    "dy/(2*dx)",
    "dy/2dx",
    # A variable the parser does not know (CodeRabbit on PR #558).
    "d(foo**2)/dfoo",
    "1/delta + d(foo**2)/dfoo",
    "x/(2*dfoo)",
    # Whatever stands before the differential (CodeRabbit on PR #558).
    "d(foo**2)/(-dfoo)",
    "x/(y*dfoo)",
    # A subscripted variable (Gitar on PR #558).
    "d(x_1^2)/dx_1",
    "d/dx_1*x_1**2",
])
def test_leibniz_notation_is_refused(text):
    with pytest.raises(DerivativeNotationError):
        safe_parse_expr(text)


@pytest.mark.parametrize("text", [
    "d/2", "x*d/(2*d)", "d + x", "delta*x", "x/delta", "x/diff(x**2, x)", "x/d*y", "x/(d)",
    # SymPy keeps a name with "_" whole (CodeRabbit on PR #558).
    "distance_m", "x/distance_m", "dx_1",
])
def test_the_symbol_d_still_parses(text):
    safe_parse_expr(text)


def test_a_caller_symbol_that_starts_with_d_is_not_a_differential():
    assert safe_parse_expr("x/dt", extra_symbols={"dt": sympy.Symbol("dt")}) == x / sympy.Symbol("dt")


@pytest.mark.parametrize(("expression", "status", "is_valid", "admission", "message"), [
    ("diff(x**2, x) == 2*x", "VERIFIED", True, "ADMIT", "Identity is true"),
    ("diff(x**2, x) = 2*x", "VERIFIED", True, "ADMIT", "Identity is true"),
    ("Derivative(x^2, x) = 2x", "VERIFIED", True, "ADMIT", "Identity is true"),
    ("diff(x**2, x) = 3*x", "VERIFIED", False, "BLOCKED", "Identity is false"),
    ("diff(x**2, x) == 3*x", "VERIFIED", False, "BLOCKED", "Identity is false"),
])
def test_a_derivative_claim_is_decided(client, expression, status, is_valid, admission, message):
    result = client.post("/verify/math", json={"expression": expression}).json()

    assert (result["status"], result["is_valid"], result["admission"]) == (status, is_valid, admission)
    assert result["agent_message"] == message


@pytest.mark.parametrize(("expression", "message"), [
    ("d/dx(x^2) = 2x", DERIVATIVE_NOTATION_MESSAGE),
    ("d/dx(x^2)", DERIVATIVE_NOTATION_MESSAGE),
    ("dy/dx = 2x", DERIVATIVE_NOTATION_MESSAGE),
    ("d(x^2)/dx = 2x", DERIVATIVE_NOTATION_MESSAGE),
    ("dy/dtheta == dy/dtheta", DERIVATIVE_NOTATION_MESSAGE),
    ("diff(x**5, x, 4) = 120*x", "Expression could not be parsed"),
    ("x <= 2", "Expression could not be parsed"),
    ("a = b = c", "Expression could not be parsed"),
])
def test_input_the_parser_refuses_is_a_parse_error(client, expression, message):
    result = client.post("/verify/math", json={"expression": expression}).json()

    assert (result["status"], result["is_valid"], result["admission"]) == ("BLOCKED", False, "BLOCKED")
    assert result["constraint_id"] == "math.parse_error"
    assert result["agent_message"] == message
    # The parser's own text, which can carry SymPy's, is not echoed back.
    assert "error" not in result


@pytest.mark.parametrize("expression", [
    # The derivative is singular at x = 0 where the text it differentiates
    # is not: diff(sqrt(x), x) is 1/(2*sqrt(x)).
    "diff(sqrt(x), x)*2*sqrt(x) = 1",
    "diff(sqrt(x), x) 2sqrt(x) = 1",
    "diff(1/x, x)*x**2 = -1",
    # The text is singular where the derivative is not: x**2/x is x.
    "diff(x**2/x, x) = 1",
    # log is defined for x > 0 only, its derivative 1/x for x other than 0.
    "diff(x*log(x), x) = log(x) + 1",
])
def test_a_derivative_identity_that_holds_only_off_a_point_is_unverifiable(expression):
    dr = math_identity_result(expression)

    assert dr.status.value == "UNVERIFIABLE"
    assert dr.developer_fields["constraint_id"] == "math.domain_restricted_identity"


@pytest.mark.parametrize("expression", [
    "diff(sqrt(x), x) = 1/(2*sqrt(x))",
    "diff(1/x, x) = -1/x**2",
    "diff(diff(x**4, x), x) = 12*x**2",
    # A numeric multiplier excludes no point: 2*sqrt(x) and sqrt(x) are zero
    # at the same x (Greptile on PR #558).
    "2*diff(sqrt(x), x) = 1/sqrt(x)",
    "2/(2*sqrt(x)) = 1/sqrt(x)",
])
def test_a_derivative_identity_on_the_same_domain_is_verified(expression):
    dr = math_identity_result(expression)

    assert (dr.status.value, dr.developer_fields["is_valid"]) == ("VERIFIED", True)


def test_a_derivative_the_domain_check_cannot_evaluate_has_no_known_domain():
    # The AST reads "diff(x, x, 4)", but evaluating it exceeds the order budget.
    assert identity_domains_match("diff(x, x, 4)", "0") is False


def test_a_derivative_the_domain_check_cannot_reread_has_no_known_domain(monkeypatch):
    # SymPy's output for diff(x**2, x) is "2*x"; if re-reading it hits a
    # parser limit, the domain is unknown, not an error (Sentry on PR #558).
    original = verifier._singular_factors

    def refuse_the_derivative(expression):
        if expression == "2*x":
            raise SafeParserError("limit")
        return original(expression)

    monkeypatch.setattr(verifier, "_singular_factors", refuse_the_derivative)

    assert identity_domains_match("diff(x**2, x)", "2*x + 0") is False


def test_a_parse_error_does_not_echo_what_sympy_raised(client):
    with patch("qwed_new.core.safe_parser.parse_expr", side_effect=ValueError("SENSITIVE SYMPY TEXT")):
        result = client.post("/verify/math", json={"expression": "1+1"}).json()

    assert (result["constraint_id"], result["agent_message"]) == ("math.parse_error", "Expression could not be parsed")
    assert "SENSITIVE SYMPY TEXT" not in str(result)


def test_any_other_failure_is_still_an_internal_error(client):
    with patch("qwed_new.api.main.math_identity_result", side_effect=RuntimeError("boom")):
        result = client.post("/verify/math", json={"expression": "x = x"}).json()

    assert result["status"] == "BLOCKED"
    assert result["constraint_id"] == "api.math.execution_error"
    assert result["agent_message"] == "Internal verification error"


def test_a_batch_item_reads_diff_as_the_route_does(client):
    item = BatchItem(id="522", query="diff(x**2, x) == 2*x", verification_type=VerificationType.MATH)
    batch = BatchVerificationService()._verify_batch_math(item)
    route = client.post("/verify/math", json={"expression": "diff(x**2, x) == 2*x"}).json()

    assert (batch["status"], batch["is_valid"], batch["admission"]) == ("VERIFIED", True, "ADMIT")
    assert (batch["status"], batch["is_valid"]) == (route["status"], route["is_valid"])


@pytest.mark.parametrize(("expression", "message"), [
    ("d/dx(x^2) = 2x", DERIVATIVE_NOTATION_MESSAGE),
    ("d/dx(x^2)", DERIVATIVE_NOTATION_MESSAGE),
    ("x <= 2", "Expression could not be parsed"),
])
def test_a_batch_item_the_parser_refuses_is_a_parse_error_as_on_the_route(client, expression, message):
    # It was a failed item carrying the parser's text (CodeRabbit on PR #558).
    item = BatchItem(id="522", query=expression, verification_type=VerificationType.MATH)
    batch = BatchVerificationService()._verify_batch_math(item)
    route = client.post("/verify/math", json={"expression": expression}).json()

    assert (batch["status"], batch["is_valid"], batch["admission"]) == ("BLOCKED", False, "BLOCKED")
    assert (batch["constraint_id"], batch["agent_message"]) == ("math.parse_error", message)
    assert (route["constraint_id"], route["agent_message"]) == ("math.parse_error", message)
    assert "error" not in batch
