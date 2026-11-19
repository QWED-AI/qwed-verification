"""/verify/math does not admit identities that hold only after rounding or folding (GHSA-q7m5).

Three causes made a false identity VERIFIED · ADMIT:

- The parser applies NFKC before anything else, and NFKC turns ``²`` into
  ``2``, ``₃`` into ``3``, ``Ⅰ`` into ``I`` and ``㏒`` into ``log``:
  ``2² = 22`` and ``(x+1)² = 2x + 2`` were admitted. A character whose NFKC
  form is other text is now refused, unless it is only a width, font or
  size variant (fullwidth and mathematical digits are still digits) or a
  no-break space.
- Implicit multiplication reads ``1 000`` as ``1*000``: two numbers with
  only space between them are now refused.
- SymPy rounds a Float while it parses, so ``1 + 1.0e-17`` is 1.0 and the
  difference from 1 is an exact zero. A zero difference where a side writes
  a decimal is now checked again with the decimals read exactly: it stands
  only if they agree, and the claim is UNVERIFIABLE when they cannot be read
  exactly. The same re-check runs for derivatives, indefinite integrals and
  limits. Nothing main left undecided is admitted now.
"""

from decimal import Decimal

import pytest

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.math_identity import math_identity_result
from qwed_new.core.safe_parser import SafeParserError, safe_parse_expr, validate_variable_name
from qwed_new.core.verifier import DISPROVEN_STATUS, VerificationEngine

# Names this fix adds are imported inside the tests that use them, so each
# test fails on its own on main instead of the whole module.
INEXACT_DECIMAL_IDENTITY = "math.inexact_decimal"


def _exact(expression):
    from qwed_new.core.safe_parser import safe_parse_exact_decimals

    return safe_parse_exact_decimals(expression)


def _verdict(expression):
    result = math_identity_result(expression)
    fields = result.developer_fields
    return result.status.value, fields.get("is_valid"), admission_decision(result).value, fields.get("constraint_id")


FOLDING = [
    "2² = 22",            # superscript two
    "2² = 4",
    "(x+1)² = 2x + 2",
    "3² + 4² = 5²",
    "2₃ = 23",            # subscript three
    "xⁿ = xn",            # superscript n
    "2⁻¹ = 1",       # superscript minus, superscript one
    "xⁱ = xi",            # superscript i
    "aₐ = aa",            # subscript a
    "①② = 12",       # circled one, circled two
    "⑴ = (1)",            # parenthesized one
    "⒈ = 1.",             # digit one full stop
    "½ = 1/2",            # vulgar fraction one half
    "x⁺¹ = x+1",     # superscript plus
    "x₍1₎ = x(1)",   # subscript parentheses
    "Ⅰ*Ⅰ = -1",      # Roman numeral one: would read I, the imaginary unit
    "ⅹ - x = 0",          # small Roman numeral ten: would read x
    "⒳ = x",              # parenthesized small x: would read (x)
    "㏒(x) = log(x)",      # square log: would read log
    "1\u2009000 = 1000",       # thin space: would read 1 000
]


@pytest.mark.parametrize("expression", FOLDING)
def test_a_character_that_folds_into_other_text_is_refused(expression):
    with pytest.raises(SafeParserError, match="would be read as"):
        math_identity_result(expression)


@pytest.mark.parametrize("name", ["x²", "x₁", "n①", "ⅹ"])
def test_a_variable_name_that_folds_is_refused(name):
    with pytest.raises(SafeParserError, match="would be read as"):
        validate_variable_name(name)


@pytest.mark.parametrize("expression", ["1 000 = 0", "2 2 = 4", "1\u00a0000 = 0", "2\t2 = 4", "1 .5 = 0.5"])
def test_two_numbers_with_only_space_between_them_are_refused(expression):
    with pytest.raises(SafeParserError, match="only space between them"):
        math_identity_result(expression)


@pytest.mark.parametrize("expression, verdict", [
    ("１２ = 12", ("VERIFIED", True, "ADMIT")),      # fullwidth digits
    ("\U0001d7cf\U0001d7d0 = 12", ("VERIFIED", True, "ADMIT")),  # mathematical bold digits
    ("１２ = 13", ("VERIFIED", False, "BLOCKED")),
    ("x\u00a0+ 1 = 1 + x", ("VERIFIED", True, "ADMIT")),  # a no-break space is a space
])
def test_width_font_and_space_variants_keep_their_meaning(expression, verdict):
    assert _verdict(expression)[:3] == verdict


@pytest.mark.parametrize("expression", ["1 + 1.0e-17 = 1", "1.0e20 + 1 = 1.0e20", "0.1 + 1e-20 = 0.1"])
def test_an_identity_that_holds_only_after_rounding_is_disproven(expression):
    assert _verdict(expression)[:3] == ("VERIFIED", False, "BLOCKED")
    assert math_identity_result(expression).developer_fields["decimals"] == "exact"


@pytest.mark.parametrize("expression", [
    "1 + 1.0e-17 - 1 = 0",
    "1.0e20 + 1 - 1.0e20 = 0",
    "x - (1 + 1.0e-17)*x = 0",
    "(1 + 1.0e-17)*x - x = 0",
    "Rational(1 + 1.0e-17) = 1",
    "Rational(1, 1 + 1.0e-17) = 1",
    "Integer(2 - 1.0e-17) = 2",
    "log(1 + 1.0e-17) = 0",
    "sin(pi*(1 + 1.0e-17)) = 0",
    "cos(pi*(0.5 + 1.0e-17)) = 0",
    "tan(pi*(1 + 1.0e-17)) = 0",
])
def test_a_rounding_that_evaluation_hides_is_still_rechecked(expression):
    # Evaluation turns the rounded Float into an exact number, so neither
    # side holds a Float any more: the decimal in the text is what counts.
    assert _verdict(expression)[:3] == ("VERIFIED", False, "BLOCKED")
    assert math_identity_result(expression).developer_fields["decimals"] == "exact"


@pytest.mark.parametrize("expression", ["Float(1000, 1) + 1 = 1000", "1.5e-9999 * 2 = 3e-9999"])
def test_a_rounded_zero_that_cannot_be_read_exactly_is_unverifiable(expression):
    assert _verdict(expression) == ("UNVERIFIABLE", False, "BLOCKED", INEXACT_DECIMAL_IDENTITY)


@pytest.mark.timeout(60)
def test_a_long_decimal_to_a_large_power_is_not_expanded():
    # Read exactly, the literal is a fraction with a 3,902-digit numerator,
    # raised to the power 10,000. The parser refuses the numerator, so the
    # claim is left undecided and nothing is expanded.
    literal = "1." + "0" * 3900 + "1"
    expression = f"{literal}**10000 = {literal}**10000"
    assert _verdict(expression) == ("UNVERIFIABLE", False, "BLOCKED", INEXACT_DECIMAL_IDENTITY)


@pytest.mark.parametrize("expression", [
    "0.5 + 0.5 = 1", "2.5*2 = 5", "0.15*200 = 30", "x*0.5 + x*0.5 = x", "1e3 = 1000", "0.25*4 = 1",
    "1.5x + 0.5x = 2x", "2.5^2 = 6.25", "1_000.5 = 1000.5",
])
def test_an_exact_decimal_identity_is_still_verified(expression):
    assert _verdict(expression)[:3] == ("VERIFIED", True, "ADMIT")


@pytest.mark.parametrize("expression", ["0.1 + 0.2 = 0.3", "sqrt(2.0)**2 = 2"])
def test_what_main_left_undecided_is_still_undecided(expression):
    # The exact reading only re-checks a zero; it admits nothing new.
    assert _verdict(expression)[:3] == ("UNVERIFIABLE", False, "BLOCKED")


@pytest.mark.parametrize("expression", ["2 + 2 = 5", "3**2 + 4**2 = 5**2", "x**2 = x*x", "(x+1)**2 = x**2 + 2*x + 1"])
def test_identities_without_decimals_are_unchanged(expression):
    status, is_valid, _, _ = _verdict(expression)
    assert status == "VERIFIED"
    assert "decimals" not in math_identity_result(expression).developer_fields
    assert is_valid is (expression != "2 + 2 = 5")


def test_the_exact_reading():
    assert _exact("1 + 1.0e-17") == safe_parse_expr("1 + 10**(-17)")
    assert _exact("Float(2, 3)") is None
    assert _exact("1e" + "9" * 7) is None
    assert _exact("1e4000") is None  # 1 digit + 4,000: over the bound
    assert _exact("1e400") is None   # the parser refuses a 401-digit integer
    assert _exact("1e300") == safe_parse_expr("10**300")
    assert _exact(None) is None


def test_an_exact_reading_the_cost_checks_refuse_is_not_attempted():
    # 1.5**20000 as a Float is cheap; read exactly it is a huge rational.
    assert _exact("1.5**20000") is None


def test_verify_identity_rechecks_a_rounded_zero():
    engine = VerificationEngine()
    assert engine.verify_identity("1 + 1.0e-17", "1")["status"] == "NOT_EQUIVALENT"
    assert engine.verify_identity("1 + 1.0e-17 - 1", "0")["status"] == "NOT_EQUIVALENT"
    assert engine.verify_identity("Float(1000, 1) + 1", "1000")["status"] == "INCONCLUSIVE"
    assert engine.verify_identity("0.5 + 0.5", "1")["status"] == "VERIFIED"


@pytest.mark.parametrize("expression, expected, status", [
    ("1.0e20*x + x", "1.0e20", DISPROVEN_STATUS),
    ("(1 + 1.0e-17)*x", "1", DISPROVEN_STATUS),
    ("x**2", "Rational(2 + 1.0e-17)*x", DISPROVEN_STATUS),
    ("0.5*x**2", "x", "VERIFIED"),
    ("2.5*x**2", "5*x", "VERIFIED"),
    ("x**2", "2*x + 1.0e-17*x - 1.0e-17*x", "VERIFIED"),
    ("x**2", "2*x", "VERIFIED"),
])
def test_a_derivative_is_decided_with_exact_decimals(expression, expected, status):
    assert VerificationEngine().verify_derivative(expression, "x", expected)["status"] == status


@pytest.mark.parametrize("expression, expected, status", [
    ("x", "(0.5 + 1.0e-17)*x**2", DISPROVEN_STATUS),
    ("x", "0.5*x**2", "VERIFIED"),
    ("2*x", "x**2 + 1 + 1.0e-17*x - 1.0e-17*x", "VERIFIED"),
    ("2*x", "x**2", "VERIFIED"),
])
def test_an_indefinite_integral_is_decided_with_exact_decimals(expression, expected, status):
    assert VerificationEngine().verify_integral(expression, "x", expected)["status"] == status


@pytest.mark.parametrize("expression, point, expected, status", [
    ("1.0e20 + x", "1", "1.0e20", DISPROVEN_STATUS),
    ("x", "1 + 1.0e-17 - 1", "0", DISPROVEN_STATUS),
    ("(1 + 1.0e-17)*x", "1", "1", DISPROVEN_STATUS),
    ("(1 + 1.0e-17)*x/x", "oo", "1", DISPROVEN_STATUS),
    ("0.5*x", "2", "1", "VERIFIED"),
    ("x", "0.5", "0.5", "VERIFIED"),
    ("1/x + 1.0e-17 - 1.0e-17", "oo", "0", "VERIFIED"),
    ("x + 1", "0", "1", "VERIFIED"),
])
def test_a_limit_is_decided_with_exact_decimals(expression, point, expected, status):
    assert VerificationEngine().verify_limit(expression, "x", point, expected)["status"] == status


# --- Floats the decimal text did not show, numbers the parser splits and
# letters in another font (second review of GHSA-q7m5) ---------------------

FULLWIDTH_FLOAT = "".join(chr(0xFF21 + ord(c) - ord("A")) if c.isupper() else chr(0xFF41 + ord(c) - ord("a")) for c in "Float")

HIDDEN_FLOATS = [
    "sin(pi*(Float(1) + 1/10**17)) = 0",
    "log(Float(1) + 1/10**17) = 0",
    "Integer(Float(1000, 1) + 1) = 1000",
    "Rational(Float(1) + 1/10**17) = 1",
]


@pytest.mark.parametrize("expression", HIDDEN_FLOATS)
def test_a_float_call_is_rechecked_and_left_undecided(expression):
    # Float(...) rounds as a decimal does, and its precision is what it
    # says, so it cannot be read exactly: the zero is not admitted.
    assert _verdict(expression) == ("UNVERIFIABLE", False, "BLOCKED", INEXACT_DECIMAL_IDENTITY)
    assert math_identity_result(expression).developer_fields["decimals"] == "unreadable"


SPLIT_NUMBERS = [
    "Integer(2 - 0x1.1e-16) = 2",      # 0x1 then .1e-16
    "sin(pi*(1 + 0x1.1e-16)) = 0",
    "Rational(1, 1 + 0x1.1e-16) = 1",
    "1 + 1.0e-17 = 1 + 1__0.0e-18",    # Python 3.10 and 3.11: 1 then __0 then .0e-18
    "1.0e20 + 1 = 1.0e20 + 1__0.0e-1",
    "2*05 = 0",                         # Python 3.10 and 3.11: 0 then 5
    "010 = 0",
    "0.5 + 05 = 0.5",
    "2.5.5 = 1.25",                     # 2.5 then .5
]


@pytest.mark.parametrize("expression", SPLIT_NUMBERS)
def test_a_number_the_parser_splits_is_refused(expression):
    # Python 3.12 and later refuse most of these in the tokenizer itself.
    with pytest.raises(SafeParserError):
        math_identity_result(expression)


LETTER_FOLDS = [
    chr(0x2111) + "(I) = -1",                       # black-letter capital I: would read I
    chr(0x1D408) + "**2 = -1",                      # mathematical bold capital I
    chr(0x2110) + "*" + chr(0x2110) + " = -1",      # script capital I
    chr(0xFF29) + "**2 = -1",                       # fullwidth capital I
    "Integer(" + FULLWIDTH_FLOAT + "(1000, 1) + 1) = 1000",
]


@pytest.mark.parametrize("expression", LETTER_FOLDS)
def test_a_letter_in_another_width_or_font_is_refused(expression):
    with pytest.raises(SafeParserError, match="disallowed character that would be read as"):
        math_identity_result(expression)


def test_the_exact_reading_follows_the_parsers_tokens():
    from qwed_new.core.safe_parser import has_decimal_literal

    assert has_decimal_literal("Float(1) + 1")
    assert has_decimal_literal("x + 0.5")
    assert not has_decimal_literal("0x1e5 + 2")  # a hexadecimal e is a digit
    assert _exact("1.5x") == safe_parse_expr("3*x/2")
    assert _exact("Float(1) + 1") is None


def test_the_sides_recorded_are_the_exact_ones_that_decided():
    fields = math_identity_result("1 + 1.0e-17 = 1").developer_fields
    assert fields["decimals"] == "exact"
    assert fields["left_side"] == "100000000000000001/100000000000000000"
    assert fields["simplified_difference"] == "1/100000000000000000"


@pytest.mark.parametrize("args, status", [
    (("1.0e20 + 1", Decimal("1e20")), DISPROVEN_STATUS),
    (("1.0e20 + 1", Decimal("1e20"), 0), DISPROVEN_STATUS),
    (("1 + 1.0e-17", Decimal(1), 0), DISPROVEN_STATUS),
    (("Integer(Float(1000, 1) + 1)", 1000), "INCONCLUSIVE"),
    (("0.5 + 0.25", Decimal("0.75")), "VERIFIED"),
    (("1.5 * 2", 3), "VERIFIED"),
])
def test_verify_math_computes_from_the_decimals_read_exactly(args, status):
    # VerificationEngine.verify_math serves /verify/natural_language and
    # the consensus SymPy engine.
    result = VerificationEngine().verify_math(*args)
    assert result["status"] == status
    assert result["is_correct"] is (status == "VERIFIED")


@pytest.mark.parametrize("operation, args", [
    ("identity", ("Integer(Float(1000, 1) + 1)", "1000")),
    ("identity", ("log(Float(1) + 1/10**17)", "0")),
    ("derivative", ("sin(pi*(Float(1) + 1/10**17))*x", "x", "0")),
    ("integral", ("Integer(Float(1000, 1) + 1)", "x", "1000*x")),
    ("limit", ("Integer(Float(1000, 1) + 1) + x", "x", "0", "1000")),
])
def test_the_engine_does_not_verify_a_float_call(operation, args):
    result = getattr(VerificationEngine(), f"verify_{operation}")(*args)
    assert result["status"] != "VERIFIED"


ROUTE_CASES = [
    "2*05 = 0",
    chr(0x2111) + "(I) = -1",
    "Integer(Float(1000, 1) + 1) = 1000",
    "sin(pi*(Float(1) + 1/10**17)) = 0",
    "1 + 1.0e-17 = 1 + 1__0.0e-18",
]


@pytest.mark.parametrize("expression", ROUTE_CASES)
def test_the_request_and_batch_jobs_do_not_admit_them(expression):
    from qwed_new.core import math_worker

    assert admission_decision(math_worker.verify_math_request(expression, {})).value == "BLOCKED"
    assert admission_decision(math_worker.verify_batch_math(expression)).value == "BLOCKED"


def test_the_worker_pool_does_not_admit_them():
    from qwed_new.core import math_worker

    pool = math_worker.MathWorkerPool(workers=1, max_waiting=0)
    try:
        for expression in ROUTE_CASES:
            assert admission_decision(pool.run("request", (expression, {}), time_limit=120)).value == "BLOCKED"
            assert admission_decision(pool.run("batch", (expression,), time_limit=120)).value == "BLOCKED"
    finally:
        pool.close()


@pytest.fixture
def client():
    from unittest.mock import MagicMock, patch

    from fastapi.testclient import TestClient

    from qwed_new.api.main import app, get_current_tenant, get_session

    tenant = MagicMock(organization_id=7, api_key=MagicMock(name="key"), user_id=1)
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_session] = lambda: MagicMock()
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("expression", ROUTE_CASES)
def test_the_route_does_not_admit_them(client, expression, isolated_audit_chain):
    data = client.post("/verify/math", json={"expression": expression}).json()
    assert data["admission"] == "BLOCKED"
