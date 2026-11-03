"""#570: AgentStateGuard's verdict on a JSON number depended on the decimal module.

A CPython built without libmpdec runs the pure-Python decimal module; from 3.15
the build no longer falls back to the bundled copy, and setup-python's 3.15.1
for Ubuntu is built that way. The pure-Python module accepts an exponent the C
module refuses, so a number field holding 1e9999999999999999999999 was VERIFIED
there and BLOCKED (QWED-AGENT-STATE-102) with the C module. It also refuses a
number with more digits than int() reads, which the C module accepts. The guard
now checks both limits on the text itself, so either module gives one verdict.
"""

import decimal
import itertools
import json
import subprocess
import sys

import pytest

from qwed_new.guards.agent_state_guard import AgentStateGuard

PARSE_ERROR = "QWED-AGENT-STATE-102"
NUMBER_SCHEMA = {
    "type": "object",
    "properties": {"x": {"type": "number"}},
    "required": ["x"],
    "additionalProperties": False,
}
# sys.get_int_max_str_digits arrived in 3.10.7, and 0 means no limit.
DIGIT_LIMIT = sys.get_int_max_str_digits() if hasattr(sys, "get_int_max_str_digits") else 0


def _payload(number):
    return '{"x": ' + number + "}"


def _guard():
    return AgentStateGuard(NUMBER_SCHEMA)


OUT_OF_RANGE = [
    "1e9999999999999999999999",
    "-1e-9999999999999999999",
    f"1e{decimal.MAX_EMAX + 1}",
    f"0e{decimal.MAX_EMAX + 1}",
    f"1e{decimal.MIN_ETINY - 1}",
    f"0.5e{decimal.MIN_ETINY}",
]
IN_RANGE = [
    f"1e{decimal.MAX_EMAX}",
    f"9.99e{decimal.MAX_EMAX - 2}",
    f"1e{decimal.MIN_ETINY}",
    f"1e{decimal.MIN_EMIN}",
    "-0.0",
    "3.14",
]
# int() counts digits, leading zeros included, but not a sign. With no limit
# these are empty, and the cases that need one are skipped.
TOO_MANY_DIGITS = {
    "coefficient": "1." + "7" * DIGIT_LIMIT,
    "zero-fraction": "0." + "0" * DIGIT_LIMIT,
    "exponent": "1e" + "0" * DIGIT_LIMIT + "1",
    "negative-exponent": "1e-" + "0" * DIGIT_LIMIT + "1",
} if DIGIT_LIMIT else {}
AT_THE_DIGIT_LIMIT = {
    "coefficient": "-1." + "7" * (DIGIT_LIMIT - 1),
    "exponent": "1e" + "0" * (DIGIT_LIMIT - 1) + "1",
    "negative-exponent": "1e-" + "0" * (DIGIT_LIMIT - 1) + "1",
    "positive-exponent": "1e+" + "0" * (DIGIT_LIMIT - 1) + "1",
} if DIGIT_LIMIT else {}


@pytest.mark.parametrize("number", OUT_OF_RANGE)
def test_an_exponent_outside_decimal_range_is_a_parse_error(number):
    result = _guard().verify_state_payload(_payload(number))

    assert result["status"] == "BLOCKED"
    assert result["error_code"] == PARSE_ERROR
    assert "outside the decimal range" in result["message"]


@pytest.mark.parametrize("number", IN_RANGE)
def test_an_exponent_inside_decimal_range_is_verified(number):
    result = _guard().verify_state_payload(_payload(number))

    assert result["status"] == "VERIFIED"
    assert result["normalized_state"]["x"] == decimal.Decimal(number)


@pytest.mark.parametrize("number", TOO_MANY_DIGITS.values(), ids=TOO_MANY_DIGITS.keys())
def test_more_digits_than_int_reads_is_a_parse_error(number):
    result = _guard().verify_state_payload(_payload(number))

    assert result["status"] == "BLOCKED"
    assert result["error_code"] == PARSE_ERROR
    assert f"more than {DIGIT_LIMIT} digits" in result["message"]


@pytest.mark.parametrize("number", AT_THE_DIGIT_LIMIT.values(), ids=AT_THE_DIGIT_LIMIT.keys())
def test_digits_up_to_the_int_limit_are_verified(number):
    assert _guard().verify_state_payload(_payload(number))["status"] == "VERIFIED"


def test_with_the_int_digit_limit_off_a_long_number_is_verified():
    if not hasattr(sys, "set_int_max_str_digits"):
        pytest.skip("int() has no digit limit before 3.10.7")
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        long_coefficient = _guard().verify_state_payload(_payload("1." + "7" * 5000))
        long_exponent = _guard().verify_state_payload(_payload("1e-" + "0" * 5000 + "1"))
    finally:
        sys.set_int_max_str_digits(previous)

    assert long_coefficient["status"] == "VERIFIED"
    assert long_exponent["status"] == "VERIFIED"


def test_text_that_is_not_a_json_number_is_refused():
    # json never hands parse_float such text; refusing it keeps the parser
    # inside verify_state_payload's except clause if it ever did.
    with pytest.raises(ValueError):
        AgentStateGuard._parse_decimal("1.5x")


_VERDICTS = """
import json, sys
if sys.argv[1] == "pure-python":
    sys.modules["_decimal"] = None
import decimal
if sys.argv[1] == "pure-python" and "_pydecimal" not in sys.modules:
    sys.exit("the pure-Python decimal module was not loaded")
from qwed_new.guards.agent_state_guard import AgentStateGuard
schema, numbers = json.load(sys.stdin)
guard = AgentStateGuard(schema)
verdicts = []
for number in numbers:
    result = guard.verify_state_payload('{"x": ' + number + '}')
    verdicts.append([result["status"], result.get("error_code"), result.get("message"),
                     str(result.get("normalized_state", {}).get("x"))])
print(json.dumps(verdicts))
"""


def _verdicts(module):
    numbers = OUT_OF_RANGE + IN_RANGE + [*TOO_MANY_DIGITS.values(), *AT_THE_DIGIT_LIMIT.values()]
    run = subprocess.run(
        [sys.executable, "-c", _VERDICTS, module],
        input=json.dumps([NUMBER_SCHEMA, numbers]),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def test_the_c_and_pure_python_decimal_modules_give_the_same_verdicts():
    # Without libmpdec both runs use the pure-Python module, and the cases
    # above still pin each verdict.
    assert _verdicts("default") == _verdicts("pure-python")


def test_parse_decimal_refuses_only_what_the_c_module_or_the_digit_limit_refuses():
    pytest.importorskip("_decimal")
    coefficients = ["0", "1", "12", "100", "0.5", "1.5", "0.0001", "123.456", "1" * 30, "0.000"]
    anchors = [decimal.MAX_EMAX, decimal.MIN_EMIN, decimal.MIN_ETINY, 0]
    exponents = sorted({anchor + offset for anchor in anchors for offset in range(-35, 36)})

    for coefficient, exponent, sign in itertools.product(coefficients, exponents, ["", "-"]):
        text = f"{sign}{coefficient}e{exponent}"
        try:
            decimal.Decimal(text)
            c_module_accepts = True
        except decimal.InvalidOperation:
            c_module_accepts = False
        try:
            AgentStateGuard._parse_decimal(text)
            accepted = True
        except (ValueError, ArithmeticError):
            accepted = False
        assert accepted == c_module_accepts, text
