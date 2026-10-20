"""#469: AgentStateGuard raised RecursionError on deeply nested JSON.

``json.loads`` and ``_canonicalize`` recurse once per nesting level, and only
``ValueError`` was caught, so a payload such as ``'[' * 200000`` escaped the
public API as an exception instead of coming back BLOCKED. The guard now
rejects payloads nested deeper than ``MAX_PARSE_DEPTH`` before parsing them,
and maps any RecursionError or MemoryError from parsing or canonicalisation
to QWED-AGENT-STATE-102.
"""

import json

import pytest

from qwed_new.guards.agent_state_guard import AgentStateGuard
from tests.test_agent_state_guard import (
    STRICT_AGENT_STATE_SCHEMA,
    _build_commit_guard,
    _build_guard,
    _build_transition_guard,
)

VALID_STATE = json.dumps(
    {"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": [{"id": "t1", "done": False}]}
)
PARSE_ERROR = "QWED-AGENT-STATE-102"


def _deep(depth, opener="[", closer="]"):
    return opener * depth + closer * depth


DEEP_PAYLOADS = {
    "array-10000": _deep(10_000),
    "object-10000": '{"a":' * 10_000 + "1" + "}" * 10_000,
    "unclosed-200000": "[" * 200_000,
    "mixed-10000": '[{"a":' * 5_000 + "1" + "}]" * 5_000,
}


@pytest.mark.parametrize("payload", DEEP_PAYLOADS.values(), ids=DEEP_PAYLOADS.keys())
def test_deeply_nested_payload_is_blocked_not_raised(payload):
    result = _build_guard().verify_state_payload(payload)

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == PARSE_ERROR
    assert f"exceeds {AgentStateGuard.MAX_PARSE_DEPTH} levels" in result["message"]


@pytest.mark.parametrize("deep_side", ["current", "proposed"])
def test_deep_payload_in_a_transition_is_blocked(deep_side):
    deep = DEEP_PAYLOADS["object-10000"]
    current, proposed = (deep, VALID_STATE) if deep_side == "current" else (VALID_STATE, deep)

    result = _build_transition_guard().verify_state_transition(current, proposed)

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"


def test_deep_payload_is_never_committed(tmp_path):
    target = tmp_path / "state.json"

    result = _build_commit_guard(tmp_path).verify_transition_and_commit_state(
        VALID_STATE, DEEP_PAYLOADS["array-10000"], str(target)
    )

    assert result["verified"] is False
    assert not target.exists()


def test_nesting_at_the_parse_limit_reaches_the_validator():
    # Within MAX_PARSE_DEPTH the payload is parsed, and the validator, not the
    # parse check, reports what is wrong with it.
    payload = _deep(AgentStateGuard.MAX_PARSE_DEPTH)

    result = _build_guard().verify_state_payload(payload)

    assert result["status"] == "BLOCKED"
    assert result["error_code"] != PARSE_ERROR


def test_one_level_past_the_parse_limit_is_a_parse_error():
    result = _build_guard().verify_state_payload(_deep(AgentStateGuard.MAX_PARSE_DEPTH + 1))

    assert result["error_code"] == PARSE_ERROR


def test_the_parse_limit_stays_above_the_validation_limit():
    assert AgentStateGuard.MAX_PARSE_DEPTH > AgentStateGuard.MAX_VALIDATION_DEPTH


def test_brackets_inside_strings_do_not_count():
    state = {"agent_id": "[" * 5_000 + "{" * 5_000, "status": "pending", "step_count": 1, "tasks": []}

    result = _build_guard().verify_state_payload(json.dumps(state))

    assert result["verified"] is True
    assert result["normalized_state"]["agent_id"] == state["agent_id"]


def test_escaped_quotes_do_not_end_a_string():
    # The \" keeps the scanner inside the string, so its brackets stay text.
    agent_id = 'x\\"' + "[" * 400
    payload = (
        '{"agent_id": "' + agent_id + '", "status": "pending", "step_count": 1, "tasks": []}'
    )

    result = _build_guard().verify_state_payload(payload)

    assert result["verified"] is True


@pytest.mark.parametrize("number", ["1e9999999999999999999999", "-1e-9999999999999999999", "1.5E+99999999999999999999"])
def test_a_number_outside_decimal_range_is_blocked_not_raised(number):
    # parse_float=Decimal raises decimal.InvalidOperation, an ArithmeticError,
    # for an exponent beyond Decimal's limits.
    payload = '{"agent_id": "a1", "status": "pending", "step_count": ' + number + ', "tasks": []}'

    result = _build_guard().verify_state_payload(payload)

    assert result["status"] == "BLOCKED"
    assert result["error_code"] == PARSE_ERROR


def test_a_long_string_full_of_brackets_is_still_verified():
    state = {"agent_id": "[" * 200_000 + "\\" + '"' + "{" * 200_000, "status": "pending", "step_count": 1, "tasks": []}

    result = _build_guard().verify_state_payload(json.dumps(state))

    assert result["verified"] is True


def test_brackets_after_an_unterminated_string_count_as_structure():
    # The parser rejects this anyway; the check must not be fooled into
    # treating the brackets as string content.
    assert AgentStateGuard._nesting_exceeds('"' + "[" * 300, 256) is True


@pytest.mark.parametrize("error", [RecursionError("deep"), MemoryError("big")])
def test_a_parser_failure_past_the_check_is_still_blocked(monkeypatch, error):
    guard = _build_guard()
    monkeypatch.setattr(AgentStateGuard, "_nesting_exceeds", staticmethod(lambda text, limit: False))

    def explode(text):
        raise error

    monkeypatch.setattr(guard, "_load_strict_json", explode)

    result = guard.verify_state_payload(VALID_STATE)

    assert result["status"] == "BLOCKED"
    assert result["error_code"] == PARSE_ERROR


@pytest.mark.parametrize("error", [RecursionError("deep"), MemoryError("big")])
def test_a_canonicalisation_failure_is_blocked(monkeypatch, error):
    guard = _build_guard()

    def explode(value):
        raise error

    monkeypatch.setattr(AgentStateGuard, "_canonicalize", classmethod(lambda cls, value: explode(value)))

    result = guard.verify_state_payload(VALID_STATE)

    assert result["status"] == "BLOCKED"
    assert result["error_code"] == PARSE_ERROR


def test_the_real_parser_overflow_is_caught_without_the_check(monkeypatch):
    # Belt and braces: with the pre-parse check disabled, json.loads itself
    # overflows the stack, and the guard still returns BLOCKED.
    monkeypatch.setattr(AgentStateGuard, "_nesting_exceeds", staticmethod(lambda text, limit: False))

    result = AgentStateGuard(STRICT_AGENT_STATE_SCHEMA).verify_state_payload("[" * 200_000)

    assert result["status"] == "BLOCKED"
    assert result["error_code"] == PARSE_ERROR
