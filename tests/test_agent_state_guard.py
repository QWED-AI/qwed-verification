from decimal import Decimal

import pytest

from qwed_new.guards.agent_state_guard import AgentStateGuard


STRICT_AGENT_STATE_SCHEMA = {
    "type": "object",
    "properties": {
        "agent_id": {"type": "string"},
        "status": {"type": "string", "enum": ["pending", "running", "completed"]},
        "step_count": {"type": "integer"},
        "tasks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "done": {"type": "boolean"},
                },
                "required": ["id", "done"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["agent_id", "status", "step_count", "tasks"],
    "additionalProperties": False,
}


def _build_guard() -> AgentStateGuard:
    return AgentStateGuard(STRICT_AGENT_STATE_SCHEMA)


def test_rejects_empty_payload():
    guard = _build_guard()

    result = guard.verify_state_payload("")

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "QWED-AGENT-STATE-101"


@pytest.mark.parametrize("payload", [None, 123, []])
def test_rejects_non_string_input(payload):
    guard = _build_guard()

    result = guard.verify_state_payload(payload)

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "QWED-AGENT-STATE-101"


def test_rejects_invalid_json():
    guard = _build_guard()

    result = guard.verify_state_payload('{"agent_id": "a1",')

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-102"


def test_rejects_duplicate_keys():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "agent_id": "shadow",
          "status": "pending",
          "step_count": 1,
          "tasks": []
        }
        """
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-102"
    assert "Duplicate key" in result["message"]


def test_rejects_non_standard_json_constants():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "step_count": NaN,
          "tasks": []
        }
        """
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-102"
    assert "Non-standard JSON constant" in result["message"]


def test_rejects_missing_required_keys():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "tasks": []
        }
        """
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-103"
    assert "missing required keys" in result["message"]


def test_rejects_unexpected_keys():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "step_count": 1,
          "tasks": [],
          "claimed_done": true
        }
        """
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-103"
    assert "unexpected keys" in result["message"]


def test_rejects_wrong_types_in_nested_payload():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "step_count": 1,
          "tasks": [
            {"id": "task-1", "done": "yes"}
          ]
        }
        """
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-103"
    assert "$.tasks[0].done must be a boolean" in result["message"]


def test_accepts_structurally_valid_payload_and_normalizes_order():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "tasks": [
            {"done": false, "id": "task-1"}
          ],
          "step_count": 1,
          "status": "pending",
          "agent_id": "a1"
        }
        """
    )

    assert result["verified"] is True
    assert result["status"] == "VERIFIED"
    assert result["normalized_state"] == {
        "agent_id": "a1",
        "status": "pending",
        "step_count": 1,
        "tasks": [{"done": False, "id": "task-1"}],
    }


def test_invalid_schema_definition_fails_fast():
    with pytest.raises(ValueError, match="must declare a supported type"):
        AgentStateGuard({"properties": {}})


def test_rejects_non_dict_schema_definition():
    with pytest.raises(ValueError, match="must be a dictionary"):
        AgentStateGuard(["not", "a", "dict"])


def test_rejects_empty_enum_definition():
    with pytest.raises(ValueError, match="must be a non-empty list"):
        AgentStateGuard(
            {
                "type": "object",
                "properties": {"status": {"type": "string", "enum": []}},
                "required": [],
                "additionalProperties": False,
            }
        )


def test_rejects_object_schema_without_properties():
    with pytest.raises(ValueError, match="must define properties"):
        AgentStateGuard({"type": "object"})


def test_rejects_required_key_list_with_non_strings():
    with pytest.raises(ValueError, match="must be a list of strings"):
        AgentStateGuard(
            {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
                "required": ["agent_id", 1],
                "additionalProperties": False,
            }
        )


def test_rejects_required_keys_missing_from_properties():
    with pytest.raises(ValueError, match="missing from properties"):
        AgentStateGuard(
            {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
                "required": ["agent_id", "status"],
                "additionalProperties": False,
            }
        )


def test_rejects_non_boolean_additional_properties():
    with pytest.raises(ValueError, match="must be a boolean value"):
        AgentStateGuard(
            {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
                "required": [],
                "additionalProperties": "nope",
            }
        )


def test_rejects_array_schema_without_items():
    with pytest.raises(ValueError, match="must define an items schema"):
        AgentStateGuard(
            {
                "type": "object",
                "properties": {"tasks": {"type": "array"}},
                "required": [],
                "additionalProperties": False,
            }
        )


def test_rejects_string_enum_mismatch():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "status": "failed",
          "step_count": 1,
          "tasks": []
        }
        """
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-103"
    assert "$.status must be one of" in result["message"]


def test_rejects_object_type_mismatch():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        [
          {
            "agent_id": "a1",
            "status": "pending",
            "step_count": 1,
            "tasks": []
          }
        ]
        """
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-103"
    assert "$ must be an object" in result["message"]


def test_rejects_array_type_mismatch():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "step_count": 1,
          "tasks": {}
        }
        """
    )

    assert result["verified"] is False
    assert "$.tasks must be an array" in result["message"]


def test_rejects_integer_bool_type_confusion():
    guard = _build_guard()

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "step_count": true,
          "tasks": []
        }
        """
    )

    assert result["verified"] is False
    assert "$.step_count must be an integer" in result["message"]


def test_validate_number_value_rejects_non_finite_numbers():
    guard = AgentStateGuard(
        {
            "type": "object",
            "properties": {"score": {"type": "number"}},
            "required": ["score"],
            "additionalProperties": False,
        }
    )

    error = guard._validate_value({"type": "number"}, float("nan"), "$.score")

    assert "must use deterministic JSON numbers" in error


def test_validate_null_value_rejects_non_null():
    guard = AgentStateGuard(
        {
            "type": "object",
            "properties": {"marker": {"type": "null"}},
            "required": ["marker"],
            "additionalProperties": False,
        }
    )

    error = guard._validate_value({"type": "null"}, "not-null", "$.marker")

    assert error == "$.marker must be null, got str."


def test_rejects_empty_property_name_in_schema():
    with pytest.raises(ValueError, match="must be non-empty strings"):
        AgentStateGuard(
            {
                "type": "object",
                "properties": {"": {"type": "string"}},
                "required": [],
                "additionalProperties": False,
            }
        )


def test_allows_optional_keys_to_be_absent():
    guard = AgentStateGuard(
        {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "notes": {"type": "string"},
            },
            "required": ["agent_id"],
            "additionalProperties": False,
        }
    )

    result = guard.verify_state_payload('{"agent_id": "a1"}')

    assert result["verified"] is True
    assert result["normalized_state"] == {"agent_id": "a1"}


def test_allows_extra_keys_when_schema_explicitly_permits_them():
    guard = AgentStateGuard(
        {
            "type": "object",
            "properties": {"agent_id": {"type": "string"}},
            "required": ["agent_id"],
            "additionalProperties": True,
        }
    )

    result = guard.verify_state_payload(
        """
        {
          "agent_id": "a1",
          "runtime_note": "allowed"
        }
        """
    )

    assert result["verified"] is True
    assert result["normalized_state"] == {
        "agent_id": "a1",
        "runtime_note": "allowed",
    }


def test_validate_value_rejects_unsupported_schema_type():
    guard = _build_guard()

    error = guard._validate_value({"type": "mystery"}, "x", "$.mystery")

    assert error == "$.mystery uses unsupported schema type 'mystery'."


def test_validate_string_value_rejects_non_string():
    guard = _build_guard()

    error = guard._validate_value({"type": "string"}, 7, "$.agent_id")

    assert error == "$.agent_id must be a string, got int."


def test_validate_number_value_rejects_non_numeric_type():
    guard = _build_guard()

    error = guard._validate_value({"type": "number"}, "7", "$.score")

    assert error == "$.score must be a number, got str."


def test_validate_number_value_accepts_finite_number():
    guard = _build_guard()

    error = guard._validate_value({"type": "number"}, Decimal("7.5"), "$.score")

    assert error is None


def test_validate_number_value_accepts_integer():
    guard = _build_guard()

    error = guard._validate_value({"type": "number"}, 7, "$.score")

    assert error is None


def test_validate_number_value_rejects_bool():
    guard = _build_guard()

    error = guard._validate_value({"type": "number"}, True, "$.score")

    assert error == "$.score must be a number, got bool."


def test_validate_null_value_accepts_null():
    guard = _build_guard()

    error = guard._validate_value({"type": "null"}, None, "$.marker")

    assert error is None


def test_parses_decimal_json_numbers_as_decimal():
    guard = AgentStateGuard(
        {
            "type": "object",
            "properties": {"score": {"type": "number"}},
            "required": ["score"],
            "additionalProperties": False,
        }
    )

    result = guard.verify_state_payload('{"score": 7.5}')

    assert result["verified"] is True
    assert result["normalized_state"]["score"] == Decimal("7.5")


def test_rejects_excessive_validation_depth():
    schema = {"type": "string"}
    value = "leaf"

    for _ in range(AgentStateGuard.MAX_VALIDATION_DEPTH):
        schema = {"type": "array", "items": schema}
        value = [value]

    guard = AgentStateGuard(schema)

    # Directly validate the nested structure to exercise the depth guard.
    error = guard._validate_value(schema, value, "$")

    assert error is not None
    assert error.startswith("$[0]")
    assert error.endswith(
        f"exceeds maximum validation depth ({AgentStateGuard.MAX_VALIDATION_DEPTH})."
    )
