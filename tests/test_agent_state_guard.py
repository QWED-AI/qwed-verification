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
