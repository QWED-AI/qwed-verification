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

STRICT_AGENT_TRANSITION_RULES = {
    "immutable_paths": ["$.agent_id"],
    "monotonic_integer_paths": ["$.step_count"],
    "ordered_enum_paths": {
        "$.status": ["pending", "running", "completed"],
    },
    "keyed_object_array_paths": {
        "$.tasks": {
            "key": "id",
            "monotonic_boolean_fields": ["done"],
            "allow_new_items": True,
        }
    },
}


def _build_guard() -> AgentStateGuard:
    return AgentStateGuard(STRICT_AGENT_STATE_SCHEMA)


def _build_transition_guard() -> AgentStateGuard:
    return AgentStateGuard(
        STRICT_AGENT_STATE_SCHEMA,
        transition_rules=STRICT_AGENT_TRANSITION_RULES,
    )


def _build_commit_guard(tmp_path) -> AgentStateGuard:
    return AgentStateGuard(
        STRICT_AGENT_STATE_SCHEMA,
        transition_rules=STRICT_AGENT_TRANSITION_RULES,
        allowed_commit_roots=[str(tmp_path)],
    )


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


def test_transition_requires_configured_rules():
    guard = _build_guard()

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-104"


def test_placeholder_transition_config_does_not_count_as_enabled():
    guard = AgentStateGuard(
        STRICT_AGENT_STATE_SCHEMA,
        transition_rules={
            "immutable_paths": [],
            "monotonic_integer_paths": [],
            "ordered_enum_paths": {},
            "keyed_object_array_paths": {},
        },
    )

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-104"


def test_freezes_schema_and_transition_rules_against_caller_mutation():
    schema = {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string"},
            "status": {"type": "string", "enum": ["pending", "running", "completed"]},
        },
        "required": ["agent_id", "status"],
        "additionalProperties": False,
    }
    transition_rules = {
        "immutable_paths": ["$.agent_id"],
        "ordered_enum_paths": {"$.status": ["pending", "running", "completed"]},
    }

    guard = AgentStateGuard(schema, transition_rules=transition_rules)

    schema["properties"]["agent_id"]["type"] = "integer"
    transition_rules["immutable_paths"].append("$.status")
    transition_rules["ordered_enum_paths"]["$.status"].append("failed")

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "pending"}',
        '{"agent_id": "a1", "status": "running"}',
    )

    assert result["verified"] is True
    assert guard.required_schema["properties"]["agent_id"]["type"] == "string"
    assert guard.transition_rules["immutable_paths"] == ("$.agent_id",)


def test_accepts_valid_monotonic_state_transition():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "step_count": 1,
          "tasks": [{"id": "task-1", "done": false}]
        }
        """,
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 2,
          "tasks": [
            {"id": "task-1", "done": true},
            {"id": "task-2", "done": false}
          ]
        }
        """,
    )

    assert result["verified"] is True
    assert result["status"] == "VERIFIED"
    assert result["normalized_previous_state"]["status"] == "pending"
    assert result["normalized_state"]["status"] == "running"


def test_rejects_commit_without_allowed_roots(tmp_path):
    guard = _build_transition_guard()
    target_path = tmp_path / "state.json"

    result = guard.verify_transition_and_commit_state(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
        str(target_path),
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-107"
    assert not target_path.exists()


def test_rejects_relative_commit_path(tmp_path):
    guard = _build_commit_guard(tmp_path)

    result = guard.verify_transition_and_commit_state(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
        "state.json",
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-107"


def test_rejects_commit_path_outside_allowed_roots(tmp_path):
    guard = _build_commit_guard(tmp_path)
    outside_target = tmp_path.parent / "outside.json"

    result = guard.verify_transition_and_commit_state(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
        str(outside_target),
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-107"
    assert not outside_target.exists()


def test_rejects_commit_path_with_non_json_extension(tmp_path):
    guard = _build_commit_guard(tmp_path)
    target_path = tmp_path / "state.txt"

    result = guard.verify_transition_and_commit_state(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
        str(target_path),
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-107"
    assert not target_path.exists()


def test_rejects_commit_when_target_parent_does_not_exist(tmp_path):
    guard = _build_commit_guard(tmp_path)
    target_path = tmp_path / "missing" / "state.json"

    result = guard.verify_transition_and_commit_state(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
        str(target_path),
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-107"
    assert not target_path.exists()


def test_rejects_commit_without_side_effects_when_transition_is_blocked(tmp_path):
    guard = _build_commit_guard(tmp_path)
    target_path = tmp_path / "state.json"

    result = guard.verify_transition_and_commit_state(
        '{"agent_id": "a1", "status": "running", "step_count": 3, "tasks": []}',
        '{"agent_id": "a1", "status": "pending", "step_count": 2, "tasks": []}',
        str(target_path),
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-106"
    assert not target_path.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_commits_verified_transition_atomically(tmp_path):
    guard = _build_commit_guard(tmp_path)
    target_path = tmp_path / "state.json"

    result = guard.verify_transition_and_commit_state(
        """
        {
          "agent_id": "a1",
          "status": "pending",
          "step_count": 1,
          "tasks": [{"id": "task-1", "done": false}]
        }
        """,
        """
        {
          "tasks": [
            {"done": true, "id": "task-1"},
            {"done": false, "id": "task-2"}
          ],
          "step_count": 2,
          "status": "running",
          "agent_id": "a1"
        }
        """,
        str(target_path),
    )

    assert result["verified"] is True
    assert result["status"] == "VERIFIED"
    assert result["committed_path"] == str(target_path)
    assert result["committed_bytes"] > 0
    assert target_path.read_text(encoding="utf-8") == (
        '{"agent_id":"a1","status":"running","step_count":2,'
        '"tasks":[{"done":true,"id":"task-1"},{"done":false,"id":"task-2"}]}'
    )
    assert list(tmp_path.glob("*.tmp")) == []


def test_cleans_up_temp_file_when_atomic_replace_fails(tmp_path, monkeypatch):
    guard = _build_commit_guard(tmp_path)
    target_path = tmp_path / "state.json"

    def failing_replace(source, destination):
        raise OSError("replace failed")

    monkeypatch.setattr("qwed_new.guards.agent_state_guard.os.replace", failing_replace)

    result = guard.verify_transition_and_commit_state(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
        str(target_path),
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-108"
    assert not target_path.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_rejects_invalid_current_state_during_transition():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "pending"}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-105"
    assert "current agent state failed structural verification" in result["message"]


def test_rejects_immutable_field_transition_change():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a2", "status": "running", "step_count": 2, "tasks": []}',
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-106"
    assert "$.agent_id is immutable" in result["message"]


def test_rejects_monotonic_counter_regression():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "running", "step_count": 3, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
    )

    assert result["verified"] is False
    assert "$.step_count regressed" in result["message"]


def test_rejects_ordered_status_regression():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "completed", "step_count": 3, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 4, "tasks": []}',
    )

    assert result["verified"] is False
    assert "$.status regressed" in result["message"]


def test_rejects_task_reopen_transition():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 2,
          "tasks": [{"id": "task-1", "done": true}]
        }
        """,
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 3,
          "tasks": [{"id": "task-1", "done": false}]
        }
        """,
    )

    assert result["verified"] is False
    assert "regressed from True to False" in result["message"]


def test_rejects_task_deletion_or_reordering():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 2,
          "tasks": [
            {"id": "task-1", "done": false},
            {"id": "task-2", "done": false}
          ]
        }
        """,
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 3,
          "tasks": [
            {"id": "task-2", "done": false},
            {"id": "task-1", "done": true}
          ]
        }
        """,
    )

    assert result["verified"] is False
    assert "must preserve existing item order and prevent deletion" in result["message"]


def test_returns_structural_failure_for_invalid_proposed_state_in_transition():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running"}',
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-103"


def test_rejects_transition_rules_that_are_not_dicts():
    with pytest.raises(ValueError, match="Transition rules must be a dictionary"):
        AgentStateGuard(STRICT_AGENT_STATE_SCHEMA, transition_rules=["nope"])


def test_rejects_transition_rules_with_unknown_keys():
    with pytest.raises(ValueError, match="unsupported keys"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"unknown_rule": []},
        )


def test_rejects_invalid_path_list_rule():
    with pytest.raises(ValueError, match="must be a list of JSON-style path strings"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"immutable_paths": "$.agent_id"},
        )


def test_rejects_invalid_json_path_rule():
    with pytest.raises(ValueError, match="paths must use dot-style JSON paths"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"immutable_paths": ["agent_id"]},
        )


def test_rejects_invalid_ordered_enum_rule():
    with pytest.raises(ValueError, match="must define at least two ordered values"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"ordered_enum_paths": {"$.status": ["pending"]}},
        )


def test_blocks_transition_when_ordered_enum_rule_omits_valid_state_value():
    guard = AgentStateGuard(
        STRICT_AGENT_STATE_SCHEMA,
        transition_rules={
            "ordered_enum_paths": {"$.status": ["pending", "running"]},
        },
    )

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "completed", "step_count": 2, "tasks": []}',
        '{"agent_id": "a1", "status": "completed", "step_count": 3, "tasks": []}',
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-106"
    assert "transition-rule evaluation failed deterministically" in result["message"]


def test_blocks_transition_when_rule_path_is_missing_from_state():
    guard = AgentStateGuard(
        STRICT_AGENT_STATE_SCHEMA,
        transition_rules={
            "immutable_paths": ["$.notes"],
        },
    )

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "pending", "step_count": 1, "tasks": []}',
        '{"agent_id": "a1", "status": "running", "step_count": 2, "tasks": []}',
    )

    assert result["verified"] is False
    assert result["error_code"] == "QWED-AGENT-STATE-106"
    assert "Configured path '$.notes' was not found in state." in result["message"]


def test_rejects_non_dict_ordered_enum_rules():
    with pytest.raises(ValueError, match="ordered_enum_paths must be a dictionary"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"ordered_enum_paths": ["$.status"]},
        )


def test_rejects_invalid_keyed_object_array_rule():
    with pytest.raises(ValueError, match="must define a non-empty key field"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"keyed_object_array_paths": {"$.tasks": {}}},
        )


def test_rejects_unknown_keyed_object_array_rule_keys():
    with pytest.raises(ValueError, match="contains unsupported keys"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={
                "keyed_object_array_paths": {
                    "$.tasks": {"key": "id", "allow_new_item": False}
                }
            },
        )


def test_rejects_non_dict_keyed_object_array_rules():
    with pytest.raises(ValueError, match="keyed_object_array_paths must be a dictionary"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"keyed_object_array_paths": ["$.tasks"]},
        )


def test_rejects_non_dict_single_keyed_object_array_rule():
    with pytest.raises(ValueError, match="must be a dictionary"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={"keyed_object_array_paths": {"$.tasks": "bad"}},
        )


def test_rejects_invalid_monotonic_boolean_fields_rule():
    with pytest.raises(ValueError, match="must be a list of field names"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={
                "keyed_object_array_paths": {
                    "$.tasks": {"key": "id", "monotonic_boolean_fields": "done"}
                }
            },
        )


def test_rejects_non_boolean_allow_new_items_rule():
    with pytest.raises(ValueError, match="allow_new_items must be a boolean"):
        AgentStateGuard(
            STRICT_AGENT_STATE_SCHEMA,
            transition_rules={
                "keyed_object_array_paths": {
                    "$.tasks": {"key": "id", "allow_new_items": "yes"}
                }
            },
        )


def test_rejects_keyed_object_array_duplicate_ids():
    guard = _build_transition_guard()

    result = guard.verify_state_transition(
        '{"agent_id": "a1", "status": "running", "step_count": 1, "tasks": []}',
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 2,
          "tasks": [
            {"id": "task-1", "done": false},
            {"id": "task-1", "done": false}
          ]
        }
        """,
    )

    assert result["verified"] is False
    assert "contains duplicate 'id' values" in result["message"]


def test_rejects_keyed_object_array_missing_key_field():
    guard = _build_transition_guard()

    error = guard._validate_keyed_object_array_transition(
        path="$.tasks",
        current_items=[],
        proposed_items=[{"done": False}],
        rule={"key": "id", "monotonic_boolean_fields": ["done"], "allow_new_items": True},
    )

    assert error == "$.tasks[0] is missing key field 'id'."


def test_rejects_keyed_object_array_non_object_items():
    guard = _build_transition_guard()

    current_state = {"tasks": []}
    proposed_state = {"tasks": ["bad-item"]}
    rule = {"key": "id", "monotonic_boolean_fields": ["done"], "allow_new_items": True}

    error = guard._validate_keyed_object_array_transition(
        path="$.tasks",
        current_items=current_state["tasks"],
        proposed_items=proposed_state["tasks"],
        rule=rule,
    )

    assert error == "$.tasks[0] must be an object."


def test_rejects_keyed_object_array_non_array_values():
    guard = _build_transition_guard()

    error = guard._validate_keyed_object_array_transition(
        path="$.tasks",
        current_items={},
        proposed_items=[],
        rule={"key": "id", "monotonic_boolean_fields": ["done"], "allow_new_items": True},
    )

    assert error == "$.tasks must resolve to arrays in both current and proposed state."


def test_rejects_keyed_object_array_invalid_current_items():
    guard = _build_transition_guard()

    error = guard._validate_keyed_object_array_transition(
        path="$.tasks",
        current_items=[{"done": False}],
        proposed_items=[],
        rule={"key": "id", "monotonic_boolean_fields": ["done"], "allow_new_items": True},
    )

    assert error == "$.tasks[0] is missing key field 'id'."


def test_rejects_new_items_when_append_is_disabled():
    guard = AgentStateGuard(
        STRICT_AGENT_STATE_SCHEMA,
        transition_rules={
            **STRICT_AGENT_TRANSITION_RULES,
            "keyed_object_array_paths": {
                "$.tasks": {
                    "key": "id",
                    "monotonic_boolean_fields": ["done"],
                    "allow_new_items": False,
                }
            },
        },
    )

    result = guard.verify_state_transition(
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 1,
          "tasks": [{"id": "task-1", "done": false}]
        }
        """,
        """
        {
          "agent_id": "a1",
          "status": "running",
          "step_count": 2,
          "tasks": [
            {"id": "task-1", "done": true},
            {"id": "task-2", "done": false}
          ]
        }
        """,
    )

    assert result["verified"] is False
    assert "does not allow appending new items" in result["message"]


def test_rejects_changes_to_existing_task_fields_outside_monotonic_bool():
    guard = _build_transition_guard()

    error = guard._validate_keyed_object_item_transition(
        path="$.tasks",
        key_field="id",
        item_key="task-1",
        current_item={"id": "task-1", "done": False, "label": "old"},
        proposed_item={"id": "task-1", "done": True, "label": "new"},
        monotonic_boolean_fields=["done"],
    )

    assert error == "$.tasks[id='task-1'].label changed from 'old' to 'new'."


def test_get_path_value_rejects_missing_paths():
    with pytest.raises(ValueError, match="was not found in state"):
        AgentStateGuard._get_path_value({"agent_id": "a1"}, "$.status")


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
