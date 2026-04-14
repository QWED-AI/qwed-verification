"""
AgentStateGuard

Phase 1 focuses on structural verification, Phase 2 adds bounded semantic
transition validation, and Phase 3 adds governed atomic commit:
- strict JSON parsing
- strict schema validation
- deterministic transition checks
- fail-closed decision objects

No side effects occur before verification completes.
"""

from __future__ import annotations

import json
import os
import tempfile
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Iterable


class AgentStateGuard:
    """
    Deterministically verifies proposed agent state payloads before any commit.

    Phase 1 validates structure, Phase 2 adds bounded semantic transition
    proof, and Phase 3 adds governed atomic commit.
    """

    _VALID_SCHEMA_TYPES = frozenset(
        {"object", "array", "string", "integer", "number", "boolean", "null"}
    )
    _VALID_TRANSITION_RULE_KEYS = frozenset(
        {
            "immutable_paths",
            "monotonic_integer_paths",
            "ordered_enum_paths",
            "keyed_object_array_paths",
        }
    )
    MAX_VALIDATION_DEPTH = 64

    def __init__(
        self,
        required_schema: Dict[str, Any],
        transition_rules: Dict[str, Any] | None = None,
        allowed_commit_roots: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        validated_schema = self._validate_schema_definition(required_schema, "$")
        validated_transition_rules = self._validate_transition_rules_definition(
            transition_rules or {}
        )
        self.required_schema = self._freeze_config(validated_schema)
        self.transition_rules = self._freeze_config(validated_transition_rules)
        self._transition_rules_configured = self._has_effective_transition_rules(
            self.transition_rules
        )
        self.allowed_commit_roots = self._validate_allowed_commit_roots(
            allowed_commit_roots or []
        )

    def verify_state_payload(self, proposed_state_json: str) -> Dict[str, Any]:
        """
        Verify a proposed state payload against the configured strict schema.

        Returns a strict verified/non-verified decision object.
        """
        if not isinstance(proposed_state_json, str) or not proposed_state_json.strip():
            return self._blocked(
                error_code="QWED-AGENT-STATE-101",
                message="Blocked: proposed agent state must be a non-empty JSON string.",
            )

        try:
            state_data = self._load_strict_json(proposed_state_json)
        except ValueError as exc:
            return self._blocked(
                error_code="QWED-AGENT-STATE-102",
                message=f"Blocked: invalid or non-deterministic JSON state payload. {exc}",
            )

        validation_error = self._validate_value(
            schema=self.required_schema,
            value=state_data,
            path="$",
        )
        if validation_error is not None:
            return self._blocked(
                error_code="QWED-AGENT-STATE-103",
                message=f"Blocked: {validation_error}",
            )

        return {
            "verified": True,
            "status": "VERIFIED",
            "proof": "State payload matched the configured strict schema.",
            "normalized_state": self._canonicalize(state_data),
        }

    def verify_state_transition(
        self,
        current_state_json: str,
        proposed_state_json: str,
    ) -> Dict[str, Any]:
        """
        Verify an old_state -> new_state transition with structural and
        configured semantic checks. No side effects occur here.
        """
        if not self._transition_rules_configured:
            return self._blocked(
                error_code="QWED-AGENT-STATE-104",
                message=(
                    "Blocked: semantic transition verification requires configured "
                    "transition rules."
                ),
            )

        current_result = self.verify_state_payload(current_state_json)
        if not current_result["verified"]:
            return self._blocked(
                error_code="QWED-AGENT-STATE-105",
                message=(
                    "Blocked: current agent state failed structural verification. "
                    f"{current_result['message']}"
                ),
            )

        proposed_result = self.verify_state_payload(proposed_state_json)
        if not proposed_result["verified"]:
            return proposed_result

        try:
            transition_error = self._validate_transition_rules(
                current_state=current_result["normalized_state"],
                proposed_state=proposed_result["normalized_state"],
            )
        except Exception as exc:
            return self._blocked(
                error_code="QWED-AGENT-STATE-106",
                message=(
                    "Blocked: transition-rule evaluation failed deterministically. "
                    f"{type(exc).__name__}: {exc}"
                ),
            )
        if transition_error is not None:
            return self._blocked(
                error_code="QWED-AGENT-STATE-106",
                message=f"Blocked: {transition_error}",
            )

        return {
            "verified": True,
            "status": "VERIFIED",
            "proof": (
                "State transition satisfied the configured structural and "
                "semantic rules."
            ),
            "normalized_previous_state": current_result["normalized_state"],
            "normalized_state": proposed_result["normalized_state"],
        }

    def verify_transition_and_commit_state(
        self,
        current_state_json: str,
        proposed_state_json: str,
        target_path: str,
    ) -> Dict[str, Any]:
        """
        Verify a transition and atomically commit the normalized state only after
        verification succeeds.
        """
        commit_target = self._validate_commit_target(target_path)
        if isinstance(commit_target, dict):
            return commit_target

        verification_result = self.verify_state_transition(
            current_state_json=current_state_json,
            proposed_state_json=proposed_state_json,
        )
        if not verification_result["verified"]:
            return verification_result

        try:
            committed_bytes = self._atomic_write_json(
                verification_result["normalized_state"],
                commit_target,
            )
        except OSError as exc:
            return self._blocked(
                error_code="QWED-AGENT-STATE-108",
                message=(
                    "Blocked: atomic state commit failed deterministically. "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        return {
            "verified": True,
            "status": "VERIFIED",
            "proof": (
                "State transition satisfied structural and semantic rules and was "
                "atomically committed."
            ),
            "normalized_previous_state": verification_result["normalized_previous_state"],
            "normalized_state": verification_result["normalized_state"],
            "committed_path": str(commit_target),
            "committed_bytes": committed_bytes,
        }

    def _load_strict_json(self, proposed_state_json: str) -> Any:
        return json.loads(
            proposed_state_json,
            object_pairs_hook=self._reject_duplicate_keys,
            parse_constant=self._reject_non_standard_constant,
            # Preserve deterministic numeric semantics for Phase 1 validation.
            parse_float=Decimal,
        )

    @classmethod
    def _freeze_config(cls, value: Any) -> Any:
        if isinstance(value, dict):
            frozen = {key: cls._freeze_config(item) for key, item in value.items()}
            return MappingProxyType(frozen)
        if isinstance(value, list):
            return tuple(cls._freeze_config(item) for item in value)
        return value

    @staticmethod
    def _has_effective_transition_rules(transition_rules: Any) -> bool:
        return any(bool(value) for value in transition_rules.values())

    @staticmethod
    def _validate_allowed_commit_roots(
        allowed_commit_roots: list[str] | tuple[str, ...]
    ) -> tuple[Path, ...]:
        if not isinstance(allowed_commit_roots, (list, tuple)):
            raise ValueError("allowed_commit_roots must be a list or tuple of paths.")

        validated_roots: list[Path] = []
        for root in allowed_commit_roots:
            if not isinstance(root, str) or not root.strip():
                raise ValueError(
                    "allowed_commit_roots entries must be non-empty absolute paths."
                )
            resolved_root = Path(root).resolve(strict=False)
            if not resolved_root.is_absolute():
                raise ValueError(
                    "allowed_commit_roots entries must be absolute paths."
                )
            validated_roots.append(resolved_root)
        return tuple(validated_roots)

    def _validate_commit_target(self, target_path: str) -> Path | Dict[str, Any]:
        if not self.allowed_commit_roots:
            return self._blocked(
                error_code="QWED-AGENT-STATE-107",
                message=(
                    "Blocked: atomic state commit requires configured allowed "
                    "commit roots."
                ),
            )

        if not isinstance(target_path, str) or not target_path.strip():
            return self._blocked(
                error_code="QWED-AGENT-STATE-107",
                message="Blocked: target_path must be a non-empty absolute path.",
            )

        candidate = Path(target_path)
        if not candidate.is_absolute():
            return self._blocked(
                error_code="QWED-AGENT-STATE-107",
                message="Blocked: target_path must be an absolute path.",
            )

        resolved_target = candidate.resolve(strict=False)
        parent = resolved_target.parent
        if not parent.exists() or not parent.is_dir():
            return self._blocked(
                error_code="QWED-AGENT-STATE-107",
                message=(
                    "Blocked: target_path parent directory must already exist for "
                    "atomic commit."
                ),
            )

        if resolved_target.suffix.lower() != ".json":
            return self._blocked(
                error_code="QWED-AGENT-STATE-107",
                message="Blocked: target_path must end with .json for state commits.",
            )

        if not any(
            self._is_path_within_root(resolved_target, allowed_root)
            for allowed_root in self.allowed_commit_roots
        ):
            return self._blocked(
                error_code="QWED-AGENT-STATE-107",
                message="Blocked: target_path is outside the configured commit roots.",
            )

        return resolved_target

    def _validate_schema_definition(
        self, schema: Dict[str, Any], path: str
    ) -> Dict[str, Any]:
        if not isinstance(schema, dict):
            raise ValueError(f"Schema at {path} must be a dictionary.")

        schema_type = self._validate_schema_type(schema, path)
        self._validate_enum_definition(schema, path)
        handler = self._SCHEMA_DEFINITION_VALIDATORS.get(schema_type)
        if handler is not None:
            handler(self, schema, path)

        return schema

    def _validate_transition_rules_definition(
        self, transition_rules: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not isinstance(transition_rules, dict):
            raise ValueError("Transition rules must be a dictionary.")

        unknown_keys = sorted(
            set(transition_rules) - set(self._VALID_TRANSITION_RULE_KEYS)
        )
        if unknown_keys:
            raise ValueError(
                f"Transition rules contain unsupported keys: {unknown_keys}."
            )

        validated_rules: Dict[str, Any] = {}
        validated_rules["immutable_paths"] = self._validate_path_list(
            transition_rules.get("immutable_paths", []),
            "immutable_paths",
        )
        validated_rules["monotonic_integer_paths"] = self._validate_path_list(
            transition_rules.get("monotonic_integer_paths", []),
            "monotonic_integer_paths",
        )
        validated_rules["ordered_enum_paths"] = self._validate_ordered_enum_paths(
            transition_rules.get("ordered_enum_paths", {})
        )
        validated_rules["keyed_object_array_paths"] = (
            self._validate_keyed_object_array_paths(
                transition_rules.get("keyed_object_array_paths", {})
            )
        )
        return validated_rules

    def _validate_value(
        self,
        schema: Dict[str, Any],
        value: Any,
        path: str,
        depth: int = 0,
    ) -> str | None:
        if depth >= self.MAX_VALIDATION_DEPTH:
            return (
                f"{path} exceeds maximum validation depth "
                f"({self.MAX_VALIDATION_DEPTH})."
            )

        enum_error = self._validate_enum_value(schema, value, path)
        if enum_error is not None:
            return enum_error

        schema_type = schema["type"]
        handler = self._VALUE_VALIDATORS.get(schema_type)
        if handler is None:
            return f"{path} uses unsupported schema type {schema_type!r}."
        return handler(self, schema, value, path, depth)

    def _validate_schema_type(self, schema: Dict[str, Any], path: str) -> str:
        schema_type = schema.get("type")
        if schema_type not in self._VALID_SCHEMA_TYPES:
            raise ValueError(
                f"Schema at {path} must declare a supported type, got {schema_type!r}."
            )
        return schema_type

    @staticmethod
    def _validate_path_list(paths: Any, rule_name: str) -> list[str]:
        if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
            raise ValueError(f"{rule_name} must be a list of JSON-style path strings.")
        for path in paths:
            AgentStateGuard._validate_json_path(path, rule_name)
        return paths

    def _validate_ordered_enum_paths(self, rules: Any) -> Dict[str, list[Any]]:
        if not isinstance(rules, dict):
            raise ValueError("ordered_enum_paths must be a dictionary.")

        validated: Dict[str, list[Any]] = {}
        for path, allowed_values in rules.items():
            self._validate_json_path(path, "ordered_enum_paths")
            if not isinstance(allowed_values, list) or len(allowed_values) < 2:
                raise ValueError(
                    f"ordered_enum_paths[{path!r}] must define at least two ordered values."
                )
            validated[path] = allowed_values
        return validated

    def _validate_keyed_object_array_paths(
        self, rules: Any
    ) -> Dict[str, Dict[str, Any]]:
        if not isinstance(rules, dict):
            raise ValueError("keyed_object_array_paths must be a dictionary.")

        validated: Dict[str, Dict[str, Any]] = {}
        for path, rule in rules.items():
            self._validate_json_path(path, "keyed_object_array_paths")
            if not isinstance(rule, dict):
                raise ValueError(
                    f"keyed_object_array_paths[{path!r}] must be a dictionary."
                )
            unknown_rule_keys = sorted(
                set(rule) - {"key", "monotonic_boolean_fields", "allow_new_items"}
            )
            if unknown_rule_keys:
                raise ValueError(
                    f"keyed_object_array_paths[{path!r}] contains unsupported keys: "
                    f"{unknown_rule_keys}."
                )

            key = rule.get("key")
            if not isinstance(key, str) or not key:
                raise ValueError(
                    f"keyed_object_array_paths[{path!r}] must define a non-empty key field."
                )

            monotonic_boolean_fields = rule.get("monotonic_boolean_fields", [])
            if not isinstance(monotonic_boolean_fields, list) or any(
                not isinstance(field, str) or not field
                for field in monotonic_boolean_fields
            ):
                raise ValueError(
                    f"keyed_object_array_paths[{path!r}].monotonic_boolean_fields "
                    "must be a list of field names."
                )

            allow_new_items = rule.get("allow_new_items", True)
            if not isinstance(allow_new_items, bool):
                raise ValueError(
                    f"keyed_object_array_paths[{path!r}].allow_new_items must be a boolean."
                )

            validated[path] = {
                "key": key,
                "monotonic_boolean_fields": monotonic_boolean_fields,
                "allow_new_items": allow_new_items,
            }

        return validated

    @staticmethod
    def _validate_enum_definition(schema: Dict[str, Any], path: str) -> None:
        if "enum" not in schema:
            return
        enum_values = schema["enum"]
        if not isinstance(enum_values, list) or not enum_values:
            raise ValueError(f"Schema enum at {path} must be a non-empty list.")

    def _validate_object_schema(self, schema: Dict[str, Any], path: str) -> None:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            raise ValueError(f"Object schema at {path} must define properties.")

        required = schema.get("required", [])
        self._validate_required_keys(required, properties, path)
        self._validate_additional_properties(schema.get("additionalProperties", False), path)

        for key, child_schema in properties.items():
            self._validate_property_name(key, path)
            self._validate_schema_definition(child_schema, f"{path}.{key}")

    def _validate_array_schema(self, schema: Dict[str, Any], path: str) -> None:
        if "items" not in schema:
            raise ValueError(f"Array schema at {path} must define an items schema.")
        self._validate_schema_definition(schema["items"], f"{path}[]")

    @staticmethod
    def _validate_required_keys(
        required: Any, properties: Dict[str, Any], path: str
    ) -> None:
        if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
            raise ValueError(f"Required keys at {path} must be a list of strings.")

        unknown_required = sorted(set(required) - set(properties))
        if unknown_required:
            raise ValueError(
                f"Required keys at {path} are missing from properties: {unknown_required}."
            )

    @staticmethod
    def _validate_additional_properties(additional_properties: Any, path: str) -> None:
        if not isinstance(additional_properties, bool):
            raise ValueError(f"additionalProperties at {path} must be a boolean value.")

    @staticmethod
    def _validate_property_name(key: Any, path: str) -> None:
        if not isinstance(key, str) or not key:
            raise ValueError(f"Object property names at {path} must be non-empty strings.")

    @staticmethod
    def _validate_enum_value(schema: Dict[str, Any], value: Any, path: str) -> str | None:
        if "enum" in schema and value not in schema["enum"]:
            return f"{path} must be one of {schema['enum']!r}, got {value!r}."
        return None

    def _validate_transition_rules(
        self,
        current_state: Dict[str, Any],
        proposed_state: Dict[str, Any],
    ) -> str | None:
        validators = (
            self._validate_immutable_paths,
            self._validate_monotonic_integer_paths,
            self._validate_ordered_enum_transition_paths,
            self._validate_keyed_object_array_transition_paths,
        )
        for validator in validators:
            error = validator(current_state, proposed_state)
            if error is not None:
                return error
        return None

    def _validate_immutable_paths(
        self,
        current_state: Dict[str, Any],
        proposed_state: Dict[str, Any],
    ) -> str | None:
        for path in self.transition_rules["immutable_paths"]:
            current_value = self._get_path_value(current_state, path)
            proposed_value = self._get_path_value(proposed_state, path)
            if current_value != proposed_value:
                return (
                    f"{path} is immutable across state transitions. "
                    f"Current={current_value!r}, proposed={proposed_value!r}."
                )
        return None

    def _validate_monotonic_integer_paths(
        self,
        current_state: Dict[str, Any],
        proposed_state: Dict[str, Any],
    ) -> str | None:
        for path in self.transition_rules["monotonic_integer_paths"]:
            current_value = self._get_path_value(current_state, path)
            proposed_value = self._get_path_value(proposed_state, path)
            if proposed_value < current_value:
                return (
                    f"{path} regressed from {current_value!r} to "
                    f"{proposed_value!r}."
                )
        return None

    def _validate_ordered_enum_transition_paths(
        self,
        current_state: Dict[str, Any],
        proposed_state: Dict[str, Any],
    ) -> str | None:
        for path, allowed_values in self.transition_rules["ordered_enum_paths"].items():
            current_value = self._get_path_value(current_state, path)
            proposed_value = self._get_path_value(proposed_state, path)
            current_index = allowed_values.index(current_value)
            proposed_index = allowed_values.index(proposed_value)
            if proposed_index < current_index:
                return (
                    f"{path} regressed from {current_value!r} to "
                    f"{proposed_value!r}."
                )
        return None

    def _validate_keyed_object_array_transition_paths(
        self,
        current_state: Dict[str, Any],
        proposed_state: Dict[str, Any],
    ) -> str | None:
        for path, rule in self.transition_rules["keyed_object_array_paths"].items():
            current_items = self._get_path_value(current_state, path)
            proposed_items = self._get_path_value(proposed_state, path)
            error = self._validate_keyed_object_array_transition(
                path=path,
                current_items=current_items,
                proposed_items=proposed_items,
                rule=rule,
            )
            if error is not None:
                return error
        return None

    def _validate_keyed_object_array_transition(
        self,
        path: str,
        current_items: Any,
        proposed_items: Any,
        rule: Dict[str, Any],
    ) -> str | None:
        if not isinstance(current_items, list) or not isinstance(proposed_items, list):
            return f"{path} must resolve to arrays in both current and proposed state."

        key_field = rule["key"]
        current_keys = self._extract_keyed_item_keys(current_items, path, key_field)
        if isinstance(current_keys, str):
            return current_keys
        proposed_keys = self._extract_keyed_item_keys(proposed_items, path, key_field)
        if isinstance(proposed_keys, str):
            return proposed_keys

        if proposed_keys[: len(current_keys)] != current_keys:
            return f"{path} must preserve existing item order and prevent deletion."
        if not rule["allow_new_items"] and len(proposed_keys) != len(current_keys):
            return f"{path} does not allow appending new items."

        current_map = {item[key_field]: item for item in current_items}
        proposed_map = {item[key_field]: item for item in proposed_items}

        for key in current_keys:
            current_item = current_map[key]
            proposed_item = proposed_map[key]
            item_error = self._validate_keyed_object_item_transition(
                path=path,
                key_field=key_field,
                item_key=key,
                current_item=current_item,
                proposed_item=proposed_item,
                monotonic_boolean_fields=rule["monotonic_boolean_fields"],
            )
            if item_error is not None:
                return item_error
        return None

    @staticmethod
    def _extract_keyed_item_keys(
        items: list[Any], path: str, key_field: str
    ) -> list[Any] | str:
        keys: list[Any] = []
        seen_keys: set[Any] = set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                return f"{path}[{index}] must be an object."
            if key_field not in item:
                return f"{path}[{index}] is missing key field {key_field!r}."
            key = item[key_field]
            if key in seen_keys:
                return f"{path} contains duplicate {key_field!r} values: {key!r}."
            seen_keys.add(key)
            keys.append(key)
        return keys

    @staticmethod
    def _validate_keyed_object_item_transition(
        path: str,
        key_field: str,
        item_key: Any,
        current_item: Dict[str, Any],
        proposed_item: Dict[str, Any],
        monotonic_boolean_fields: list[str],
    ) -> str | None:
        for field in monotonic_boolean_fields:
            old_value = current_item.get(field)
            new_value = proposed_item.get(field)
            if old_value is True and new_value is False:
                return (
                    f"{path}[{key_field}={item_key!r}].{field} regressed from True to False."
                )

        for field, old_value in current_item.items():
            if field in monotonic_boolean_fields:
                continue
            new_value = proposed_item.get(field)
            if old_value != new_value:
                return (
                    f"{path}[{key_field}={item_key!r}].{field} changed from "
                    f"{old_value!r} to {new_value!r}."
                )
        return None

    @staticmethod
    def _validate_json_path(path: str, rule_name: str) -> None:
        if not isinstance(path, str) or not path.startswith("$.") or ".." in path:
            raise ValueError(
                f"{rule_name} paths must use dot-style JSON paths starting with '$.'."
            )

    @staticmethod
    def _is_path_within_root(candidate: Path, root: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    @staticmethod
    def _get_path_value(state: Dict[str, Any], path: str) -> Any:
        value: Any = state
        for part in path[2:].split("."):
            if not isinstance(value, dict) or part not in value:
                raise ValueError(f"Configured path {path!r} was not found in state.")
            value = value[part]
        return value

    @classmethod
    def _serialize_json_deterministically(cls, value: Any) -> str:
        if isinstance(value, MappingProxyType):
            value = dict(value)
        if isinstance(value, dict):
            items = []
            for key in sorted(value):
                items.append(
                    f"{json.dumps(key)}:{cls._serialize_json_deterministically(value[key])}"
                )
            return "{" + ",".join(items) + "}"
        if isinstance(value, (list, tuple)):
            return "[" + ",".join(cls._serialize_json_deterministically(item) for item in value) + "]"
        if isinstance(value, Decimal):
            return str(value)
        return json.dumps(value, separators=(",", ":"))

    def _atomic_write_json(self, normalized_state: Dict[str, Any], target_path: Path) -> int:
        payload = self._serialize_json_deterministically(normalized_state).encode("utf-8")
        temp_file_path: str | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                delete=False,
                dir=target_path.parent,
                prefix=f"{target_path.stem}.",
                suffix=".tmp",
            ) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(payload)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.replace(temp_file_path, target_path)
            temp_file_path = None
            return len(payload)
        finally:
            if temp_file_path is not None:
                try:
                    os.unlink(temp_file_path)
                except FileNotFoundError:
                    pass

    def _validate_object_value(
        self, schema: Dict[str, Any], value: Any, path: str, depth: int
    ) -> str | None:
        if not isinstance(value, dict):
            return f"{path} must be an object, got {type(value).__name__}."

        properties = schema["properties"]
        required = schema.get("required", [])
        missing_keys = [key for key in required if key not in value]
        if missing_keys:
            return f"{path} is missing required keys: {missing_keys}."

        extra_key_error = self._validate_extra_keys(
            value=value,
            properties=properties,
            additional_properties=schema.get("additionalProperties", False),
            path=path,
        )
        if extra_key_error is not None:
            return extra_key_error

        for key, child_schema in properties.items():
            if key not in value:
                continue
            error = self._validate_value(
                child_schema,
                value[key],
                f"{path}.{key}",
                depth + 1,
            )
            if error is not None:
                return error

        return None

    def _validate_array_value(
        self, schema: Dict[str, Any], value: Any, path: str, depth: int
    ) -> str | None:
        if not isinstance(value, list):
            return f"{path} must be an array, got {type(value).__name__}."

        item_schema = schema["items"]
        for index, item in enumerate(value):
            error = self._validate_value(
                item_schema,
                item,
                f"{path}[{index}]",
                depth + 1,
            )
            if error is not None:
                return error
        return None

    @staticmethod
    def _validate_extra_keys(
        value: Dict[str, Any],
        properties: Dict[str, Any],
        additional_properties: bool,
        path: str,
    ) -> str | None:
        if additional_properties:
            return None
        extra_keys = sorted(set(value) - set(properties))
        if extra_keys:
            return f"{path} contains unexpected keys: {extra_keys}."
        return None

    def _validate_string_value(
        self, schema: Dict[str, Any], value: Any, path: str, depth: int
    ) -> str | None:
        del self
        del schema
        del depth
        if not isinstance(value, str):
            return f"{path} must be a string, got {type(value).__name__}."
        return None

    def _validate_integer_value(
        self, schema: Dict[str, Any], value: Any, path: str, depth: int
    ) -> str | None:
        del self
        del schema
        del depth
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{path} must be an integer, got {type(value).__name__}."
        return None

    def _validate_number_value(
        self, schema: Dict[str, Any], value: Any, path: str, depth: int
    ) -> str | None:
        del self
        del schema
        del depth
        if isinstance(value, bool):
            return f"{path} must be a number, got {type(value).__name__}."
        if isinstance(value, Decimal):
            return None
        if isinstance(value, float):
            return (
                f"{path} must use deterministic JSON numbers. "
                "Provide decimals in JSON so they parse as Decimal."
            )
        if not isinstance(value, int):
            return f"{path} must be a number, got {type(value).__name__}."
        return None

    def _validate_boolean_value(
        self, schema: Dict[str, Any], value: Any, path: str, depth: int
    ) -> str | None:
        del self
        del schema
        del depth
        if not isinstance(value, bool):
            return f"{path} must be a boolean, got {type(value).__name__}."
        return None

    def _validate_null_value(
        self, schema: Dict[str, Any], value: Any, path: str, depth: int
    ) -> str | None:
        del self
        del schema
        del depth
        if value is not None:
            return f"{path} must be null, got {type(value).__name__}."
        return None

    @staticmethod
    def _reject_duplicate_keys(pairs: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate key {key!r} is not allowed.")
            result[key] = value
        return result

    @staticmethod
    def _reject_non_standard_constant(value: str) -> Any:
        raise ValueError(f"Non-standard JSON constant {value!r} is not allowed.")

    @classmethod
    def _blocked(cls, error_code: str, message: str) -> Dict[str, Any]:
        # Error-code allocation:
        # - QWED-AGENT-STATE-001..099 are reserved for shared state/input guards
        # - QWED-AGENT-STATE-100..199 are reserved for AgentStateGuard failures
        return {
            "verified": False,
            "status": "BLOCKED",
            "error_code": error_code,
            "message": message,
        }

    @classmethod
    def _canonicalize(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: cls._canonicalize(value[key])
                for key in sorted(value)
            }
        if isinstance(value, list):
            return [cls._canonicalize(item) for item in value]
        return value


AgentStateGuard._SCHEMA_DEFINITION_VALIDATORS = {
    "object": AgentStateGuard._validate_object_schema,
    "array": AgentStateGuard._validate_array_schema,
}

AgentStateGuard._VALUE_VALIDATORS = {
    "object": AgentStateGuard._validate_object_value,
    "array": AgentStateGuard._validate_array_value,
    "string": AgentStateGuard._validate_string_value,
    "integer": AgentStateGuard._validate_integer_value,
    "number": AgentStateGuard._validate_number_value,
    "boolean": AgentStateGuard._validate_boolean_value,
    "null": AgentStateGuard._validate_null_value,
}
