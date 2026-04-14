"""
AgentStateGuard

Phase 1 focuses only on structural verification:
- strict JSON parsing
- strict schema validation
- fail-closed decision objects

No state transition proof or commit side effects are introduced here.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, Iterable


class AgentStateGuard:
    """
    Deterministically verifies proposed agent state payloads before any commit.

    Phase 1 validates structure only. Semantic transition proof and execution
    policy belong to later phases.
    """

    _VALID_SCHEMA_TYPES = frozenset(
        {"object", "array", "string", "integer", "number", "boolean", "null"}
    )

    def __init__(self, required_schema: Dict[str, Any]) -> None:
        self.required_schema = self._validate_schema_definition(required_schema, "$")

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

    def _load_strict_json(self, proposed_state_json: str) -> Any:
        return json.loads(
            proposed_state_json,
            object_pairs_hook=self._reject_duplicate_keys,
            parse_constant=self._reject_non_standard_constant,
        )

    def _validate_schema_definition(
        self, schema: Dict[str, Any], path: str
    ) -> Dict[str, Any]:
        if not isinstance(schema, dict):
            raise ValueError(f"Schema at {path} must be a dictionary.")

        schema_type = schema.get("type")
        if schema_type not in self._VALID_SCHEMA_TYPES:
            raise ValueError(
                f"Schema at {path} must declare a supported type, got {schema_type!r}."
            )

        if "enum" in schema:
            enum_values = schema["enum"]
            if not isinstance(enum_values, list) or not enum_values:
                raise ValueError(f"Schema enum at {path} must be a non-empty list.")

        if schema_type == "object":
            properties = schema.get("properties")
            if not isinstance(properties, dict):
                raise ValueError(f"Object schema at {path} must define properties.")

            required = schema.get("required", [])
            if not isinstance(required, list) or any(
                not isinstance(item, str) for item in required
            ):
                raise ValueError(f"Required keys at {path} must be a list of strings.")

            unknown_required = sorted(set(required) - set(properties))
            if unknown_required:
                raise ValueError(
                    f"Required keys at {path} are missing from properties: {unknown_required}."
                )

            additional_properties = schema.get("additionalProperties", False)
            if not isinstance(additional_properties, bool):
                raise ValueError(
                    f"additionalProperties at {path} must be a boolean value."
                )

            for key, child_schema in properties.items():
                if not isinstance(key, str) or not key:
                    raise ValueError(f"Object property names at {path} must be non-empty strings.")
                self._validate_schema_definition(child_schema, f"{path}.{key}")

        elif schema_type == "array":
            if "items" not in schema:
                raise ValueError(f"Array schema at {path} must define an items schema.")
            self._validate_schema_definition(schema["items"], f"{path}[]")

        return schema

    def _validate_value(self, schema: Dict[str, Any], value: Any, path: str) -> str | None:
        schema_type = schema["type"]

        if "enum" in schema and value not in schema["enum"]:
            return f"{path} must be one of {schema['enum']!r}, got {value!r}."

        if schema_type == "object":
            if not isinstance(value, dict):
                return f"{path} must be an object, got {type(value).__name__}."

            properties = schema["properties"]
            required = schema.get("required", [])

            missing_keys = [key for key in required if key not in value]
            if missing_keys:
                return f"{path} is missing required keys: {missing_keys}."

            additional_properties = schema.get("additionalProperties", False)
            if not additional_properties:
                extra_keys = sorted(set(value) - set(properties))
                if extra_keys:
                    return f"{path} contains unexpected keys: {extra_keys}."

            for key, child_schema in properties.items():
                if key in value:
                    error = self._validate_value(child_schema, value[key], f"{path}.{key}")
                    if error is not None:
                        return error

            return None

        if schema_type == "array":
            if not isinstance(value, list):
                return f"{path} must be an array, got {type(value).__name__}."

            item_schema = schema["items"]
            for index, item in enumerate(value):
                error = self._validate_value(item_schema, item, f"{path}[{index}]")
                if error is not None:
                    return error
            return None

        if schema_type == "string":
            if not isinstance(value, str):
                return f"{path} must be a string, got {type(value).__name__}."
            return None

        if schema_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                return f"{path} must be an integer, got {type(value).__name__}."
            return None

        if schema_type == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return f"{path} must be a number, got {type(value).__name__}."
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                return f"{path} must be a finite number."
            return None

        if schema_type == "boolean":
            if not isinstance(value, bool):
                return f"{path} must be a boolean, got {type(value).__name__}."
            return None

        if schema_type == "null":
            if value is not None:
                return f"{path} must be null, got {type(value).__name__}."
            return None

        return f"{path} uses unsupported schema type {schema_type!r}."

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
