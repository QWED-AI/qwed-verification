"""
JSON Schema Verifier: Deterministic Schema Validation.

100% Deterministic - No probability/ML involved.

Features:
1. Type checking (string, number, boolean, array, object)
2. Constraint validation (minimum, maximum, pattern, enum, required)
3. Nested object validation
4. Array item validation
5. Inline math consistency checks for numeric fields (price, tax, total)
6. UCP-specific validation rules

Example:
    schema = {"type": "object", "properties": {"price": {"type": "number", "minimum": 0}}}
    data = {"price": 99.99}
    result = verifier.verify(data, schema)  # VERIFIED - deterministic!
"""

from typing import Dict, List, Any, Union
from dataclasses import dataclass
import math
import re
import json

from qwed_new.core.diagnostics import DiagnosticResult


@dataclass
class SchemaIssue:
    """A schema validation issue."""
    path: str           # JSON path to the issue (e.g., "$.items[0].price")
    issue_type: str     # "type_mismatch", "constraint_violation", etc.
    expected: str       # What was expected
    actual: str         # What was found
    severity: str = "ERROR"  # "ERROR", "WARNING"
    message: str = ""


# Constraint identifiers for DiagnosticResult developer_fields.
_CONSTRAINT_ID_PARSE_ERROR = "schema_verifier.parse_error"
_CONSTRAINT_ID_VALIDATION_ERROR = "schema_verifier.validation_error"
_CONSTRAINT_ID_SCHEMA_VALID = "schema_verifier.schema_valid"
_CONSTRAINT_ID_SCHEMA_VIOLATION = "schema_verifier.schema_violation"
_CONSTRAINT_ID_UCP_VALID = "schema_verifier.ucp_valid"
_CONSTRAINT_ID_UCP_VIOLATION = "schema_verifier.ucp_violation"


def _evidence_proof_data(evidence: Dict[str, Any]) -> str:
    """Serialize proof evidence to a canonical JSON string for proof_ref.

    Fails closed (raises ValueError) on unsupported values, non-string dict
    keys, or cycles so proof-bearing evidence never contains process-dependent
    representations (e.g. ``repr`` of arbitrary objects embeds memory
    addresses, making proof_ref unstable across processes). Sets are
    canonicalized to sorted lists.

    Raises:
        ValueError: if the evidence contains a cycle, a non-string key, or an
            unsupported type.
    """
    seen: set = set()
    _assert_evidence_safe(evidence, seen)
    try:
        return json.dumps(evidence, sort_keys=True, default=_set_to_sorted_list)
    except (TypeError, RecursionError) as exc:
        raise ValueError("proof evidence could not be serialized deterministically") from exc


def _assert_evidence_safe(value: Any, seen: set) -> None:
    """Validate that ``value`` is a JSON-safe, acyclic structure (no copy).

    Strings, ints, floats, bools, and None are primitives and immediately
    return. Lists, tuples, dicts, and sets are recursed into along their
    parent path in ``seen`` so genuine cycles are detected while shared
    (non-cyclic) references remain allowed.

    Raises:
        ValueError: on a cycle, a non-string dict key, or an unsupported type.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    oid = id(value)
    if oid in seen:
        raise ValueError("cyclic value cannot be serialized into proof evidence")
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError(
                    "non-string key in evidence object: "
                    f"expected str, got {type(key).__name__}"
                )
        seen.add(oid)
        try:
            for item in value.values():
                _assert_evidence_safe(item, seen)
        finally:
            seen.discard(oid)
    elif isinstance(value, (list, tuple)):
        seen.add(oid)
        try:
            for item in value:
                _assert_evidence_safe(item, seen)
        finally:
            seen.discard(oid)
    elif isinstance(value, (set, frozenset)):
        seen.add(oid)
        try:
            for item in value:
                _assert_evidence_safe(item, seen)
        finally:
            seen.discard(oid)
    else:
        raise ValueError(
            f"unsupported value type in proof evidence: {type(value).__name__}"
        )


def _set_to_sorted_list(o: Any) -> Any:
    """json.dumps default: canonicalize sets to sorted lists; reject the rest."""
    if isinstance(o, (set, frozenset)):
        return sorted(o, key=repr)
    raise TypeError(f"unsupported evidence type: {type(o).__name__}")


class SchemaVerifier:
    """
    Deterministic JSON Schema Verifier.
    
    Validates JSON data against JSON Schema.
    
    All checks are 100% deterministic:
    - Type: Is value a string/number/boolean? YES or NO.
    - Range: Is 5 >= 0? YES or NO.
    - Pattern: Does "abc" match /^[a-z]+$/? YES or NO.
    
    UCP-Specific Features:
    - Currency precision validation
    - Tax calculation verification
    - Total computation checking
    """
    
    # JSON Schema type mapping
    TYPE_MAP = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None)
    }
    
    # Fields that get inline math consistency checks
    MATH_FIELDS = {
        "total", "subtotal", "tax", "tax_amount", "discount",
        "grand_total", "net_total", "gross_total", "balance",
        "sum", "average", "mean", "computed", "calculated"
    }
    
    # Currency precision rules
    CURRENCY_PRECISION = {
        "USD": 2, "EUR": 2, "GBP": 2, "INR": 2,
        "JPY": 0, "KRW": 0,  # No decimal places
        "BTC": 8, "ETH": 18  # Crypto precision
    }
    
    def __init__(self, enable_math_delegation: bool = True):
        """
        Initialize Schema Verifier.
        
        Args:
            enable_math_delegation: If True, run inline math consistency
                                    checks for computed numeric fields.
        """
        self.enable_math_delegation = enable_math_delegation
    
    def verify(
        self, 
        data: Any, 
        schema: Dict[str, Any],
        strict: bool = True
    ) -> DiagnosticResult:
        """
        Verify data against a JSON Schema.
        
        Args:
            data: The JSON data to verify.
            schema: JSON Schema definition.
            strict: If True, fail on additional properties not in schema.
            
        Returns:
            DiagnosticResult with:
            - VERIFIED when schema validation completed deterministically,
              with proof_ref binding the schema + instance evidence.
            - BLOCKED (constraint_id schema_verifier.parse_error) when the
              schema cannot be parsed as a schema object.
            - BLOCKED (constraint_id schema_verifier.validation_error) when
              an unexpected error occurs during validation.
            
        Example:
            >>> schema = {"type": "object", "properties": {"name": {"type": "string"}}}
            >>> result = verifier.verify({"name": "John"}, schema)
            >>> print(result.status.value)
            VERIFIED
        """
        if not isinstance(schema, dict):
            return DiagnosticResult.blocked(
                "Schema verification blocked: the schema could not be parsed",
                {
                    "constraint_id": _CONSTRAINT_ID_PARSE_ERROR,
                    "error_type": f"expected dict, got {type(schema).__name__}",
                },
            )

        try:
            schema_errors = self._validate_schema_shape(schema)
        except RecursionError:
            schema_errors = ["$: recursive schema definition"]

        if schema_errors:
            return DiagnosticResult.blocked(
                "Schema verification blocked: the schema could not be parsed",
                {
                    "constraint_id": _CONSTRAINT_ID_PARSE_ERROR,
                    "errors": schema_errors,
                },
            )

        issues: List[SchemaIssue] = []
        stats = {"paths_checked": 0, "constraints_checked": 0}

        try:
            self._validate_node(data, schema, "$", issues, stats, strict)
        except Exception as exc:
            return DiagnosticResult.blocked(
                "Schema verification blocked: an unexpected validation error occurred",
                {
                    "constraint_id": _CONSTRAINT_ID_VALIDATION_ERROR,
                    "error_type": type(exc).__name__,
                },
            )

        is_valid = len([i for i in issues if i.severity == "ERROR"]) == 0

        serialized_issues = [
            {
                "path": i.path,
                "type": i.issue_type,
                "expected": i.expected,
                "actual": i.actual,
                "severity": i.severity,
                "message": i.message,
            }
            for i in issues
        ]

        developer_fields = {
            "constraint_id": (
                _CONSTRAINT_ID_SCHEMA_VALID if is_valid
                else _CONSTRAINT_ID_SCHEMA_VIOLATION
            ),
            "is_valid": is_valid,
            "issues": serialized_issues,
            "summary": {
                "total_issues": len(issues),
                "errors": sum(1 for i in issues if i.severity == "ERROR"),
                "warnings": sum(1 for i in issues if i.severity == "WARNING"),
                "paths_checked": stats["paths_checked"],
                "constraints_checked": stats["constraints_checked"],
            },
        }

        try:
            schema_evidence = {
                "schema": schema,
                "instance": data,
                "verdict": "VALID" if is_valid else "INVALID",
                "issues": serialized_issues,
                "paths_checked": stats["paths_checked"],
                "constraints_checked": stats["constraints_checked"],
            }
            proof_data = _evidence_proof_data(schema_evidence)
        except ValueError as exc:
            return DiagnosticResult.blocked(
                "Schema verification blocked: proof evidence could not be normalized",
                {
                    "constraint_id": _CONSTRAINT_ID_VALIDATION_ERROR,
                    "error_type": type(exc).__name__,
                },
            )

        if is_valid:
            agent_message = "Data conforms to the declared schema."
        else:
            agent_message = (
                "Data does not conform to the declared schema "
                f"({developer_fields['summary']['errors']} violation(s) detected)."
            )

        return DiagnosticResult.verified(
            agent_message=agent_message,
            developer_fields=developer_fields,
            evidence=schema_evidence,
            proof_data=proof_data,
        )

    def _validate_schema_shape(self, schema: Any, path: str = "$") -> List[str]:
        """Recursively meta-validate schema keyword shapes.

        Malformed keyword values must be rejected as parse errors instead of
        being silently treated as empty/omitted. Returns a list of error
        messages; an empty list means the schema shape is well-formed.
        """
        if not isinstance(schema, dict):
            return [f"{path}: schema must be a dict, got {type(schema).__name__}"]

        errors: List[str] = []

        type_kw = schema.get("type")
        if type_kw is not None:
            if isinstance(type_kw, str):
                if type_kw not in self.TYPE_MAP:
                    errors.append(f"{path}.type: unknown type {type_kw!r}")
            elif isinstance(type_kw, list):
                if not type_kw or not all(isinstance(t, str) and t in self.TYPE_MAP for t in type_kw):
                    errors.append(f"{path}.type: must be a list of valid types")
            else:
                errors.append(f"{path}.type: must be a string or list of strings")

        if "enum" in schema and not isinstance(schema["enum"], list):
            errors.append(f"{path}.enum: must be a list")

        if "properties" in schema:
            props = schema["properties"]
            if not isinstance(props, dict):
                errors.append(f"{path}.properties: must be a dict")
            else:
                for prop_name, prop_schema in props.items():
                    if not isinstance(prop_schema, dict):
                        errors.append(f"{path}.properties.{prop_name}: must be a schema dict")
                    else:
                        errors.extend(self._validate_schema_shape(prop_schema, f"{path}.properties.{prop_name}"))

        if "required" in schema:
            req = schema["required"]
            if not isinstance(req, list) or not all(isinstance(r, str) for r in req):
                errors.append(f"{path}.required: must be a list of strings")

        additional = schema.get("additionalProperties", True)
        if not isinstance(additional, (bool, dict)):
            errors.append(f"{path}.additionalProperties: must be a bool or schema dict")
        elif isinstance(additional, dict):
            errors.extend(self._validate_schema_shape(additional, f"{path}.additionalProperties"))

        if "items" in schema:
            items = schema["items"]
            if isinstance(items, dict):
                errors.extend(self._validate_schema_shape(items, f"{path}.items"))
            else:
                errors.append(f"{path}.items: must be a schema dict")

        if "prefixItems" in schema:
            prefix = schema["prefixItems"]
            if not isinstance(prefix, list):
                errors.append(f"{path}.prefixItems: must be a list of schemas")
            else:
                for i, item_schema in enumerate(prefix):
                    if isinstance(item_schema, dict):
                        errors.extend(self._validate_schema_shape(item_schema, f"{path}.prefixItems[{i}]"))
                    else:
                        errors.append(f"{path}.prefixItems[{i}]: must be a schema dict")

        for kw in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            if kw in schema:
                kw_val = schema[kw]
                if (
                    not isinstance(kw_val, (int, float))
                    or isinstance(kw_val, bool)
                    or not math.isfinite(kw_val)
                ):
                    errors.append(f"{path}.{kw}: must be a finite number")

        if "multipleOf" in schema:
            mo = schema["multipleOf"]
            if (
                not isinstance(mo, (int, float))
                or isinstance(mo, bool)
                or not math.isfinite(mo)
                or mo <= 0
            ):
                errors.append(f"{path}.multipleOf: must be a finite positive number")

        for kw in ("minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"):
            if kw in schema and (
                not isinstance(schema[kw], int)
                or isinstance(schema[kw], bool)
                or schema[kw] < 0
            ):
                errors.append(f"{path}.{kw}: must be a non-negative integer")

        for kw in ("pattern", "format"):
            if kw in schema and not isinstance(schema[kw], str):
                errors.append(f"{path}.{kw}: must be a string")

        if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
            errors.append(f"{path}.uniqueItems: must be a bool")

        return errors

    def _validate_node(
        self,
        data: Any,
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int],
        strict: bool
    ) -> None:
        """Recursively validate a node against its schema."""
        stats["paths_checked"] += 1
        
        # Handle schema references
        if "$ref" in schema:
            # Basic $ref handling (same-document refs)
            # Full $ref resolution would require schema registry
            pass
        
        # Type validation
        if "type" in schema:
            self._check_type(data, schema["type"], path, issues, stats)
        
        # Enum validation
        if "enum" in schema:
            self._check_enum(data, schema["enum"], path, issues, stats)
        
        # Const validation
        if "const" in schema:
            self._check_const(data, schema["const"], path, issues, stats)
        
        # Type-specific validations
        schema_type = schema.get("type")
        
        if schema_type == "string" and isinstance(data, str):
            self._validate_string(data, schema, path, issues, stats)
        
        elif schema_type in ("number", "integer") and isinstance(data, (int, float)):
            self._validate_number(data, schema, path, issues, stats)
        
        elif schema_type == "array" and isinstance(data, list):
            self._validate_array(data, schema, path, issues, stats, strict)
        
        elif schema_type == "object" and isinstance(data, dict):
            self._validate_object(data, schema, path, issues, stats, strict)
    
    def _check_type(
        self,
        data: Any,
        expected_type: Union[str, List[str]],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int]
    ) -> bool:
        """Check if data matches expected type."""
        stats["constraints_checked"] += 1
        
        # Handle union types
        if isinstance(expected_type, list):
            for t in expected_type:
                if self._is_type(data, t):
                    return True
            issues.append(SchemaIssue(
                path=path,
                issue_type="type_mismatch",
                expected=f"one of {expected_type}",
                actual=type(data).__name__,
                message=f"Expected {expected_type}, got {type(data).__name__}"
            ))
            return False
        
        if not self._is_type(data, expected_type):
            issues.append(SchemaIssue(
                path=path,
                issue_type="type_mismatch",
                expected=expected_type,
                actual=type(data).__name__,
                message=f"Expected {expected_type}, got {type(data).__name__}"
            ))
            return False
        
        return True
    
    def _is_type(self, data: Any, type_name: str) -> bool:
        """Check if data is of the specified JSON type."""
        if type_name not in self.TYPE_MAP:
            return False
        
        expected_types = self.TYPE_MAP[type_name]
        
        # Special handling: integer vs number
        if type_name == "integer":
            return isinstance(data, int) and not isinstance(data, bool)
        if type_name == "number":
            return isinstance(data, (int, float)) and not isinstance(data, bool)
        if type_name == "boolean":
            return isinstance(data, bool)
        
        return isinstance(data, expected_types)
    
    def _check_enum(
        self,
        data: Any,
        enum_values: List[Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int]
    ) -> None:
        """Check if data is in the allowed enum values."""
        stats["constraints_checked"] += 1
        
        if data not in enum_values:
            issues.append(SchemaIssue(
                path=path,
                issue_type="enum_violation",
                expected=f"one of {enum_values}",
                actual=str(data),
                message=f"Value must be one of {enum_values}"
            ))
    
    def _check_const(
        self,
        data: Any,
        const_value: Any,
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int]
    ) -> None:
        """Check if data equals the const value."""
        stats["constraints_checked"] += 1
        
        if data != const_value:
            issues.append(SchemaIssue(
                path=path,
                issue_type="const_violation",
                expected=str(const_value),
                actual=str(data),
                message=f"Value must be exactly {const_value}"
            ))
    
    def _validate_string(
        self,
        data: str,
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int]
    ) -> None:
        """Validate string constraints."""
        
        # minLength
        if "minLength" in schema:
            stats["constraints_checked"] += 1
            if len(data) < schema["minLength"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"minLength {schema['minLength']}",
                    actual=f"length {len(data)}",
                    message=f"String too short (min: {schema['minLength']})"
                ))
        
        # maxLength
        if "maxLength" in schema:
            stats["constraints_checked"] += 1
            if len(data) > schema["maxLength"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"maxLength {schema['maxLength']}",
                    actual=f"length {len(data)}",
                    message=f"String too long (max: {schema['maxLength']})"
                ))
        
        # pattern
        if "pattern" in schema:
            stats["constraints_checked"] += 1
            if not re.search(schema["pattern"], data):
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="pattern_violation",
                    expected=f"pattern /{schema['pattern']}/",
                    actual=data[:50] + "..." if len(data) > 50 else data,
                    message=f"String does not match pattern"
                ))
        
        # format (common formats)
        if "format" in schema:
            self._check_format(data, schema["format"], path, issues, stats)
    
    def _check_format(
        self,
        data: str,
        format_name: str,
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int]
    ) -> None:
        """Validate string format."""
        stats["constraints_checked"] += 1
        
        formats = {
            "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "uri": r"^https?://",
            "date": r"^\d{4}-\d{2}-\d{2}$",
            "date-time": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
            "uuid": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            "ipv4": r"^(\d{1,3}\.){3}\d{1,3}$",
        }
        
        if format_name in formats:
            if not re.search(formats[format_name], data, re.IGNORECASE):
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="format_violation",
                    expected=f"format '{format_name}'",
                    actual=data[:30] + "..." if len(data) > 30 else data,
                    severity="WARNING",  # Format is advisory per spec
                    message=f"String does not match format '{format_name}'"
                ))
    
    def _validate_number(
        self,
        data: Union[int, float],
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int]
    ) -> None:
        """Validate numeric constraints."""
        
        # minimum
        if "minimum" in schema:
            stats["constraints_checked"] += 1
            if data < schema["minimum"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f">= {schema['minimum']}",
                    actual=str(data),
                    message=f"Value below minimum ({schema['minimum']})"
                ))
        
        # maximum
        if "maximum" in schema:
            stats["constraints_checked"] += 1
            if data > schema["maximum"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"<= {schema['maximum']}",
                    actual=str(data),
                    message=f"Value above maximum ({schema['maximum']})"
                ))
        
        # exclusiveMinimum
        if "exclusiveMinimum" in schema:
            stats["constraints_checked"] += 1
            if data <= schema["exclusiveMinimum"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"> {schema['exclusiveMinimum']}",
                    actual=str(data),
                    message=f"Value must be greater than {schema['exclusiveMinimum']}"
                ))
        
        # exclusiveMaximum
        if "exclusiveMaximum" in schema:
            stats["constraints_checked"] += 1
            if data >= schema["exclusiveMaximum"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"< {schema['exclusiveMaximum']}",
                    actual=str(data),
                    message=f"Value must be less than {schema['exclusiveMaximum']}"
                ))
        
        # multipleOf
        if "multipleOf" in schema:
            stats["constraints_checked"] += 1
            if data % schema["multipleOf"] != 0:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"multiple of {schema['multipleOf']}",
                    actual=str(data),
                    message=f"Value not a multiple of {schema['multipleOf']}"
                ))
    
    def _validate_array(
        self,
        data: List[Any],
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int],
        strict: bool
    ) -> None:
        """Validate array constraints."""
        
        # minItems
        if "minItems" in schema:
            stats["constraints_checked"] += 1
            if len(data) < schema["minItems"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"minItems {schema['minItems']}",
                    actual=f"{len(data)} items",
                    message=f"Array too short (min: {schema['minItems']} items)"
                ))
        
        # maxItems
        if "maxItems" in schema:
            stats["constraints_checked"] += 1
            if len(data) > schema["maxItems"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"maxItems {schema['maxItems']}",
                    actual=f"{len(data)} items",
                    message=f"Array too long (max: {schema['maxItems']} items)"
                ))
        
        # uniqueItems
        if schema.get("uniqueItems"):
            stats["constraints_checked"] += 1
            try:
                # Try to check uniqueness (works for hashable items)
                seen = set()
                for item in data:
                    item_key = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
                    if item_key in seen:
                        issues.append(SchemaIssue(
                            path=path,
                            issue_type="uniqueness_violation",
                            expected="unique items",
                            actual="duplicate found",
                            message="Array contains duplicate items"
                        ))
                        break
                    seen.add(item_key)
            except (TypeError, ValueError) as exc:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="uniqueness_validation_error",
                    expected="provably unique items",
                    actual="uniqueness check could not be completed",
                    message=(
                        "uniqueItems could not be verified deterministically: "
                        f"{exc}"
                    )
                ))

        # items (single schema for all items)
        if "items" in schema and isinstance(schema["items"], dict):
            for i, item in enumerate(data):
                self._validate_node(item, schema["items"], f"{path}[{i}]", issues, stats, strict)
        
        # prefixItems (tuple validation)
        elif "prefixItems" in schema:
            for i, item_schema in enumerate(schema["prefixItems"]):
                if i < len(data):
                    self._validate_node(data[i], item_schema, f"{path}[{i}]", issues, stats, strict)
    
    def _validate_object(
        self,
        data: Dict[str, Any],
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int],
        strict: bool
    ) -> None:
        """Validate object constraints."""
        
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        additional = schema.get("additionalProperties", True)
        
        # Check required properties
        for prop in required:
            stats["constraints_checked"] += 1
            if prop not in data:
                issues.append(SchemaIssue(
                    path=f"{path}.{prop}",
                    issue_type="missing_required",
                    expected="required property",
                    actual="missing",
                    message=f"Required property '{prop}' is missing"
                ))
        
        # Validate each property
        for key, value in data.items():
            prop_path = f"{path}.{key}"
            
            if key in properties:
                self._validate_node(value, properties[key], prop_path, issues, stats, strict)
                
                # Check for math delegation
                if self.enable_math_delegation and key.lower() in self.MATH_FIELDS:
                    self._check_math_field(key, value, data, prop_path, issues, stats)
            
            elif strict and additional is False:
                stats["constraints_checked"] += 1
                issues.append(SchemaIssue(
                    path=prop_path,
                    issue_type="additional_property",
                    expected="no additional properties",
                    actual=key,
                    severity="ERROR",
                    message=f"Additional property '{key}' not allowed"
                ))
            
            elif isinstance(additional, dict):
                # additionalProperties is a schema
                self._validate_node(value, additional, prop_path, issues, stats, strict)
        
        # minProperties
        if "minProperties" in schema:
            stats["constraints_checked"] += 1
            if len(data) < schema["minProperties"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"minProperties {schema['minProperties']}",
                    actual=f"{len(data)} properties",
                    message=f"Object has too few properties"
                ))
        
        # maxProperties
        if "maxProperties" in schema:
            stats["constraints_checked"] += 1
            if len(data) > schema["maxProperties"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"maxProperties {schema['maxProperties']}",
                    actual=f"{len(data)} properties",
                    message=f"Object has too many properties"
                ))
    
    def _check_math_field(
        self,
        field_name: str,
        value: Any,
        parent_data: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int]
    ) -> None:
        """
        Check computed fields using inline arithmetic consistency.
        
        For fields like 'total', 'tax', etc., verify against
        related fields using float comparison.
        """
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return
        
        # Example: total = subtotal + tax
        if field_name.lower() == "total":
            subtotal = parent_data.get("subtotal")
            tax = parent_data.get("tax") or parent_data.get("tax_amount", 0)
            
            if (
                subtotal is not None
                and isinstance(subtotal, (int, float)) and not isinstance(subtotal, bool)
                and isinstance(tax, (int, float)) and not isinstance(tax, bool)
            ):
                stats["constraints_checked"] += 1
                expected = subtotal + tax
                
                # Use decimal comparison for currency
                if abs(value - expected) > 0.01:  # Allow 1 cent tolerance
                    issues.append(SchemaIssue(
                        path=path,
                        issue_type="math_verification_failed",
                        expected=f"{expected:.2f}",
                        actual=f"{value:.2f}",
                        message=f"Total mismatch: expected {expected:.2f}, got {value:.2f}"
                    ))
        
        # Example: tax = subtotal * tax_rate
        elif field_name.lower() in ("tax", "tax_amount"):
            subtotal = parent_data.get("subtotal")
            tax_rate = parent_data.get("tax_rate")
            
            if (
                subtotal is not None and tax_rate is not None
                and isinstance(subtotal, (int, float)) and not isinstance(subtotal, bool)
                and isinstance(tax_rate, (int, float)) and not isinstance(tax_rate, bool)
            ):
                stats["constraints_checked"] += 1
                expected = subtotal * tax_rate
                
                if abs(value - expected) > 0.01:
                    issues.append(SchemaIssue(
                        path=path,
                        issue_type="math_verification_failed",
                        expected=f"{expected:.2f}",
                        actual=f"{value:.2f}",
                        message=f"Tax mismatch: expected {expected:.2f}, got {value:.2f}"
                    ))
    
    def verify_ucp_transaction(
        self,
        transaction: Dict[str, Any],
        currency: str = "USD"
    ) -> DiagnosticResult:
        """
        Verify a UCP (Unified Commerce Protocol) transaction.
        
        UCP-specific validations:
        1. Currency precision
        2. Total = Subtotal + Tax - Discount
        3. All amounts >= 0
        4. Required fields present
        
        Args:
            transaction: UCP transaction data.
            currency: Currency code for precision checking.
            
        Returns:
            DiagnosticResult:
            - VERIFIED when the transaction deterministically conforms to the
              UCP schema and arithmetic rules, with proof_ref binding the
              schema + instance evidence.
            - Passed through BLOCKED when the schema itself cannot be parsed
              or validation errors occur.
        """
        schema = {
            "type": "object",
            "required": ["subtotal", "total"],
            "properties": {
                "subtotal": {"type": "number", "minimum": 0},
                "tax": {"type": "number", "minimum": 0},
                "tax_rate": {"type": "number", "minimum": 0, "maximum": 1},
                "discount": {"type": "number", "minimum": 0},
                "total": {"type": "number", "minimum": 0},
                "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "price", "quantity"],
                        "properties": {
                            "name": {"type": "string"},
                            "price": {"type": "number", "minimum": 0},
                            "quantity": {"type": "integer", "minimum": 1}
                        }
                    }
                }
            }
        }
        
        result = self.verify(transaction, schema, strict=False)
        # Fail closed: pass through BLOCKED, and short-circuit on any
        # deterministic schema violation (e.g. non-dict transaction, or
        # non-numeric amount fields). The base result already carries the
        # structured violation; UCP-specific arithmetic would otherwise raise
        # TypeError/AttributeError on unusable inputs.
        if not result.is_verified or not result.developer_fields.get("is_valid", True):
            return result
        
        # Additional UCP-specific checks (issue dicts, JSON-safe).
        issues = list(result.developer_fields["issues"])
        
        try:
            # Currency precision check
            precision = self.CURRENCY_PRECISION.get(currency, 2) if isinstance(currency, str) else 2
            for field in ["subtotal", "tax", "discount", "total"]:
                if field in transaction:
                    value = transaction[field]
                    if isinstance(value, float):
                        decimal_places = len(str(value).split(".")[-1]) if "." in str(value) else 0
                        if decimal_places > precision:
                            issues.append({
                                "path": f"$.{field}",
                                "type": "currency_precision",
                                "expected": f"max {precision} decimal places for {currency}",
                                "actual": f"{decimal_places} decimal places",
                                "severity": "WARNING",
                                "message": f"Currency precision exceeded for {currency}"
                            })
            
            # Verify computed total
            subtotal = transaction.get("subtotal", 0)
            tax = transaction.get("tax", 0)
            discount = transaction.get("discount", 0)
            total = transaction.get("total", 0)
            
            expected_total = subtotal + tax - discount
            if abs(total - expected_total) > 0.01:
                issues.append({
                    "path": "$.total",
                    "type": "math_verification_failed",
                    "expected": f"{expected_total:.2f}",
                    "actual": f"{total:.2f}",
                    "severity": "ERROR",
                    "message": f"Total mismatch: {subtotal} + {tax} - {discount} = {expected_total:.2f}, got {total:.2f}"
                })
        except Exception as exc:
            return DiagnosticResult.blocked(
                "UCP transaction verification blocked: an unexpected validation error occurred",
                {
                    "constraint_id": _CONSTRAINT_ID_VALIDATION_ERROR,
                    "error_type": type(exc).__name__,
                },
            )
        
        is_valid = len([i for i in issues if i.get("severity") == "ERROR"]) == 0
        
        developer_fields = {
            "constraint_id": (
                _CONSTRAINT_ID_UCP_VALID if is_valid
                else _CONSTRAINT_ID_UCP_VIOLATION
            ),
            "is_valid": is_valid,
            "issues": issues,
            "transaction_type": "UCP",
            "currency": currency,
            "summary": {
                "total_issues": len(issues),
                "errors": sum(1 for i in issues if i.get("severity") == "ERROR"),
                "warnings": sum(1 for i in issues if i.get("severity") == "WARNING")
            },
        }
        
        try:
            ucp_evidence = {
                "schema": schema,
                "instance": transaction,
                "verdict": "VALID" if is_valid else "INVALID",
                "issues": issues,
                "currency": currency,
            }
            proof_data = _evidence_proof_data(ucp_evidence)
        except ValueError as exc:
            return DiagnosticResult.blocked(
                "UCP transaction verification blocked: proof evidence could not be normalized",
                {
                    "constraint_id": _CONSTRAINT_ID_VALIDATION_ERROR,
                    "error_type": type(exc).__name__,
                },
            )
        
        agent_message = (
            "UCP transaction conforms to the declared schema."
            if is_valid else
            "UCP transaction does not conform to the declared schema "
            f"({developer_fields['summary']['errors']} violation(s) detected)."
        )
        
        return DiagnosticResult.verified(
            agent_message=agent_message,
            developer_fields=developer_fields,
            evidence=ucp_evidence,
            proof_data=proof_data,
        )
