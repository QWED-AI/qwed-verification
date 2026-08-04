"""
Tests for SchemaVerifier - Deterministic JSON Schema validation.

Tests cover:
1. Type checking (string, number, boolean, array, object)
2. Constraint validation (min/max, pattern, enum)
3. Nested object validation
4. Array validation
5. UCP transaction verification
6. Inline math consistency for computed fields
7. DiagnosticResult conformance (status, developer_fields, proof_ref)
"""

import pytest
from qwed_new.core.schema_verifier import SchemaVerifier
from qwed_new.core.diagnostics import DiagnosticStatus


@pytest.fixture
def verifier():
    """Create a fresh verifier for each test."""
    return SchemaVerifier()


def assert_verified(result):
    """Assert a VERIFIED DiagnosticResult with proof_ref present."""
    assert result.status is DiagnosticStatus.VERIFIED
    assert result.is_verified is True
    assert result.proof_ref is not None
    assert result.proof_ref.startswith("sha256:")
    assert result.agent_message


def assert_invalid(result):
    """Assert a VERIFIED result that deterministically detected violations."""
    assert result.status is DiagnosticStatus.VERIFIED
    assert result.is_verified is True
    assert result.proof_ref is not None
    assert result.developer_fields["is_valid"] is False


class TestTypeValidation:
    """Test basic type validation."""
    
    def test_string_type_valid(self, verifier):
        """String type should validate string values."""
        schema = {"type": "string"}
        result = verifier.verify("hello", schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
        assert result.constraint_id == "schema_verifier.schema_valid"
    
    def test_string_type_invalid(self, verifier):
        """String type should reject non-strings."""
        schema = {"type": "string"}
        result = verifier.verify(123, schema)
        assert_invalid(result)
        assert result.developer_fields["issues"][0]["type"] == "type_mismatch"
    
    def test_number_type_valid(self, verifier):
        """Number type should validate numeric values."""
        schema = {"type": "number"}
        result = verifier.verify(42.5, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_number_type_accepts_int(self, verifier):
        """Number type should accept integers too."""
        schema = {"type": "number"}
        result = verifier.verify(42, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_integer_type_rejects_float(self, verifier):
        """Integer type should reject floats."""
        schema = {"type": "integer"}
        result = verifier.verify(42.5, schema)
        assert_invalid(result)
    
    def test_boolean_type_valid(self, verifier):
        """Boolean type should validate booleans."""
        schema = {"type": "boolean"}
        result = verifier.verify(True, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_boolean_type_invalid(self, verifier):
        """Boolean type should reject non-booleans."""
        schema = {"type": "boolean"}
        result = verifier.verify(1, schema)  # 1 is not True
        assert_invalid(result)
    
    def test_array_type_valid(self, verifier):
        """Array type should validate lists."""
        schema = {"type": "array"}
        result = verifier.verify([1, 2, 3], schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_object_type_valid(self, verifier):
        """Object type should validate dicts."""
        schema = {"type": "object"}
        result = verifier.verify({"key": "value"}, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_null_type_valid(self, verifier):
        """Null type should validate None."""
        schema = {"type": "null"}
        result = verifier.verify(None, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True


class TestStringConstraints:
    """Test string constraint validation."""
    
    def test_min_length_valid(self, verifier):
        """String with sufficient length passes."""
        schema = {"type": "string", "minLength": 3}
        result = verifier.verify("hello", schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_min_length_invalid(self, verifier):
        """String too short fails."""
        schema = {"type": "string", "minLength": 10}
        result = verifier.verify("hi", schema)
        assert_invalid(result)
    
    def test_max_length_valid(self, verifier):
        """String within max length passes."""
        schema = {"type": "string", "maxLength": 10}
        result = verifier.verify("hello", schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_max_length_invalid(self, verifier):
        """String too long fails."""
        schema = {"type": "string", "maxLength": 3}
        result = verifier.verify("hello", schema)
        assert_invalid(result)
    
    def test_pattern_valid(self, verifier):
        """String matching pattern passes."""
        schema = {"type": "string", "pattern": "^[a-z]+$"}
        result = verifier.verify("hello", schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_pattern_invalid(self, verifier):
        """String not matching pattern fails."""
        schema = {"type": "string", "pattern": "^[a-z]+$"}
        result = verifier.verify("Hello123", schema)
        assert_invalid(result)
    
    def test_email_format(self, verifier):
        """Email format validation."""
        schema = {"type": "string", "format": "email"}
        result = verifier.verify("test@example.com", schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True


class TestNumberConstraints:
    """Test numeric constraint validation."""
    
    def test_minimum_valid(self, verifier):
        """Number at or above minimum passes."""
        schema = {"type": "number", "minimum": 0}
        result = verifier.verify(5, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_minimum_invalid(self, verifier):
        """Number below minimum fails."""
        schema = {"type": "number", "minimum": 0}
        result = verifier.verify(-5, schema)
        assert_invalid(result)
    
    def test_maximum_valid(self, verifier):
        """Number at or below maximum passes."""
        schema = {"type": "number", "maximum": 100}
        result = verifier.verify(50, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_maximum_invalid(self, verifier):
        """Number above maximum fails."""
        schema = {"type": "number", "maximum": 100}
        result = verifier.verify(150, schema)
        assert_invalid(result)
    
    def test_exclusive_minimum(self, verifier):
        """Exclusive minimum validation."""
        schema = {"type": "number", "exclusiveMinimum": 0}
        assert verifier.verify(0.1, schema).developer_fields["is_valid"] is True
        assert verifier.verify(0, schema).developer_fields["is_valid"] is False
    
    def test_exclusive_maximum(self, verifier):
        """Exclusive maximum validation."""
        schema = {"type": "number", "exclusiveMaximum": 100}
        assert verifier.verify(99.9, schema).developer_fields["is_valid"] is True
        assert verifier.verify(100, schema).developer_fields["is_valid"] is False
    
    def test_multiple_of(self, verifier):
        """MultipleOf validation."""
        schema = {"type": "number", "multipleOf": 5}
        assert verifier.verify(10, schema).developer_fields["is_valid"] is True
        assert verifier.verify(7, schema).developer_fields["is_valid"] is False


class TestEnumValidation:
    """Test enum constraint validation."""
    
    def test_enum_valid(self, verifier):
        """Value in enum list passes."""
        schema = {"enum": ["red", "green", "blue"]}
        result = verifier.verify("green", schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_enum_invalid(self, verifier):
        """Value not in enum list fails."""
        schema = {"enum": ["red", "green", "blue"]}
        result = verifier.verify("yellow", schema)
        assert_invalid(result)
    
    def test_const_valid(self, verifier):
        """Const value matches."""
        schema = {"const": "fixed_value"}
        result = verifier.verify("fixed_value", schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_const_invalid(self, verifier):
        """Const value doesn't match."""
        schema = {"const": "fixed_value"}
        result = verifier.verify("other", schema)
        assert_invalid(result)


class TestArrayValidation:
    """Test array constraint validation."""
    
    def test_min_items_valid(self, verifier):
        """Array with enough items passes."""
        schema = {"type": "array", "minItems": 2}
        result = verifier.verify([1, 2, 3], schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_min_items_invalid(self, verifier):
        """Array with too few items fails."""
        schema = {"type": "array", "minItems": 5}
        result = verifier.verify([1, 2], schema)
        assert_invalid(result)
    
    def test_max_items_valid(self, verifier):
        """Array within max items passes."""
        schema = {"type": "array", "maxItems": 5}
        result = verifier.verify([1, 2, 3], schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_max_items_invalid(self, verifier):
        """Array with too many items fails."""
        schema = {"type": "array", "maxItems": 2}
        result = verifier.verify([1, 2, 3, 4, 5], schema)
        assert_invalid(result)
    
    def test_unique_items_valid(self, verifier):
        """Array with unique items passes."""
        schema = {"type": "array", "uniqueItems": True}
        result = verifier.verify([1, 2, 3], schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_unique_items_invalid(self, verifier):
        """Array with duplicates fails."""
        schema = {"type": "array", "uniqueItems": True}
        result = verifier.verify([1, 2, 2, 3], schema)
        assert_invalid(result)

    def test_unique_items_uncheckable_fails_closed(self, verifier):
        """If uniqueness cannot be proven, validation must fail closed."""
        schema = {"type": "array", "uniqueItems": True}
        result = verifier.verify([{"bad": {1, 2}}, {"bad": {3, 4}}], schema)

        assert_invalid(result)
        assert result.developer_fields["issues"][0]["type"] == "uniqueness_validation_error"
        assert "uniqueItems could not be verified deterministically" in result.developer_fields["issues"][0]["message"]

    def test_items_schema(self, verifier):
        """Array items validated against item schema."""
        schema = {
            "type": "array",
            "items": {"type": "number", "minimum": 0}
        }
        assert verifier.verify([1, 2, 3], schema).developer_fields["is_valid"] is True
        assert verifier.verify([1, -2, 3], schema).developer_fields["is_valid"] is False


class TestObjectValidation:
    """Test object constraint validation."""
    
    def test_required_properties_present(self, verifier):
        """Object with required properties passes."""
        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            }
        }
        result = verifier.verify({"name": "John", "age": 30}, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_required_properties_missing(self, verifier):
        """Object missing required property fails."""
        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            }
        }
        result = verifier.verify({"name": "John"}, schema)
        assert_invalid(result)
        assert any("missing_required" in i["type"] for i in result.developer_fields["issues"])
    
    def test_property_type_validation(self, verifier):
        """Object property types are validated."""
        schema = {
            "type": "object",
            "properties": {
                "price": {"type": "number"}
            }
        }
        assert verifier.verify({"price": 99.99}, schema).developer_fields["is_valid"] is True
        assert verifier.verify({"price": "99.99"}, schema).developer_fields["is_valid"] is False
    
    def test_nested_object_validation(self, verifier):
        """Nested objects are validated recursively."""
        schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    },
                    "required": ["name"]
                }
            }
        }
        assert verifier.verify({"user": {"name": "John"}}, schema).developer_fields["is_valid"] is True
        assert verifier.verify({"user": {}}, schema).developer_fields["is_valid"] is False

    def test_strict_additional_properties_false_rejects_extra_fields(self, verifier):
        """Strict mode must fail closed on undeclared object properties."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "required": ["name"],
            "additionalProperties": False
        }

        result = verifier.verify({"name": "rahul", "role": "admin"}, schema, strict=True)

        assert result.developer_fields["is_valid"] is False
        assert any(
            issue["type"] == "additional_property" and issue["severity"] == "ERROR"
            for issue in result.developer_fields["issues"]
        )

    def test_strict_additional_properties_false_accepts_declared_fields(self, verifier):
        """Strict mode should still allow payloads that fully match the schema."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "required": ["name"],
            "additionalProperties": False
        }

        result = verifier.verify({"name": "rahul"}, schema, strict=True)

        assert result.developer_fields["is_valid"] is True

    def test_non_strict_mode_keeps_additional_properties_non_blocking(self, verifier):
        """Non-strict mode preserves permissive handling for extra properties."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "required": ["name"],
            "additionalProperties": False
        }

        result = verifier.verify({"name": "rahul", "role": "admin"}, schema, strict=False)

        assert result.developer_fields["is_valid"] is True
        assert not any(issue["type"] == "additional_property" for issue in result.developer_fields["issues"])

    def test_nested_additional_properties_false_rejects_extra_nested_fields(self, verifier):
        """Nested objects must also fail closed on undeclared extra properties."""
        schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    },
                    "required": ["name"],
                    "additionalProperties": False
                }
            },
            "required": ["user"]
        }

        result = verifier.verify(
            {"user": {"name": "rahul", "role": "admin"}},
            schema,
            strict=True
        )

        assert result.developer_fields["is_valid"] is False
        assert any(
            issue["path"] == "$.user.role"
            and issue["type"] == "additional_property"
            and issue["severity"] == "ERROR"
            for issue in result.developer_fields["issues"]
        )


class TestMathConsistency:
    """Test computed field verification (inline float comparison)."""
    
    def test_total_calculation_valid(self, verifier):
        """Correct total calculation passes."""
        schema = {
            "type": "object",
            "properties": {
                "subtotal": {"type": "number"},
                "tax": {"type": "number"},
                "total": {"type": "number"}
            }
        }
        data = {"subtotal": 100.00, "tax": 10.00, "total": 110.00}
        result = verifier.verify(data, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_total_calculation_invalid(self, verifier):
        """Incorrect total calculation fails."""
        schema = {
            "type": "object",
            "properties": {
                "subtotal": {"type": "number"},
                "tax": {"type": "number"},
                "total": {"type": "number"}
            }
        }
        data = {"subtotal": 100.00, "tax": 10.00, "total": 115.00}  # Wrong!
        result = verifier.verify(data, schema)
        # Should detect math discrepancy
        assert any("math" in str(i).lower() for i in result.developer_fields["issues"])


class TestUCPTransaction:
    """Test UCP-specific transaction verification."""
    
    def test_valid_ucp_transaction(self, verifier):
        """Valid UCP transaction passes."""
        transaction = {
            "subtotal": 100.00,
            "tax": 10.00,
            "discount": 0,
            "total": 110.00,
            "currency": "USD"
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
        assert result.constraint_id == "schema_verifier.ucp_valid"
    
    def test_ucp_transaction_total_mismatch(self, verifier):
        """UCP transaction with wrong total fails."""
        transaction = {
            "subtotal": 100.00,
            "tax": 10.00,
            "discount": 5.00,
            "total": 110.00  # Should be 105.00
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
        assert result.constraint_id == "schema_verifier.ucp_violation"
        assert any("math" in str(i).lower() for i in result.developer_fields["issues"])
    
    def test_ucp_negative_amount(self, verifier):
        """UCP transaction with negative amount fails."""
        transaction = {
            "subtotal": -100.00,  # Invalid
            "tax": 10.00,
            "total": -90.00
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
    
    def test_ucp_with_items(self, verifier):
        """UCP transaction with line items."""
        transaction = {
            "subtotal": 25.00,
            "tax": 2.50,
            "total": 27.50,
            "items": [
                {"name": "Widget", "price": 10.00, "quantity": 2},
                {"name": "Gadget", "price": 5.00, "quantity": 1}
            ]
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True


class TestDiagnosticConformance:
    """Test DiagnosticResult structural conformance (Issue #204)."""
    
    def test_result_is_diagnostic_result(self, verifier):
        """verify() returns a DiagnosticResult, not an ad-hoc dict."""
        schema = {"type": "string"}
        result = verifier.verify("test", schema)
        assert result.status is DiagnosticStatus.VERIFIED
        assert result.is_authoritative is True
        assert result.agent_message

    def test_verified_result_has_proof_ref(self, verifier):
        """VERIFIED results must carry a deterministic proof_ref."""
        schema = {"type": "string"}
        result = verifier.verify("test", schema)
        assert result.proof_ref is not None
        assert result.proof_ref.startswith("sha256:")
    
    def test_proof_ref_is_deterministic(self, verifier):
        """Same schema + instance produce the same proof_ref."""
        schema = {"type": "object", "properties": {"name": {"type": "string"}}}
        r1 = verifier.verify({"name": "John"}, schema)
        r2 = verifier.verify({"name": "John"}, schema)
        assert r1.proof_ref == r2.proof_ref
    
    def test_invalid_result_is_verified_with_violation(self, verifier):
        """Deterministic violations are VERIFIED with developer_fields."""
        schema = {"type": "string"}
        result = verifier.verify(123, schema)
        assert result.status is DiagnosticStatus.VERIFIED
        assert result.developer_fields["is_valid"] is False
        assert result.constraint_id == "schema_verifier.schema_violation"
    
    def test_issue_structure(self, verifier):
        """Issue objects should have complete info."""
        schema = {"type": "number"}
        result = verifier.verify("not a number", schema)
        
        issue = result.developer_fields["issues"][0]
        assert "path" in issue
        assert "type" in issue
        assert "expected" in issue
        assert "actual" in issue
    
    def test_summary_counts(self, verifier):
        """Summary should have correct counts."""
        schema = {
            "type": "object",
            "required": ["a", "b"],
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "number"}
            }
        }
        result = verifier.verify({}, schema)
        
        assert result.developer_fields["summary"]["total_issues"] >= 2
        assert result.developer_fields["summary"]["errors"] >= 2
    
    def test_agent_message_is_sanitized(self, verifier):
        """agent_message must not leak verification internals."""
        schema = {"type": "string"}
        result = verifier.verify(123, schema)
        assert result.agent_message
        assert "type_mismatch" not in result.agent_message
        assert "schema_verifier" not in result.agent_message
    
    def test_parse_error_blocked(self, verifier):
        """Non-dict schema must be BLOCKED, not crash."""
        result = verifier.verify({"a": 1}, "not a schema")
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.proof_ref is None
        assert result.constraint_id == "schema_verifier.parse_error"


class TestEdgeCases:
    """Test edge cases and special scenarios."""
    
    def test_empty_object(self, verifier):
        """Empty object against minimal schema."""
        schema = {"type": "object"}
        result = verifier.verify({}, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_empty_array(self, verifier):
        """Empty array against minimal schema."""
        schema = {"type": "array"}
        result = verifier.verify([], schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
    
    def test_complex_nested_structure(self, verifier):
        """Complex nested structure validation."""
        schema = {
            "type": "object",
            "properties": {
                "users": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "name"],
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
        data = {
            "users": [
                {"id": 1, "name": "Alice", "tags": ["admin", "user"]},
                {"id": 2, "name": "Bob", "tags": ["user"]}
            ]
        }
        result = verifier.verify(data, schema)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True


class TestReviewRegressions:
    """Regression tests for review findings (proof stability, malformed
    schemas, UCP type safety)."""

    def test_unsupported_value_fails_closed(self, verifier):
        """Objects with unsupported (non-JSON) values must not produce
        address-dependent proof_refs — fail closed with BLOCKED."""
        class Unserializable:
            pass
        schema = {"type": "object", "properties": {}}
        result = verifier.verify({"x": Unserializable()}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.proof_ref is None
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_cyclic_value_fails_closed(self, verifier):
        """Cyclic data must fail closed with BLOCKED, not recurse forever."""
        schema = {"type": "object", "properties": {}}
        data = {"x": []}
        data["x"].append(data)
        result = verifier.verify(data, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.proof_ref is None
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_shared_reference_allowed(self, verifier):
        """A shared (non-cyclic) reference is not a cycle and stays VERIFIED."""
        schema = {"type": "object", "properties": {}}
        shared = {"name": "x"}
        result = verifier.verify({"a": shared, "b": shared}, schema)
        assert result.is_verified is True

    def test_set_value_normalized_to_sorted_list(self, verifier):
        """Set values are normalized deterministically into the evidence."""
        schema = {"type": "object", "properties": {}}
        result = verifier.verify({"tags": {"b", "a"}}, schema)
        assert result.is_verified is True
        assert result.proof_ref is not None

    def test_proof_ref_is_cross_process_stable(self, verifier):
        """The same logical input must produce the same proof_ref in a fresh
        process (no memory-address dependent repr in evidence)."""
        import subprocess
        import sys
        import os

        schema = {"type": "object", "properties": {"name": {"type": "string"}}}
        code = (
            "import json, sys\n"
            "from qwed_new.core.schema_verifier import SchemaVerifier\n"
            "schema = {'type': 'object', 'properties': {'name': {'type': 'string'}}}\n"
            "r = SchemaVerifier().verify({'name': 'John'}, schema)\n"
            "print(r.proof_ref)\n"
        )
        env = dict(os.environ)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = os.path.join(root, "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")

        outputs = []
        for _ in range(2):
            proc = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                cwd=root,
                env=env,
            )
            assert proc.returncode == 0, proc.stderr
            outputs.append(proc.stdout.strip())

        assert len(outputs) == 2
        assert outputs[0] == outputs[1]
        assert outputs[0].startswith("sha256:")

    def test_malformed_properties_fails_closed(self, verifier):
        """Non-dict properties must be BLOCKED, not silently treated as empty."""
        schema = {"type": "object", "properties": []}
        result = verifier.verify({"role": "admin"}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.proof_ref is None
        assert result.constraint_id == "schema_verifier.parse_error"

    def test_malformed_required_fails_closed(self, verifier):
        """Non-list-of-strings required must be BLOCKED."""
        schema = {"type": "object", "required": ["a", 42]}
        result = verifier.verify({"a": 1}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.parse_error"

    def test_malformed_numeric_constraint_fails_closed(self, verifier):
        """Non-numeric minimum must be BLOCKED."""
        schema = {"type": "number", "minimum": "zero"}
        result = verifier.verify(5, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.parse_error"

    def test_malformed_nested_properties_fails_closed(self, verifier):
        """Malformed nested property schema must be BLOCKED."""
        schema = {
            "type": "object",
            "properties": {
                "user": {"type": "object", "properties": "nope"}
            }
        }
        result = verifier.verify({"user": {}}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.parse_error"

    def test_ucp_non_dict_transaction_fails_closed(self, verifier):
        """Non-dict UCP transaction must not raise AttributeError."""
        result = verifier.verify_ucp_transaction("not-a-dict")
        assert result.status is DiagnosticStatus.VERIFIED
        assert result.developer_fields["is_valid"] is False
        assert result.proof_ref is not None

    def test_ucp_string_amount_fails_closed(self, verifier):
        """String amount fields must not raise TypeError."""
        transaction = {
            "subtotal": "100.00",
            "tax": 10.00,
            "total": 110.00,
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
        assert result.proof_ref is not None

    def test_ucp_none_amount_fails_closed(self, verifier):
        """None amount fields must not raise TypeError."""
        transaction = {
            "subtotal": None,
            "tax": 10.00,
            "total": 110.00,
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
        assert result.proof_ref is not None

    def test_ucp_discount_string_fails_closed(self, verifier):
        """A bad discount type must not crash the computed-total arithmetic."""
        transaction = {
            "subtotal": 100.00,
            "tax": 10.00,
            "discount": "bad",
            "total": 110.00,
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
        assert result.proof_ref is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
