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
    """Test computed field verification (inline exact Decimal comparison)."""
    
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
        """Incorrect total calculation fails deterministically."""
        schema = {
            "type": "object",
            "properties": {
                "subtotal": {"type": "number"},
                "tax": {"type": "number"},
                "discount": {"type": "number"},
                "total": {"type": "number"}
            }
        }
        data = {"subtotal": 100.00, "tax": 10.00, "discount": 5.00, "total": 115.00}  # Wrong!
        result = verifier.verify(data, schema)
        assert result.developer_fields["is_valid"] is False
        assert any(
            i["type"] == "math_verification_failed" and i["severity"] == "ERROR"
            for i in result.developer_fields["issues"]
        )

    def test_total_calculation_with_discount_valid(self, verifier):
        """total = subtotal + tax - discount passes the math check."""
        schema = {
            "type": "object",
            "properties": {
                "subtotal": {"type": "number"},
                "tax": {"type": "number"},
                "discount": {"type": "number"},
                "total": {"type": "number"}
            }
        }
        data = {"subtotal": 100.00, "tax": 10.00, "discount": 5.00, "total": 105.00}
        result = verifier.verify(data, schema)
        assert result.developer_fields["is_valid"] is True

    def test_tax_rate_math_mismatch(self, verifier):
        """tax = subtotal * tax_rate mismatch is detected deterministically."""
        schema = {
            "type": "object",
            "properties": {
                "subtotal": {"type": "number"},
                "tax_rate": {"type": "number"},
                "tax": {"type": "number"}
            }
        }
        data = {"subtotal": 100.00, "tax_rate": 0.10, "tax": 15.00}  # Wrong!
        result = verifier.verify(data, schema)
        assert any(
            i["type"] == "math_verification_failed" and i["severity"] == "ERROR"
            for i in result.developer_fields["issues"]
        )


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

    def test_valid_ucp_transaction_with_discount(self, verifier):
        """A valid discounted UCP transaction passes (total = subtotal + tax - discount)."""
        transaction = {
            "subtotal": 100.00,
            "tax": 10.00,
            "discount": 5.00,
            "total": 105.00,
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

    def test_ucp_payload_currency_used_for_validation_and_metadata(self, verifier):
        """The transaction's declared currency drives validation AND metadata.

        Regression (CodeRabbit/Sentry/Greptile): when the payload declares a
        currency that differs from the method argument, precision checks used
        the declared currency but developer_fields["currency"] and proof
        evidence reported the argument. JPY has 0 decimal places, so a
        subtotal like 100.5 must be precision-checked (and reported) as JPY.
        """
        transaction = {
            "subtotal": 100.5,
            "tax": 0,
            "total": 100.5,
            "currency": "JPY",
        }
        result = verifier.verify_ucp_transaction(transaction, currency="USD")
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
        assert result.developer_fields["currency"] == "JPY"
        # 100.5 exceeds JPY's zero-decimal precision: a verifier that reports
        # "JPY" but applies USD precision would silently produce no warning.
        assert any(
            i["type"] == "currency_precision" and i["severity"] == "WARNING"
            for i in result.developer_fields["issues"]
        )

        # If the proof had attested the (wrong) USD argument instead of the
        # declared JPY, its proof_ref would equal the one for a USD-defaulted
        # transaction with identical amounts. They must differ.
        usd_defaulted = verifier.verify_ucp_transaction(
            {"subtotal": 100.5, "tax": 0, "total": 100.5}
        )
        assert result.proof_ref != usd_defaulted.proof_ref

    def test_ucp_currency_rounded_total_not_rejected_by_base_check(self, verifier):
        """A currency-rounded total must survive the generic inline total check.

        Regression (CodeRabbit): USD subtotal=1.005, tax=0, discount=0 with
        total=1.00 is a legitimately rounded amount — the currency-aware
        half-even check accepts it. The generic base total check used exact
        comparison and rejected it, making base_valid False and skipping the
        UCP check entirely.
        """
        transaction = {
            "subtotal": 1.005,
            "tax": 0,
            "discount": 0,
            "total": 1.00,
            "currency": "USD",
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.status is DiagnosticStatus.VERIFIED
        assert result.developer_fields["is_valid"] is True
        assert result.constraint_id == "schema_verifier.ucp_valid"

    def test_ucp_currency_rounded_total_still_rejects_real_mismatch(self, verifier):
        """Currency quantization must not mask a genuine total mismatch."""
        transaction = {
            "subtotal": 1.005,
            "tax": 0,
            "discount": 0,
            "total": 2.50,  # Real mismatch, far beyond rounding
            "currency": "USD",
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
        assert result.constraint_id == "schema_verifier.ucp_violation"

    def test_ucp_unlisted_currency_uses_precision_fallback(self, verifier):
        """Unlisted currency must share UCP's two-decimal fallback.

        Regression (Greptile P1): base total quantization only applied to
        currencies in CURRENCY_PRECISION, so an unlisted currency (XYZ) with
        subtotal=1.005, total=1.00 failed the unquantized base check — a base
        error that prevented UCP validation from accepting the rounded total.
        """
        transaction = {
            "subtotal": 1.005,
            "tax": 0,
            "discount": 0,
            "total": 1.00,  # Legitimately rounded to two decimals
            "currency": "XYZ",
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
        assert result.constraint_id == "schema_verifier.ucp_valid"

    def test_ucp_currency_rounded_tax_not_rejected_by_base_check(self, verifier):
        """A currency-rounded tax must survive the generic tax check.

        Regression (Sentry): the tax branch compared exactly while total was
        quantized, so tax rounded from 7.00035 to 7.00 was rejected for a
        currency payload.
        """
        transaction = {
            "subtotal": 100.00,
            "tax_rate": 0.07,
            "tax": 7.00,  # 100 * 0.07 = 7.00035, rounded to cents
            "total": 107.00,
            "currency": "USD",
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert_verified(result)
        assert result.developer_fields["is_valid"] is True
        assert result.constraint_id == "schema_verifier.ucp_valid"

    
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
                timeout=60,
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

    def test_ucp_non_dict_transaction_is_violation(self, verifier):
        """Non-dict UCP transaction must not raise AttributeError."""
        result = verifier.verify_ucp_transaction("not-a-dict")
        assert result.status is DiagnosticStatus.VERIFIED
        assert result.developer_fields["is_valid"] is False
        assert result.proof_ref is not None
        assert result.constraint_id == "schema_verifier.ucp_violation"
        assert result.developer_fields["transaction_type"] == "UCP"
        assert result.developer_fields["currency"] == "USD"

    def test_ucp_string_amount_is_violation(self, verifier):
        """String amount fields must not raise TypeError."""
        transaction = {
            "subtotal": "100.00",
            "tax": 10.00,
            "total": 110.00,
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
        assert result.proof_ref is not None
        assert result.constraint_id == "schema_verifier.ucp_violation"
        assert result.developer_fields["transaction_type"] == "UCP"
        assert result.developer_fields["currency"] == "USD"

    def test_ucp_none_amount_is_violation(self, verifier):
        """None amount fields must not raise TypeError."""
        transaction = {
            "subtotal": None,
            "tax": 10.00,
            "total": 110.00,
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.developer_fields["is_valid"] is False
        assert result.proof_ref is not None

    def test_ucp_discount_string_is_violation(self, verifier):
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


class TestSchemaShapeValidation:
    """Regression coverage for _validate_schema_shape malformed keyword shapes."""

    @pytest.mark.parametrize("schema", [
        {"type": "banana"},                              # unknown type string
        {"type": []},                                    # empty type list
        {"type": ["string", "banana"]},                  # invalid type entry
        {"type": {}},                                    # type is neither str nor list
        {"type": 42},                                    # type wrong primitive kind
        {"enum": "red"},                                 # enum not a list
        {"type": "object", "properties": {"a": "str"}},  # property schema not dict
        {"type": "object", "required": "name"},          # required not a list
        {"type": "object", "required": ["a", 42]},       # required entry not string
        {"type": "object", "additionalProperties": "no"},  # additionalProperties wrong kind
        {"type": "object", "additionalProperties": {"minLength": "x"}},  # nested bad schema
        {"type": "array", "items": []},                  # items not dict
        {"type": "array", "prefixItems": {}},            # prefixItems not list
        {"type": "array", "prefixItems": ["x"]},         # prefixItems entry not dict
        {"type": "number", "minimum": "zero"},           # minimum not number
        {"type": "number", "minimum": True},             # minimum bool (JSON gotcha)
        {"type": "number", "maximum": 5, "exclusiveMaximum": "5"},  # bad exclusiveMaximum
        {"type": "number", "multipleOf": 0},             # multipleOf not positive
        {"type": "number", "multipleOf": False},         # multipleOf bool
        {"type": "string", "minLength": 1.5},            # minLength not int
        {"type": "array", "minItems": True},             # minItems bool
        {"type": "object", "maxProperties": "3"},        # maxProperties not int
        {"type": "string", "maxLength": False},          # maxLength bool
        {"type": "string", "pattern": 123},              # pattern not string
        {"type": "string", "format": 123},               # format not string
        {"type": "array", "uniqueItems": "yes"},         # uniqueItems not bool
        {"type": "string", "minLength": -1},             # negative minLength
        {"type": "array", "minItems": -1},               # negative minItems
        {"type": "object", "maxProperties": -2},         # negative maxProperties
        {"type": "number", "minimum": float("nan")},     # NaN minimum
        {"type": "number", "maximum": float("inf")},     # +inf maximum
        {"type": "number", "exclusiveMinimum": float("-inf")},  # -inf exclusive bound
        {"type": "number", "multipleOf": float("inf")},  # non-finite multipleOf
    ])
    def test_malformed_schema_shape_blocked(self, verifier, schema):
        """Malformed schema keyword shapes must be BLOCKED with parse_error."""
        result = verifier.verify({"a": 1}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.proof_ref is None
        assert result.constraint_id == "schema_verifier.parse_error"

    def test_malformed_schema_errors_reported(self, verifier):
        """Blocked parse_error results surface the collected shape errors."""
        schema = {"type": "banana", "properties": []}
        result = verifier.verify({}, schema)
        assert result.constraint_id == "schema_verifier.parse_error"
        assert result.developer_fields["errors"]

    def test_recursive_schema_blocked(self, verifier):
        """A self-referential schema must fail closed, not RecursionError out."""
        schema = {"type": "object"}
        schema["properties"] = {"self_ref": schema}
        result = verifier.verify({"self_ref": {"self_ref": {}}}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.proof_ref is None
        assert result.constraint_id == "schema_verifier.parse_error"

    @pytest.mark.parametrize("keyword", [
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    ])
    def test_huge_integer_bound_does_not_crash(self, verifier, keyword):
        """Integers beyond float range are finite and must not raise OverflowError."""
        schema = {"type": "number", keyword: 10 ** 1000}
        result = verifier.verify(1, schema)
        assert result.status is DiagnosticStatus.VERIFIED
        assert result.proof_ref is not None

    def test_union_type_list_valid(self, verifier):
        """A valid union type list must still be accepted."""
        schema = {"type": ["string", "null"]}
        assert verifier.verify("hello", schema).developer_fields["is_valid"] is True
        assert verifier.verify(None, schema).developer_fields["is_valid"] is True

    def test_prefix_items_valid(self, verifier):
        """Valid prefixItems tuple validation continues to work."""
        schema = {
            "type": "array",
            "prefixItems": [{"type": "string"}, {"type": "number"}]
        }
        assert verifier.verify(["a", 1], schema).developer_fields["is_valid"] is True

    def test_additional_properties_schema_valid(self, verifier):
        """additionalProperties as a schema must validate extras against it."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": {"type": "number"}
        }
        assert verifier.verify({"name": "a", "score": 5}, schema).developer_fields["is_valid"] is True

    def test_exclusive_minimum_maximum_valid(self, verifier):
        """Valid exclusive numeric bounds keep working with shape validation."""
        schema = {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 10}
        assert verifier.verify(5, schema).developer_fields["is_valid"] is True

    def test_union_type_list_invalid(self, verifier):
        """Union type mismatch is rejected deterministically."""
        schema = {"type": ["string", "null"]}
        result = verifier.verify(42, schema)
        assert result.developer_fields["is_valid"] is False
        assert result.developer_fields["issues"][0]["type"] == "type_mismatch"

    def test_union_type_still_applies_type_specific_constraints(self, verifier):
        """Union schemas must still enforce type-specific constraints on the
        matched runtime type (regression: constraints were skipped for unions)."""
        schema = {"type": ["string", "null"], "minLength": 5}
        # String value is type-valid but too short -> constraint violation.
        result = verifier.verify("ab", schema)
        assert result.developer_fields["is_valid"] is False
        issues = [i["type"] for i in result.developer_fields["issues"]]
        assert "constraint_violation" in issues
        assert verifier.verify("abcdef", schema).developer_fields["is_valid"] is True
        assert verifier.verify(None, schema).developer_fields["is_valid"] is True

    def test_shape_cache_invalidated_on_schema_mutation(self, verifier):
        """In-place schema mutation must be re-validated, not served stale.

        Regression (Greptile P1): the schema-shape cache was keyed by object
        identity, so mutating a caller-owned schema dict between verify() calls
        returned a stale shape result. Render invalid->valid and valid->invalid
        to prove every verify applies the schema's current contents.
        """
        schema = {"type": "object", "properties": {"a": {"type": "string"}}}
        valid_result = verifier.verify({"a": "ok"}, schema)
        assert valid_result.status is DiagnosticStatus.VERIFIED

        # Mutate in place to a MALFORMED shape: must re-validate (parse_error),
        # never serve the stale VERIFIED from the first call.
        schema["properties"]["a"] = {"type": "banana"}
        mutated = verifier.verify({"a": "ok"}, schema)
        assert mutated.status is DiagnosticStatus.BLOCKED
        assert mutated.constraint_id == "schema_verifier.parse_error"
        assert mutated.proof_ref is None

        # Repair in place: must re-validate again (no stale BLOCKED).
        schema["properties"]["a"] = {"type": "string"}
        repaired = verifier.verify({"a": "ok"}, schema)
        assert repaired.status is DiagnosticStatus.VERIFIED

    def test_shape_cache_healed_from_previous_error(self, verifier):
        """Repairing a previously-malformed schema must not stay blocked.

        Regression (Greptile P1): the content-keyed cache must evict the stale
        error when a malformed dict is corrected between calls on the same
        verifier instance.
        """
        schema = {"type": "number", "minimum": True}  # malformed (bool)
        bad = verifier.verify(1, schema)
        assert bad.status is DiagnosticStatus.BLOCKED
        assert bad.constraint_id == "schema_verifier.parse_error"

        schema["minimum"] = 0  # repaired in place
        fixed = verifier.verify(1, schema)
        assert fixed.status is DiagnosticStatus.VERIFIED

    def test_all_of_requires_all_subschemas(self, verifier):
        """allOf data must satisfy every subschema.

        Regression (Greptile P1): composition keywords were silently ignored,
        so ``verify(7, {"allOf": [{"type": "string"}]})`` returned valid.
        """
        schema = {"allOf": [{"type": "string"}, {"minLength": 3}]}
        assert verifier.verify("yes", schema).developer_fields["is_valid"] is True
        result = verifier.verify(7, {"allOf": [{"type": "string"}]})
        assert result.developer_fields["is_valid"] is False
        assert result.constraint_id == "schema_verifier.schema_violation"
        assert any(i["type"] == "type_mismatch" for i in result.developer_fields["issues"])

    def test_any_of_requires_one_match(self, verifier):
        """anyOf data must satisfy at least one subschema."""
        schema = {"anyOf": [{"type": "string"}, {"type": "boolean"}]}
        assert verifier.verify("ok", schema).developer_fields["is_valid"] is True
        assert verifier.verify(True, schema).developer_fields["is_valid"] is True
        result = verifier.verify(7, schema)
        assert result.developer_fields["is_valid"] is False
        assert any(i["type"] == "anyOf_match_failed" for i in result.developer_fields["issues"])

    def test_one_of_requires_exactly_one_match(self, verifier):
        """oneOf data must satisfy exactly one subschema."""
        schema = {"oneOf": [{"type": "number"}, {"type": "integer"}]}
        # 7 matches both number AND integer -> more than one -> violation.
        result = verifier.verify(7, schema)
        assert result.developer_fields["is_valid"] is False
        assert any(i["type"] == "oneOf_match_failed" for i in result.developer_fields["issues"])
        # 7.5 matches only number -> valid.
        assert verifier.verify(7.5, schema).developer_fields["is_valid"] is True

    def test_not_rejects_matching_data(self, verifier):
        """not data must fail the subschema."""
        schema = {"not": {"type": "string"}}
        result = verifier.verify("nope", schema)
        assert result.developer_fields["is_valid"] is False
        assert any(i["type"] == "not_violation" for i in result.developer_fields["issues"])
        assert verifier.verify(7, schema).developer_fields["is_valid"] is True

    def test_typeless_subschema_constraints_still_apply(self, verifier):
        """Object/array keyword constraints apply even when type is omitted.

        Regression (Greptile P1): a typeless ``{"required": ["y"]}`` subschema
        never dispatched ``_validate_object``, so ``not``/``allOf`` children
        with object/array-but-no-type keywords were silently skipped. The
        data's runtime type must drive the relevant keyword validation.
        """
        # not {"required": ["y"]} on a dict lacking y -> not satisfied -> valid.
        assert verifier.verify(
            {"x": 1}, {"not": {"required": ["y"]}}
        ).developer_fields["is_valid"] is True
        # not {"required": ["y"]} on a dict that HAS y -> not violated -> invalid.
        result = verifier.verify({"y": 1}, {"not": {"required": ["y"]}})
        assert result.developer_fields["is_valid"] is False
        assert any(i["type"] == "not_violation" for i in result.developer_fields["issues"])

        # allOf [{"required": ["y"]}] on a dict lacking y -> required fails -> invalid.
        result = verifier.verify({"x": 1}, {"allOf": [{"required": ["y"]}]})
        assert result.developer_fields["is_valid"] is False
        assert any(i["type"] == "missing_required" for i in result.developer_fields["issues"])

        # anyOf [{"minItems": 2}] on a 1-element array -> no match -> invalid.
        result = verifier.verify([1], {"anyOf": [{"minItems": 2}]})
        assert result.developer_fields["is_valid"] is False
        assert verifier.verify([1, 2], {"anyOf": [{"minItems": 2}]}).developer_fields["is_valid"] is True

    def test_composition_schema_shape_errors_blocked(self, verifier):
        """Malformed composition schemas are parse errors, not silently valid."""
        blocked = verifier.verify(7, {"allOf": []})
        assert blocked.status is DiagnosticStatus.BLOCKED
        assert blocked.constraint_id == "schema_verifier.parse_error"

        blocked = verifier.verify(7, {"oneOf": [{"type": "number"}, "not-a-schema"]})
        assert blocked.status is DiagnosticStatus.BLOCKED
        assert blocked.constraint_id == "schema_verifier.parse_error"

        blocked = verifier.verify(7, {"not": "not-a-schema"})
        assert blocked.status is DiagnosticStatus.BLOCKED
        assert blocked.constraint_id == "schema_verifier.parse_error"

    def test_shapes_error_paths_name_the_keyword(self, verifier):
        """Shape errors report the offending keyword in the path.

        Regression (Sentry LOW): _shape_composition_list reported "$" for
        malformed allOf/anyOf/oneOf because it did not know which keyword it
        was validating; other shape validators also hardcoded their keyword.
        Every dispatched checker now receives the keyword and reports e.g.
        "$.allOf", not "$".
        """
        result = verifier.verify(7, {"allOf": "not-a-list"})
        assert "errors" in result.developer_fields
        errors = result.developer_fields["errors"]
        assert any(err.startswith("$.allOf") for err in errors)

        result = verifier.verify(7, {"oneOf": []})
        assert any(err.startswith("$.oneOf") for err in result.developer_fields["errors"])

        result = verifier.verify(7, {"type": "nope"})
        assert any(err.startswith("$.type") for err in result.developer_fields["errors"])

    def test_composition_probes_do_not_inflate_stats(self, verifier):
        """Probe validations (anyOf/oneOf/not) must not inflate evidence stats.

        Regression (Sentry LOW): probes shared the caller's stats dict, so a
        successful anyOf/oneOf counted paths_checked for every discarded probe
        (e.g. oneOf with a 3rd-subschema match reported 4 paths instead of 2).
        Probes now run with isolated stats and only the winning subschema's
        stats are merged back.
        """
        result = verifier.verify(
            7, {"anyOf": [{"type": "string"}, {"minLength": 1}]}
        )
        assert result.developer_fields["is_valid"] is True
        # root + the single matching subschema; the discarded string probe
        # must not add a path.
        assert result.developer_fields["summary"]["paths_checked"] == 2

        result = verifier.verify(
            7, {"oneOf": [{"type": "string"}, {"type": "boolean"}, {"type": "integer"}]}
        )
        assert result.developer_fields["is_valid"] is True
        assert result.developer_fields["summary"]["paths_checked"] == 2

        result = verifier.verify(7, {"not": {"type": "string"}})
        assert result.developer_fields["is_valid"] is True
        assert result.developer_fields["summary"]["paths_checked"] == 2

    def test_prefix_items_plus_items_valid(self, verifier):
        """prefixItems AND items combine: prefix tuples validate the leading
        elements, items validates the remaining (regression: elif skipped
        tuple validation when both were present)."""
        schema = {
            "type": "array",
            "prefixItems": [{"type": "string"}, {"type": "number"}],
            "items": {"type": "boolean"}
        }
        assert verifier.verify(["a", 1, True, False], schema).developer_fields["is_valid"] is True

    def test_prefix_items_plus_items_invalid_trailing(self, verifier):
        """A trailing element violating items is rejected even with prefixItems."""
        schema = {
            "type": "array",
            "prefixItems": [{"type": "string"}, {"type": "number"}],
            "items": {"type": "boolean"}
        }
        result = verifier.verify(["a", 1, "not-a-bool"], schema)
        assert result.developer_fields["is_valid"] is False

    def test_prefix_items_plus_items_invalid_prefix(self, verifier):
        """A leading element violating prefixItems is rejected."""
        schema = {
            "type": "array",
            "prefixItems": [{"type": "string"}, {"type": "number"}],
            "items": {"type": "boolean"}
        }
        result = verifier.verify([1, 2], schema)
        assert result.developer_fields["is_valid"] is False

    def test_min_max_properties(self, verifier):
        """minProperties/maxProperties constraints determine conformance."""
        schema = {"type": "object", "minProperties": 2, "maxProperties": 2}
        result = verifier.verify({"a": 1}, schema)
        assert result.developer_fields["is_valid"] is False
        assert verifier.verify({"a": 1, "b": 2}, schema).developer_fields["is_valid"] is True
        result = verifier.verify({"a": 1, "b": 2, "c": 3}, schema)
        assert result.developer_fields["is_valid"] is False

    def test_invalid_regex_pattern_blocked(self, verifier):
        """A syntactically invalid regex in schema is a schema parse error."""
        schema = {"type": "string", "pattern": "("}  # Invalid regex
        result = verifier.verify("anything", schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.parse_error"

    def test_shape_validator_exception_returns_blocked(self, verifier, monkeypatch):
        """An unexpected exception from a shape validator must fail closed.

        Regression (Sentry MEDIUM): the call to _schema_shape_errors in
        verify() sat outside the try/except wrapping _validate_node, so a
        future shape-validator bug would propagate uncaught instead of
        returning the documented BLOCKED validation_error result.
        """
        def boom(_schema):
            raise RuntimeError("shape validator crashed")

        monkeypatch.setattr(verifier, "_schema_shape_errors", boom)
        result = verifier.verify({"a": 1}, {"type": "object"})
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"
        assert result.developer_fields["error_type"] == "RuntimeError"

    def test_ucp_currency_precision_violation(self, verifier):
        """Currency precision warning is emitted without blocking validity."""
        transaction = {
            "subtotal": 100.123,  # 3 decimals exceeds USD precision (2)
            "tax": 10.00,
            "total": 110.123,
            "currency": "USD",
            "items": []
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert any(i["type"] == "currency_precision" and i["severity"] == "WARNING"
                   for i in result.developer_fields["issues"])
        assert result.developer_fields["is_valid"] is True
        assert result.constraint_id == "schema_verifier.ucp_valid"


class TestEvidenceNormalization:
    """Coverage for _evidence_proof_data / _assert_string_keys edge cases."""

    def test_cyclic_list_fails_closed(self, verifier):
        """A cyclic top-level list must fail closed."""
        schema = {"type": "array"}
        data = [1, 2]
        data.append(data)
        result = verifier.verify(data, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_non_string_dict_key_fails_closed(self, verifier):
        """JSON objects keyed by non-strings must fail closed (no silent merge)."""
        schema = {"type": "object"}
        result = verifier.verify({1: "a"}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_ucp_large_amount_validates_deterministically(self, verifier):
        """Large representable amounts validate (no Decimal.InvalidOperation)."""
        transaction = {
            "subtotal": 1e300,
            "tax": 0.0,
            "discount": 0.0,
            "total": 1e300,
            "currency": "USD"
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result.status is DiagnosticStatus.VERIFIED
        assert result.proof_ref is not None
        assert result.developer_fields["is_valid"] is True
        assert result.developer_fields["constraint_id"] == "schema_verifier.ucp_valid"

    def test_ucp_unexpected_error_fails_closed(self, verifier):
        """Unexpected UCP-specific errors must return BLOCKED, not crash."""
        from unittest.mock import MagicMock
        bad_map = MagicMock()
        bad_map.get.side_effect = RuntimeError("boom")
        verifier.CURRENCY_PRECISION = bad_map
        transaction = {"subtotal": 100.0, "tax": 10.0, "total": 110.0}
        result = verifier.verify_ucp_transaction(transaction)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.proof_ref is None
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_set_to_sorted_list_rejects_unsupported(self):
        """_set_to_sorted_list raises TypeError for non-set values."""
        from qwed_new.core.schema_verifier import _set_to_sorted_list
        assert _set_to_sorted_list(frozenset({2, 1})) == [1, 2]
        with pytest.raises(TypeError):
            _set_to_sorted_list(object())

    def test_nested_non_string_dict_key_fails_closed(self, verifier):
        """Non-string keys nested inside lists/objects must also fail closed."""
        schema = {"type": "object"}
        result = verifier.verify({"rows": [{"ok": True}, {2: "b"}]}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_unsupported_evidence_value_fails_closed(self, verifier):
        """Values with no deterministic JSON form must fail closed."""
        schema = {"type": "object"}
        result = verifier.verify({"obj": object()}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_evidence_proof_data_rejects_cyclic(self):
        """_evidence_proof_data raises ValueError on cyclic structures."""
        from qwed_new.core.schema_verifier import _evidence_proof_data
        cyclic = {}
        cyclic["self"] = cyclic
        with pytest.raises(ValueError):
            _evidence_proof_data(cyclic)

    def test_evidence_proof_data_accepts_shared_references(self):
        """A repeated (non-cyclic) reference is not a cycle and must serialize."""
        from qwed_new.core.schema_verifier import _evidence_proof_data
        shared = {"a": 1}
        assert _evidence_proof_data({"x": shared, "y": shared, "z": [shared]})

    def test_evidence_proof_data_canonicalizes_sets(self):
        """Sets are canonicalized to sorted lists, order-independently."""
        from qwed_new.core.schema_verifier import _evidence_proof_data
        assert _evidence_proof_data({"s": {3, 1, 2}}) == _evidence_proof_data({"s": {2, 3, 1}})

    def test_verify_evidence_serialization_failure_returns_blocked(self, verifier):
        """If proof serialization unexpectedly fails, verify returns BLOCKED."""
        from unittest.mock import patch
        seen = []

        def boom_evidence(evidence):
            seen.append(evidence)
            raise ValueError("boom")

        with patch("qwed_new.core.schema_verifier._evidence_proof_data", side_effect=boom_evidence):
            result = verifier.verify({"a": 1}, {"type": "object"})
        # The mock must have been fed the generic schema_evidence (which is the
        # only call site on the base-verify path): it carries paths_checked and
        # is not the UCP-specific evidence (no "currency" key).
        assert seen
        assert "paths_checked" in seen[0]
        assert "currency" not in seen[0]
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"
        assert result.proof_ref is None

    def test_ucp_blocked_base_result_passthrough(self, verifier):
        """A BLOCKED base verify result is passed through unchanged."""
        from unittest.mock import patch
        from qwed_new.core.diagnostics import DiagnosticResult
        blocked = DiagnosticResult.blocked(
            "blocked", {"constraint_id": "schema_verifier.validation_error"}
        )
        with patch.object(verifier, "verify", return_value=blocked):
            result = verifier.verify_ucp_transaction({"subtotal": 1, "total": 1})
        assert result is blocked

    def test_ucp_evidence_normalization_failed_returns_blocked(self, verifier):
        """UCP evidence normalization failure returns BLOCKED with validation_error."""
        from unittest.mock import patch
        from qwed_new.core.schema_verifier import _evidence_proof_data
        real = _evidence_proof_data
        calls = []

        def fail_on_ucp_evidence(evidence):
            calls.append(evidence)
            if len(calls) == 1:
                return real(evidence)
            raise ValueError("boom")

        with patch("qwed_new.core.schema_verifier._evidence_proof_data", side_effect=fail_on_ucp_evidence):
            result = verifier.verify_ucp_transaction({"subtotal": 1, "total": 1})
        # Two call sites: the base-verify schema evidence first, then the
        # UCP-specific evidence. The failing (last) call must be the UCP one,
        # which carries "currency" and omits paths_checked — proving the mock
        # failed the UCP evidence-normalization branch, not the base one.
        assert len(calls) == 2
        assert "paths_checked" in calls[0]
        assert "currency" not in calls[0]
        assert "currency" in calls[1]
        assert "paths_checked" not in calls[1]
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"
        assert result.proof_ref is None

    def test_hostile_repr_set_member_fails_closed(self, verifier):
        """A set member with a hostile __repr__ must not let the exception escape."""
        class Hostile:
            def __repr__(self):
                raise RuntimeError("boom")
        schema = {"type": "object"}
        result = verifier.verify({"bad": {Hostile()}}, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"
        assert result.proof_ref is None

    def test_nan_evidence_fails_closed(self, verifier):
        """NaN in evidence must not serialize into the proof evidence."""
        result = verifier.verify(float("nan"), {"type": "number"})
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_inf_evidence_fails_closed(self, verifier):
        """Infinity in evidence must not serialize into the proof evidence."""
        result = verifier.verify(float("inf"), {"type": "number"})
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_unexpected_validation_error_returns_blocked(self, verifier):
        """An unexpected error inside node validation fails closed."""
        from unittest.mock import patch
        with patch.object(verifier, "_validate_node", side_effect=RuntimeError("boom")):
            result = verifier.verify({"a": 1}, {"type": "object"})
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.validation_error"

    def test_ref_schema_blocked_without_registry(self, verifier):
        """Unresolved $ref fails closed — cannot validate without registry."""
        schema = {"$ref": "#/definitions/x", "type": "object"}
        result = verifier.verify({"a": 1}, schema)
        assert result.developer_fields["is_valid"] is False
        unresolved = [
            i for i in result.developer_fields["issues"]
            if i["type"] == "unresolved_ref"
        ]
        assert len(unresolved) == 1

    def test_unknown_type_name_is_blocked(self, verifier):
        """An unknown type name is rejected at schema-parse time (fail closed)."""
        schema = {"type": ["not-a-real-type"]}
        result = verifier.verify(1, schema)
        assert result.status is DiagnosticStatus.BLOCKED
        assert result.constraint_id == "schema_verifier.parse_error"


class TestFormatWarning:
    """Advisory format violations stay warnings, never block."""

    def test_format_violation_is_advisory_warning(self, verifier):
        """A bad email format produces a WARNING issue, not an ERROR."""
        schema = {"type": "string", "format": "email"}
        result = verifier.verify("not-an-email", schema)
        assert result.developer_fields["is_valid"] is True
        assert result.developer_fields["issues"][0]["type"] == "format_violation"
        assert result.developer_fields["issues"][0]["severity"] == "WARNING"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
