"""
Tests for SchemaVerifier - Deterministic JSON Schema validation.

Tests cover:
1. Type checking (string, number, boolean, array, object)
2. Constraint validation (min/max, pattern, enum)
3. Nested object validation
4. Array validation
5. UCP transaction verification
6. Math delegation for computed fields
"""

import pytest
from src.qwed_new.core.schema_verifier import SchemaVerifier


@pytest.fixture
def verifier():
    """Create a fresh verifier for each test."""
    return SchemaVerifier()


class TestTypeValidation:
    """Test basic type validation."""
    
    def test_string_type_valid(self, verifier):
        """String type should validate string values."""
        schema = {"type": "string"}
        result = verifier.verify("hello", schema)
        assert result["is_valid"] == True
    
    def test_string_type_invalid(self, verifier):
        """String type should reject non-strings."""
        schema = {"type": "string"}
        result = verifier.verify(123, schema)
        assert result["is_valid"] == False
        assert result["issues"][0]["type"] == "type_mismatch"
    
    def test_number_type_valid(self, verifier):
        """Number type should validate numeric values."""
        schema = {"type": "number"}
        result = verifier.verify(42.5, schema)
        assert result["is_valid"] == True
    
    def test_number_type_accepts_int(self, verifier):
        """Number type should accept integers too."""
        schema = {"type": "number"}
        result = verifier.verify(42, schema)
        assert result["is_valid"] == True
    
    def test_integer_type_rejects_float(self, verifier):
        """Integer type should reject floats."""
        schema = {"type": "integer"}
        result = verifier.verify(42.5, schema)
        assert result["is_valid"] == False
    
    def test_boolean_type_valid(self, verifier):
        """Boolean type should validate booleans."""
        schema = {"type": "boolean"}
        result = verifier.verify(True, schema)
        assert result["is_valid"] == True
    
    def test_boolean_type_invalid(self, verifier):
        """Boolean type should reject non-booleans."""
        schema = {"type": "boolean"}
        result = verifier.verify(1, schema)  # 1 is not True
        assert result["is_valid"] == False
    
    def test_array_type_valid(self, verifier):
        """Array type should validate lists."""
        schema = {"type": "array"}
        result = verifier.verify([1, 2, 3], schema)
        assert result["is_valid"] == True
    
    def test_object_type_valid(self, verifier):
        """Object type should validate dicts."""
        schema = {"type": "object"}
        result = verifier.verify({"key": "value"}, schema)
        assert result["is_valid"] == True
    
    def test_null_type_valid(self, verifier):
        """Null type should validate None."""
        schema = {"type": "null"}
        result = verifier.verify(None, schema)
        assert result["is_valid"] == True


class TestStringConstraints:
    """Test string constraint validation."""
    
    def test_min_length_valid(self, verifier):
        """String with sufficient length passes."""
        schema = {"type": "string", "minLength": 3}
        result = verifier.verify("hello", schema)
        assert result["is_valid"] == True
    
    def test_min_length_invalid(self, verifier):
        """String too short fails."""
        schema = {"type": "string", "minLength": 10}
        result = verifier.verify("hi", schema)
        assert result["is_valid"] == False
    
    def test_max_length_valid(self, verifier):
        """String within max length passes."""
        schema = {"type": "string", "maxLength": 10}
        result = verifier.verify("hello", schema)
        assert result["is_valid"] == True
    
    def test_max_length_invalid(self, verifier):
        """String too long fails."""
        schema = {"type": "string", "maxLength": 3}
        result = verifier.verify("hello", schema)
        assert result["is_valid"] == False
    
    def test_pattern_valid(self, verifier):
        """String matching pattern passes."""
        schema = {"type": "string", "pattern": "^[a-z]+$"}
        result = verifier.verify("hello", schema)
        assert result["is_valid"] == True
    
    def test_pattern_invalid(self, verifier):
        """String not matching pattern fails."""
        schema = {"type": "string", "pattern": "^[a-z]+$"}
        result = verifier.verify("Hello123", schema)
        assert result["is_valid"] == False
    
    def test_email_format(self, verifier):
        """Email format validation."""
        schema = {"type": "string", "format": "email"}
        result = verifier.verify("test@example.com", schema)
        assert result["is_valid"] == True


class TestNumberConstraints:
    """Test numeric constraint validation."""
    
    def test_minimum_valid(self, verifier):
        """Number at or above minimum passes."""
        schema = {"type": "number", "minimum": 0}
        result = verifier.verify(5, schema)
        assert result["is_valid"] == True
    
    def test_minimum_invalid(self, verifier):
        """Number below minimum fails."""
        schema = {"type": "number", "minimum": 0}
        result = verifier.verify(-5, schema)
        assert result["is_valid"] == False
    
    def test_maximum_valid(self, verifier):
        """Number at or below maximum passes."""
        schema = {"type": "number", "maximum": 100}
        result = verifier.verify(50, schema)
        assert result["is_valid"] == True
    
    def test_maximum_invalid(self, verifier):
        """Number above maximum fails."""
        schema = {"type": "number", "maximum": 100}
        result = verifier.verify(150, schema)
        assert result["is_valid"] == False
    
    def test_exclusive_minimum(self, verifier):
        """Exclusive minimum validation."""
        schema = {"type": "number", "exclusiveMinimum": 0}
        assert verifier.verify(0.1, schema)["is_valid"] == True
        assert verifier.verify(0, schema)["is_valid"] == False
    
    def test_exclusive_maximum(self, verifier):
        """Exclusive maximum validation."""
        schema = {"type": "number", "exclusiveMaximum": 100}
        assert verifier.verify(99.9, schema)["is_valid"] == True
        assert verifier.verify(100, schema)["is_valid"] == False
    
    def test_multiple_of(self, verifier):
        """MultipleOf validation."""
        schema = {"type": "number", "multipleOf": 5}
        assert verifier.verify(10, schema)["is_valid"] == True
        assert verifier.verify(7, schema)["is_valid"] == False


class TestEnumValidation:
    """Test enum constraint validation."""
    
    def test_enum_valid(self, verifier):
        """Value in enum list passes."""
        schema = {"enum": ["red", "green", "blue"]}
        result = verifier.verify("green", schema)
        assert result["is_valid"] == True
    
    def test_enum_invalid(self, verifier):
        """Value not in enum list fails."""
        schema = {"enum": ["red", "green", "blue"]}
        result = verifier.verify("yellow", schema)
        assert result["is_valid"] == False
    
    def test_const_valid(self, verifier):
        """Const value matches."""
        schema = {"const": "fixed_value"}
        result = verifier.verify("fixed_value", schema)
        assert result["is_valid"] == True
    
    def test_const_invalid(self, verifier):
        """Const value doesn't match."""
        schema = {"const": "fixed_value"}
        result = verifier.verify("other", schema)
        assert result["is_valid"] == False


class TestArrayValidation:
    """Test array constraint validation."""
    
    def test_min_items_valid(self, verifier):
        """Array with enough items passes."""
        schema = {"type": "array", "minItems": 2}
        result = verifier.verify([1, 2, 3], schema)
        assert result["is_valid"] == True
    
    def test_min_items_invalid(self, verifier):
        """Array with too few items fails."""
        schema = {"type": "array", "minItems": 5}
        result = verifier.verify([1, 2], schema)
        assert result["is_valid"] == False
    
    def test_max_items_valid(self, verifier):
        """Array within max items passes."""
        schema = {"type": "array", "maxItems": 5}
        result = verifier.verify([1, 2, 3], schema)
        assert result["is_valid"] == True
    
    def test_max_items_invalid(self, verifier):
        """Array with too many items fails."""
        schema = {"type": "array", "maxItems": 2}
        result = verifier.verify([1, 2, 3, 4, 5], schema)
        assert result["is_valid"] == False
    
    def test_unique_items_valid(self, verifier):
        """Array with unique items passes."""
        schema = {"type": "array", "uniqueItems": True}
        result = verifier.verify([1, 2, 3], schema)
        assert result["is_valid"] == True
    
    def test_unique_items_invalid(self, verifier):
        """Array with duplicates fails."""
        schema = {"type": "array", "uniqueItems": True}
        result = verifier.verify([1, 2, 2, 3], schema)
        assert result["is_valid"] == False

    def test_unique_items_uncheckable_fails_closed(self, verifier):
        """If uniqueness cannot be proven, validation must fail closed."""
        schema = {"type": "array", "uniqueItems": True}
        result = verifier.verify([{"bad": {1, 2}}, {"bad": {3, 4}}], schema)

        assert result["is_valid"] == False
        assert result["status"] == "INVALID"
        assert result["issues"][0]["type"] == "uniqueness_validation_error"
        assert "uniqueItems could not be verified deterministically" in result["issues"][0]["message"]

    def test_items_schema(self, verifier):
        """Array items validated against item schema."""
        schema = {
            "type": "array",
            "items": {"type": "number", "minimum": 0}
        }
        assert verifier.verify([1, 2, 3], schema)["is_valid"] == True
        assert verifier.verify([1, -2, 3], schema)["is_valid"] == False


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
        assert result["is_valid"] == True
    
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
        assert result["is_valid"] == False
        assert any("missing_required" in i["type"] for i in result["issues"])
    
    def test_property_type_validation(self, verifier):
        """Object property types are validated."""
        schema = {
            "type": "object",
            "properties": {
                "price": {"type": "number"}
            }
        }
        assert verifier.verify({"price": 99.99}, schema)["is_valid"] == True
        assert verifier.verify({"price": "99.99"}, schema)["is_valid"] == False
    
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
        assert verifier.verify({"user": {"name": "John"}}, schema)["is_valid"] == True
        assert verifier.verify({"user": {}}, schema)["is_valid"] == False


class TestMathDelegation:
    """Test computed field verification."""
    
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
        assert result["is_valid"] == True
    
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
        assert any("math" in str(i).lower() for i in result["issues"])


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
        assert result["is_valid"] == True
    
    def test_ucp_transaction_total_mismatch(self, verifier):
        """UCP transaction with wrong total fails."""
        transaction = {
            "subtotal": 100.00,
            "tax": 10.00,
            "discount": 5.00,
            "total": 110.00  # Should be 105.00
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result["is_valid"] == False
        assert any("math" in str(i).lower() for i in result["issues"])
    
    def test_ucp_negative_amount(self, verifier):
        """UCP transaction with negative amount fails."""
        transaction = {
            "subtotal": -100.00,  # Invalid
            "tax": 10.00,
            "total": -90.00
        }
        result = verifier.verify_ucp_transaction(transaction)
        assert result["is_valid"] == False
    
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
        assert result["is_valid"] == True


class TestResultStructure:
    """Test verification result structure."""
    
    def test_result_has_required_fields(self, verifier):
        """Result should have all required fields."""
        schema = {"type": "string"}
        result = verifier.verify("test", schema)
        
        assert "is_valid" in result
        assert "status" in result
        assert "issues" in result
        assert "summary" in result
    
    def test_issue_structure(self, verifier):
        """Issue objects should have complete info."""
        schema = {"type": "number"}
        result = verifier.verify("not a number", schema)
        
        issue = result["issues"][0]
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
        
        assert result["summary"]["total_issues"] >= 2
        assert result["summary"]["errors"] >= 2


class TestEdgeCases:
    """Test edge cases and special scenarios."""
    
    def test_empty_object(self, verifier):
        """Empty object against minimal schema."""
        schema = {"type": "object"}
        result = verifier.verify({}, schema)
        assert result["is_valid"] == True
    
    def test_empty_array(self, verifier):
        """Empty array against minimal schema."""
        schema = {"type": "array"}
        result = verifier.verify([], schema)
        assert result["is_valid"] == True
    
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
        assert result["is_valid"] == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
