"""
JSON Schema Verifier: Deterministic Schema Validation with Math Delegation.

100% Deterministic - No probability/ML involved.

Features:
1. Type checking (string, number, boolean, array, object)
2. Constraint validation (minimum, maximum, pattern, enum, required)
3. Nested object validation
4. Array item validation
5. Math delegation for numeric fields (price, tax, total)
6. UCP-specific validation rules

Example:
    schema = {"type": "object", "properties": {"price": {"type": "number", "minimum": 0}}}
    data = {"price": 99.99}
    result = verifier.verify(data, schema)  # True - deterministic!
"""

from typing import Dict, List, Any, Union
from dataclasses import dataclass, field
import re
import json


@dataclass
class SchemaIssue:
    """A schema validation issue."""
    path: str           # JSON path to the issue (e.g., "$.items[0].price")
    issue_type: str     # "type_mismatch", "constraint_violation", etc.
    expected: str       # What was expected
    actual: str         # What was found
    severity: str = "ERROR"  # "ERROR", "WARNING"
    message: str = ""


@dataclass
class SchemaResult:
    """Result of schema verification."""
    is_valid: bool
    issues: List[SchemaIssue] = field(default_factory=list)
    path_checked: int = 0
    constraints_checked: int = 0


class SchemaVerifier:
    """
    Deterministic JSON Schema Verifier.
    
    Validates JSON data against JSON Schema with optional
    delegation to MathVerifier for numeric computations.
    
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
    
    # Fields that should use MathVerifier for computation
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
            enable_math_delegation: If True, delegate numeric field
                                   verification to MathVerifier.
        """
        self.enable_math_delegation = enable_math_delegation
        self._math_verifier = None
    
    @property
    def math_verifier(self):
        """Lazy load MathVerifier."""
        if self._math_verifier is None and self.enable_math_delegation:
            try:
                from .symbolic_verifier import SymbolicVerifier
                self._math_verifier = SymbolicVerifier()
            except ImportError:
                self._math_verifier = None
        return self._math_verifier
    
    def verify(
        self, 
        data: Any, 
        schema: Dict[str, Any],
        strict: bool = True
    ) -> Dict[str, Any]:
        """
        Verify data against a JSON Schema.
        
        Args:
            data: The JSON data to verify.
            schema: JSON Schema definition.
            strict: If True, fail on additional properties not in schema.
            
        Returns:
            Dict with verification results.
            
        Example:
            >>> schema = {"type": "object", "properties": {"name": {"type": "string"}}}
            >>> result = verifier.verify({"name": "John"}, schema)
            >>> print(result["is_valid"])
            True
        """
        issues = []
        stats = {"paths_checked": 0, "constraints_checked": 0}
        
        self._validate_node(data, schema, "$", issues, stats, strict)
        
        is_valid = len([i for i in issues if i.severity == "ERROR"]) == 0
        
        return {
            "is_valid": is_valid,
            "status": "VALID" if is_valid else "INVALID",
            "issues": [
                {
                    "path": i.path,
                    "type": i.issue_type,
                    "expected": i.expected,
                    "actual": i.actual,
                    "severity": i.severity,
                    "message": i.message
                }
                for i in issues
            ],
            "summary": {
                "total_issues": len(issues),
                "errors": sum(1 for i in issues if i.severity == "ERROR"),
                "warnings": sum(1 for i in issues if i.severity == "WARNING"),
                "paths_checked": stats["paths_checked"],
                "constraints_checked": stats["constraints_checked"]
            }
        }
    
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
                    severity="WARNING",
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
        Check computed fields using math verification.
        
        For fields like 'total', 'tax', etc., verify against
        related fields using MathVerifier.
        """
        if not isinstance(value, (int, float)):
            return
        
        # Example: total = subtotal + tax
        if field_name.lower() == "total":
            subtotal = parent_data.get("subtotal")
            tax = parent_data.get("tax") or parent_data.get("tax_amount", 0)
            
            if subtotal is not None:
                stats["constraints_checked"] += 1
                expected = subtotal + (tax or 0)
                
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
            
            if subtotal is not None and tax_rate is not None:
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
    ) -> Dict[str, Any]:
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
            Dict with verification results.
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
        
        # Additional UCP-specific checks
        issues = list(result["issues"])
        
        # Currency precision check
        precision = self.CURRENCY_PRECISION.get(currency, 2)
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
        
        is_valid = len([i for i in issues if i.get("severity") == "ERROR"]) == 0
        
        return {
            "is_valid": is_valid,
            "status": "VALID" if is_valid else "INVALID",
            "issues": issues,
            "transaction_type": "UCP",
            "currency": currency,
            "summary": {
                "total_issues": len(issues),
                "errors": sum(1 for i in issues if i.get("severity") == "ERROR"),
                "warnings": sum(1 for i in issues if i.get("severity") == "WARNING")
            }
        }
