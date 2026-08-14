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

from typing import Any, ClassVar, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import math
import re
import json

from qwed_new.core.diagnostics import DiagnosticResult

from .verification_context import VerificationContextDocument


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


def _set_to_sorted_list(o: Any) -> Any:
    """json.dumps default: canonicalize sets to sorted lists; reject the rest.

    A member with a hostile ``__repr__`` (one that raises) must not let its
    exception escape unconverted: it is wrapped as ``TypeError`` so the
    evidence-normalization path returns the documented ``ValueError`` instead.
    """
    if isinstance(o, (set, frozenset)):
        try:
            return sorted(o, key=repr)
        except Exception as exc:  # noqa: BLE001 - hostile __repr__ must not escape
            raise TypeError("unsupported evidence value in set") from exc
    raise TypeError(f"unsupported evidence type: {type(o).__name__}")


# Reused across calls: constructing a JSONEncoder per proof is pure overhead.
# Settings match json.dumps(..., sort_keys=True, default=_set_to_sorted_list),
# so the serialized bytes — and therefore every proof_ref — are unchanged.
# encode() keeps no state between calls (fresh cycle markers per invocation).
# allow_nan=False rejects NaN/±inf floats with ValueError, because NaN /
# Infinity / -Infinity are not valid JSON tokens for proof evidence.
_EVIDENCE_ENCODER = json.JSONEncoder(sort_keys=True, allow_nan=False, default=_set_to_sorted_list)


def _evidence_proof_data(evidence: Dict[str, Any]) -> str:
    """Serialize proof evidence to a canonical JSON string for proof_ref.

    Fails closed (raises ValueError) on unsupported values, non-string dict
    keys, or cycles so proof-bearing evidence never contains process-dependent
    representations (e.g. ``repr`` of arbitrary objects embeds memory
    addresses, making proof_ref unstable across processes). Sets are
    canonicalized to sorted lists.

    Cycles and unsupported types are detected by the encoder itself (it tracks
    containers along the current path and routes unknown types through
    ``_set_to_sorted_list``), so the fail-closed pre-pass reduces to the one
    check the encoder does not make: non-string mapping keys.

    Raises:
        ValueError: if the evidence contains a cycle, a non-string key, a
            non-finite float, or an unsupported type.
    """
    try:
        proof_data = _EVIDENCE_ENCODER.encode(evidence)
    except ValueError as exc:  # circular reference or NaN/±inf rejected by the encoder
        raise ValueError("cyclic or non-finite value cannot be serialized into proof evidence") from exc
    except (TypeError, RecursionError) as exc:
        raise ValueError("proof evidence could not be serialized deterministically") from exc
    _assert_string_keys(evidence)
    return proof_data


def _assert_string_keys(evidence: Any) -> None:
    """Reject non-string mapping keys anywhere in the proof evidence.

    ``json`` silently coerces int/float/bool/None keys to strings, so
    ``{1: "a"}`` and ``{"1": "a"}`` would collapse onto the same proof_ref.
    Called only after serialization succeeded, which guarantees the structure
    is acyclic and JSON-safe — a flat stack walk over dicts/lists/tuples is
    then sufficient (sets and frozensets cannot contain a dict, since dicts
    are unhashable).

    Raises:
        ValueError: on a non-string dict key.
    """
    stack: List[Any] = [evidence]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            _assert_key_strings(node, stack)
        elif isinstance(node, (list, tuple)):
            _extend_stack_containers(stack, node)


def _assert_key_strings(node: Dict[str, Any], stack: List[Any]) -> None:
    """Reject non-str dict keys, and queue each value for container traversal."""
    for key, value in node.items():
        if not isinstance(key, str):
            raise ValueError(
                "non-string key in evidence object: "
                f"expected str, got {type(key).__name__}"
            )
        if isinstance(value, (dict, list, tuple)):
            stack.append(value)


def _extend_stack_containers(stack: List[Any], node: Any) -> None:
    """Queue the dict/list/tuple children of a list/tuple for traversal."""
    for value in node:
        if isinstance(value, (dict, list, tuple)):
            stack.append(value)


def _is_finite_number(value: Any) -> bool:
    """True for finite, non-bool ``int``/``float`` schema values.

    ``int`` is finite by construction; routing it through ``math.isfinite``
    would raise OverflowError for values beyond float range (e.g. 10**1000).
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


# Schema keywords grouped by the shape check they share, so meta-validation
# can dispatch on the keys the schema actually declares.
_NUMERIC_BOUND_KEYWORDS = frozenset(
    {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"}
)
_SIZE_KEYWORDS = frozenset(
    {"minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"}
)
_STRING_KEYWORDS = frozenset({"pattern", "format"})

# Local decimal precision used when quantizing UCP total amounts. Generous so
# schema-accepted amounts of any magnitude (e.g. 1e300) never raise
# Decimal.InvalidOperation under the default 28-digit context.
_UCP_TOTAL_PRECISION = 400

# Max entries in the per-instance schema-shape cache before it is cleared.
_SHAPE_CACHE_MAX = 128




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
        # Schema meta-shape validation results, keyed by the schema's canonical
        # serialization. Content-keyed (not identity-keyed) so in-place schema
        # mutation invalidates the entry and every verify applies the schema's
        # current contents. Bounded: cleared when exceeding the budget.
        self._shape_cache: Dict[str, List[str]] = {}
    
    def verify(
        self, 
        data: Any, 
        schema: Dict[str, Any],
        strict: bool = True,
        currency: Optional[str] = None
    ) -> DiagnosticResult:
        """
        Verify data against a JSON Schema.
        
        Args:
            data: The JSON data to verify.
            schema: JSON Schema definition.
            strict: If True, fail on additional properties not in schema.
            currency: When set, inline computed-total math checks quantize
                to the currency's declared precision (ROUND_HALF_EVEN) so a
                legitimately currency-rounded total is not rejected. Used by
                ``verify_ucp_transaction`` to keep the generic total check
                consistent with the currency-aware UCP check.
            
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
            schema_errors = self._schema_shape_errors(schema)
        except Exception as exc:  # noqa: BLE001 - fail closed on any unexpected error
            return DiagnosticResult.blocked(
                "Schema verification blocked: an unexpected validation error occurred",
                {
                    "constraint_id": _CONSTRAINT_ID_VALIDATION_ERROR,
                    "error_type": type(exc).__name__,
                },
            )
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
            self._validate_node(data, schema, "$", issues, stats, strict, currency)
        except Exception as exc:  # noqa: BLE001 - fail closed on any unexpected error
            return DiagnosticResult.blocked(
                "Schema verification blocked: an unexpected validation error occurred",
                {
                    "constraint_id": _CONSTRAINT_ID_VALIDATION_ERROR,
                    "error_type": type(exc).__name__,
                },
            )

        # Single pass: serialize the issues and tally severities together.
        serialized_issues = []
        error_count = 0
        warning_count = 0
        for i in issues:
            severity = i.severity
            if severity == "ERROR":
                error_count += 1
            elif severity == "WARNING":
                warning_count += 1
            serialized_issues.append({
                "path": i.path,
                "type": i.issue_type,
                "expected": i.expected,
                "actual": i.actual,
                "severity": severity,
                "message": i.message,
            })

        is_valid = error_count == 0

        developer_fields = {
            "constraint_id": (
                _CONSTRAINT_ID_SCHEMA_VALID if is_valid
                else _CONSTRAINT_ID_SCHEMA_VIOLATION
            ),
            "is_valid": is_valid,
            "issues": serialized_issues,
            "summary": {
                "total_issues": len(issues),
                "errors": error_count,
                "warnings": warning_count,
                "paths_checked": stats["paths_checked"],
                "constraints_checked": stats["constraints_checked"],
            },
        }

        schema_evidence = {
            "schema": schema,
            "instance": data,
            "verdict": "VALID" if is_valid else "INVALID",
            "issues": serialized_issues,
            "paths_checked": stats["paths_checked"],
            "constraints_checked": stats["constraints_checked"],
        }
        try:
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

        Dispatch table keeps per-keyword checks as small validators so the
        loop stays flat; recursion handles nested sub-schemas.
        """
        if not isinstance(schema, dict):
            return [f"{path}: schema must be a dict, got {type(schema).__name__}"]

        errors: List[str] = []
        for keyword, value in schema.items():
            errors.extend(self._shape_check(keyword, value, path))
        return errors

    def _schema_shape_errors(self, schema: Any) -> List[str]:
        """Return shape-validation errors for a schema, cached by content.

        Schemas are caller-owned and mutable, so an identity-keyed cache would
        serve stale results after an in-place mutation (e.g. ``schema`` edited
        between ``verify`` calls). The cache is keyed by the canonical
        serialization of the schema instead: any mutation changes the key and
        forces revalidation, while repeated identical schemas skip the
        recursive meta-validation walk. Schemas that cannot be serialized
        (cycles, non-finite values) are validated directly without caching.
        The cache is bounded: when it exceeds ``_SHAPE_CACHE_MAX`` entries it
        is cleared and rebuilt lazily.
        """
        try:
            schema_key = _EVIDENCE_ENCODER.encode(schema)
        except (TypeError, ValueError, RecursionError):
            try:
                return self._validate_schema_shape(schema)
            except RecursionError:
                return ["$: recursive schema definition"]
        cached = self._shape_cache.get(schema_key)
        if cached is not None:
            return cached
        try:
            errors = self._validate_schema_shape(schema)
        except RecursionError:
            errors = ["$: recursive schema definition"]
        if len(self._shape_cache) >= _SHAPE_CACHE_MAX:
            self._shape_cache.clear()
        self._shape_cache[schema_key] = errors
        return errors

    def _shape_check(self, keyword: str, value: Any, path: str) -> List[str]:
        """Dispatch a keyword to its shape validator, or a shared keyword group."""
        checker = self._SHAPE_DISPATCH.get(keyword)
        if checker is not None:
            return checker(self, keyword, value, path)
        if keyword in _NUMERIC_BOUND_KEYWORDS:
            return self._shape_numeric_bound(keyword, value, path)
        if keyword in _SIZE_KEYWORDS:
            return self._shape_size(keyword, value, path)
        if keyword in _STRING_KEYWORDS:
            return self._shape_string(keyword, value, path)
        return []

    def _shape_type(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate the type keyword: a string or non-empty list of known types."""
        if isinstance(value, str):
            return [] if value in self.TYPE_MAP else [f"{path}.{keyword}: unknown type {value!r}"]
        if isinstance(value, list):
            if value and all(isinstance(t, str) and t in self.TYPE_MAP for t in value):
                return []
            return [f"{path}.{keyword}: must be a list of valid types"]
        return [f"{path}.{keyword}: must be a string or list of strings"]

    def _shape_properties(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate properties: dict mapping names to schema dicts, recursing."""
        if not isinstance(value, dict):
            return [f"{path}.{keyword}: must be a dict"]
        errors: List[str] = []
        for prop_name, prop_schema in value.items():
            if isinstance(prop_schema, dict):
                errors.extend(self._validate_schema_shape(prop_schema, f"{path}.{keyword}.{prop_name}"))
            else:
                errors.append(f"{path}.{keyword}.{prop_name}: must be a schema dict")
        return errors

    def _shape_required(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate required: must be a list of strings."""
        if isinstance(value, list) and all(isinstance(r, str) for r in value):
            return []
        return [f"{path}.{keyword}: must be a list of strings"]

    def _shape_items(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate items: must be a schema dict; recurses into it."""
        if isinstance(value, dict):
            return self._validate_schema_shape(value, f"{path}.{keyword}")
        return [f"{path}.{keyword}: must be a schema dict"]

    def _shape_additional_properties(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate additionalProperties: bool or schema dict; recurses into dicts."""
        if isinstance(value, dict):
            return self._validate_schema_shape(value, f"{path}.{keyword}")
        if isinstance(value, bool):
            return []
        return [f"{path}.{keyword}: must be a bool or schema dict"]

    def _shape_prefix_items(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate prefixItems: must be a list of schema dicts; recurses."""
        if not isinstance(value, list):
            return [f"{path}.{keyword}: must be a list of schemas"]
        errors: List[str] = []
        for i, item_schema in enumerate(value):
            if isinstance(item_schema, dict):
                errors.extend(self._validate_schema_shape(item_schema, f"{path}.{keyword}[{i}]"))
            else:
                errors.append(f"{path}.{keyword}[{i}]: must be a schema dict")
        return errors

    def _shape_enum(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate enum: must be a list."""
        return [] if isinstance(value, list) else [f"{path}.{keyword}: must be a list"]

    def _shape_numeric_bound(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate numeric bounds (minimum/maximum/exclusive*): finite number."""
        if _is_finite_number(value):
            return []
        return [f"{path}.{keyword}: must be a finite number"]

    def _shape_multiple_of(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate multipleOf: must be a finite positive number."""
        if _is_finite_number(value) and value > 0:
            return []
        return [f"{path}.{keyword}: must be a finite positive number"]

    def _shape_size(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate size keywords (minLength/maxItems/etc.): non-negative int."""
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return []
        return [f"{path}.{keyword}: must be a non-negative integer"]

    def _shape_string(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate string keywords (pattern/format); pattern must also compile."""
        if not isinstance(value, str):
            return [f"{path}.{keyword}: must be a string"]
        if keyword == "pattern":
            try:
                re.compile(value)
            except re.error:
                return [f"{path}.{keyword}: must be a valid regular expression"]
        return []

    def _shape_unique_items(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate uniqueItems: must be a bool."""
        return [] if isinstance(value, bool) else [f"{path}.{keyword}: must be a bool"]

    def _shape_composition_list(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate allOf/anyOf/oneOf: a non-empty list of schema dicts."""
        sub_path = f"{path}.{keyword}"
        if not isinstance(value, list) or not value:
            return [f"{sub_path}: must be a non-empty list of schemas"]
        errors: List[str] = []
        for i, sub in enumerate(value):
            if isinstance(sub, dict):
                errors.extend(self._validate_schema_shape(sub, f"{sub_path}[{i}]"))
            else:
                errors.append(f"{sub_path}[{i}]: must be a schema dict")
        return errors

    def _shape_not(self, keyword: str, value: Any, path: str) -> List[str]:
        """Validate not: must be a schema dict."""
        if isinstance(value, dict):
            return self._validate_schema_shape(value, f"{path}.{keyword}")
        return [f"{path}.{keyword}: must be a schema dict"]

    # Function-object dispatch for schema meta-validation; built once at class
    # load time so the lookup is a plain dict get() — no runtime getattr.
    _SHAPE_DISPATCH: ClassVar[Dict[str, Any]] = {
        "type": _shape_type,
        "properties": _shape_properties,
        "required": _shape_required,
        "items": _shape_items,
        "additionalProperties": _shape_additional_properties,
        "prefixItems": _shape_prefix_items,
        "enum": _shape_enum,
        "multipleOf": _shape_multiple_of,
        "uniqueItems": _shape_unique_items,
        "allOf": _shape_composition_list,
        "anyOf": _shape_composition_list,
        "oneOf": _shape_composition_list,
        "not": _shape_not,
    }

    def _validate_node(
        self,
        data: Any,
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int],
        strict: bool,
        currency: Optional[str] = None
    ) -> None:
        """Recursively validate a node against its schema."""
        stats["paths_checked"] += 1
        
        # Handle schema references — fail closed on unresolved $ref.
        # Without a schema registry, the referenced sub-schema cannot be
        # validated, so the result would silently skip constraints.
        if "$ref" in schema:
            issues.append(SchemaIssue(
                path=path,
                issue_type="unresolved_ref",
                expected="resolvable $ref",
                actual=str(schema["$ref"]),
                severity="ERROR",
                message=f"Unresolved $ref: {schema['$ref']} (no schema registry configured)"
            ))
            return  # Cannot validate further without the referenced schema
        
        # Type validation
        if "type" in schema:
            self._check_type(data, schema["type"], path, issues, stats)
        
        # Enum validation
        if "enum" in schema:
            self._check_enum(data, schema["enum"], path, issues, stats)
        
        # Const validation
        if "const" in schema:
            self._check_const(data, schema["const"], path, issues, stats)
        
        # Type-specific validations. For union types ("type": [..]), resolve
        # the concrete type the runtime value matches and apply that type's
        # constraints, so e.g. {"type": ["string", "null"], "minLength": 5}
        # still enforces minLength on string values. When the schema omits
        # ``type`` altogether, JSON Schema still requires the applicable
        # keyword constraints to run against data of the matching runtime
        # type (a ``required``/``properties`` subschema inside ``not`` must
        # still reject a dict missing the required keys). Dispatch therefore
        # falls back to the data's runtime type — but only when no type was
        # declared: when a type WAS declared and the data did not match it,
        # the type_mismatch ERROR above already accounted for the violation
        # and running the type's constraints on mismatched data would error
        # or double-count.
        schema_type = schema.get("type")
        resolved_type = self._resolve_schema_type(schema_type, data)
        if resolved_type is None and schema_type is None:
            resolved_type = self._runtime_type(data)

        if resolved_type == "string":
            self._validate_string(data, schema, path, issues, stats)

        elif resolved_type in ("number", "integer"):
            self._validate_number(data, schema, path, issues, stats)

        elif resolved_type == "array":
            self._validate_array(data, schema, path, issues, stats, strict, currency)

        elif resolved_type == "object":
            self._validate_object(data, schema, path, issues, stats, strict, currency)

        # Composition keywords (allOf/anyOf/oneOf/not) apply independently of
        # the concrete type and must be evaluated — they cannot be silently
        # skipped (a schema that passed shape meta-validation may still carry
        # composition constraints that the data violates).
        self._check_composition(data, schema, path, issues, stats, strict, currency)

    def _check_composition(
        self,
        data: Any,
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int],
        strict: bool,
        currency: Optional[str] = None
    ) -> None:
        """Evaluate JSON Schema composition keywords against the data.

        Dispatches to per-keyword handlers. Shape meta-validation (which runs
        before any ``_validate_node``) guarantees ``allOf``/``anyOf``/``oneOf``
        are non-empty lists of schema dicts and ``not`` is a schema dict, so the
        handlers rely on that invariant.
        """
        all_of = schema.get("allOf")
        if isinstance(all_of, list) and all_of:
            self._check_all_of(data, all_of, path, issues, stats, strict, currency)

        any_of = schema.get("anyOf")
        if isinstance(any_of, list) and any_of:
            self._check_any_of(data, any_of, path, issues, stats, strict, currency)

        one_of = schema.get("oneOf")
        if isinstance(one_of, list) and one_of:
            self._check_one_of(data, one_of, path, issues, stats, strict, currency)

        not_schema = schema.get("not")
        if isinstance(not_schema, dict):
            self._check_not(data, not_schema, path, issues, stats, strict, currency)

    def _probe_subschema(
        self, data: Any, sub: Dict[str, Any], sub_path: str,
        strict: bool, currency: Optional[str]
    ) -> Tuple[List[SchemaIssue], Dict[str, int]]:
        """Validate ``data`` against one subschema in isolation.

        Probe validations (anyOf/oneOf/not) must not inflate the caller's
        evidence metrics: only the subschema that actually contributes to the
        final verdict has its stats merged back. Returns (issues, probe_stats).
        """
        probe_stats = {"paths_checked": 0, "constraints_checked": 0}
        sub_issues: List[SchemaIssue] = []
        self._validate_node(data, sub, sub_path, sub_issues, probe_stats, strict, currency)
        return sub_issues, probe_stats

    def _merge_stats(self, target: Dict[str, int], source: Dict[str, int]) -> None:
        """Add ``source`` stats into ``target``."""
        target["paths_checked"] += source["paths_checked"]
        target["constraints_checked"] += source["constraints_checked"]

    def _check_all_of(
        self, data: Any, subschemas: List[Dict[str, Any]], path: str,
        issues: List[SchemaIssue], stats: Dict[str, int], strict: bool,
        currency: Optional[str]
    ) -> None:
        """allOf: every subschema must pass; collect each subschema's issues."""
        stats["constraints_checked"] += 1
        for i, sub in enumerate(subschemas):
            if not isinstance(sub, dict):
                continue
            sub_issues, probe_stats = self._probe_subschema(
                data, sub, f"{path}.allOf[{i}]", strict, currency
            )
            self._merge_stats(stats, probe_stats)
            issues.extend(sub_issues)

    def _check_any_of(
        self, data: Any, subschemas: List[Dict[str, Any]], path: str,
        issues: List[SchemaIssue], stats: Dict[str, int], strict: bool,
        currency: Optional[str]
    ) -> None:
        """anyOf: at least one subschema must pass (first match wins)."""
        stats["constraints_checked"] += 1
        for i, sub in enumerate(subschemas):
            if not isinstance(sub, dict):
                continue
            sub_issues, probe_stats = self._probe_subschema(
                data, sub, f"{path}.anyOf[{i}]", strict, currency
            )
            if not any(iss.severity == "ERROR" for iss in sub_issues):
                self._merge_stats(stats, probe_stats)
                return
        self._append_composition_issue(
            path, issues, "anyOf_match_failed", "at least one matching subschema", "none"
        )

    def _check_one_of(
        self, data: Any, subschemas: List[Dict[str, Any]], path: str,
        issues: List[SchemaIssue], stats: Dict[str, int], strict: bool,
        currency: Optional[str]
    ) -> None:
        """oneOf: exactly one subschema must pass."""
        stats["constraints_checked"] += 1
        passed = 0
        winner_stats: Optional[Dict[str, int]] = None
        for i, sub in enumerate(subschemas):
            if not isinstance(sub, dict):
                continue
            sub_issues, probe_stats = self._probe_subschema(
                data, sub, f"{path}.oneOf[{i}]", strict, currency
            )
            if not any(iss.severity == "ERROR" for iss in sub_issues):
                passed += 1
                winner_stats = probe_stats
        if passed == 1 and winner_stats is not None:
            self._merge_stats(stats, winner_stats)
        elif passed != 1:
            self._append_composition_issue(
                path, issues, "oneOf_match_failed",
                "exactly one matching subschema", f"{passed}",
            )

    def _check_not(
        self, data: Any, not_schema: Dict[str, Any], path: str,
        issues: List[SchemaIssue], stats: Dict[str, int], strict: bool,
        currency: Optional[str]
    ) -> None:
        """not: the subschema must fail (data must not satisfy it)."""
        stats["constraints_checked"] += 1
        sub_issues, probe_stats = self._probe_subschema(
            data, not_schema, f"{path}.not", strict, currency
        )
        if not any(iss.severity == "ERROR" for iss in sub_issues):
            self._append_composition_issue(
                path, issues, "not_violation", "not subschema to fail", "subschema passed"
            )
        else:
            # The subschema failed as required — its validation is the path
            # that satisfied ``not``, so its stats count.
            self._merge_stats(stats, probe_stats)

    def _append_composition_issue(
        self,
        path: str,
        issues: List[SchemaIssue],
        issue_type: str,
        expected: str,
        actual: str,
    ) -> None:
        """Append an ERROR composition violation (deterministic)."""
        issues.append(SchemaIssue(
            path=path,
            issue_type=issue_type,
            expected=expected,
            actual=actual,
            message=f"{path}: composition {issue_type} (expected {expected}, got {actual})",
        ))
    
    def _resolve_schema_type(self, schema_type: Any, data: Any) -> Optional[str]:
        """Resolve which concrete JSON type a runtime value matches within a
        single-type or union-type schema declaration (None if no match)."""
        if schema_type is None:
            return None
        type_names = schema_type if isinstance(schema_type, list) else [schema_type]
        for type_name in type_names:
            if self._is_type(data, type_name):
                return type_name
        return None

    def _runtime_type(self, data: Any) -> Optional[str]:
        """Return the JSON type name matching a runtime value, or None.

        Used to dispatch type-specific keyword constraints when a schema omits
        ``type`` (so a typeless ``required`` subschema still validates a dict).
        Mirrors ``_is_type`` precedence: bool is not recognized as number.
        """
        if isinstance(data, bool):
            return "boolean"
        if isinstance(data, str):
            return "string"
        if isinstance(data, int):
            return "integer"
        if isinstance(data, float):
            return "number"
        if isinstance(data, list):
            return "array"
        if isinstance(data, dict):
            return "object"
        if data is None:
            return "null"
        return None
    
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
                    message="String does not match pattern"
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
        strict: bool,
        currency: Optional[str] = None
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

        # prefixItems (tuple validation) - validates the leading elements.
        prefix_len = 0
        if "prefixItems" in schema:
            prefix = schema["prefixItems"]
            prefix_len = len(prefix)
            for i, item_schema in enumerate(prefix):
                if i < len(data):
                    self._validate_node(data[i], item_schema, f"{path}[{i}]", issues, stats, strict, currency)

        # items (single schema for the remaining elements after the prefix).
        if "items" in schema and isinstance(schema["items"], dict):
            for i, item in enumerate(data[prefix_len:], start=prefix_len):
                self._validate_node(item, schema["items"], f"{path}[{i}]", issues, stats, strict, currency)
    
    def _validate_object(
        self,
        data: Dict[str, Any],
        schema: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int],
        strict: bool,
        currency: Optional[str] = None
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
                self._validate_node(value, properties[key], prop_path, issues, stats, strict, currency)
                
                # Check for math delegation
                if self.enable_math_delegation and key.lower() in self.MATH_FIELDS:
                    self._check_math_field(key, value, data, prop_path, issues, stats, currency)
            
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
                self._validate_node(value, additional, prop_path, issues, stats, strict, currency)
        
        # minProperties
        if "minProperties" in schema:
            stats["constraints_checked"] += 1
            if len(data) < schema["minProperties"]:
                issues.append(SchemaIssue(
                    path=path,
                    issue_type="constraint_violation",
                    expected=f"minProperties {schema['minProperties']}",
                    actual=f"{len(data)} properties",
                    message="Object has too few properties"
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
                    message="Object has too many properties"
                ))
    
    def _check_math_field(
        self,
        field_name: str,
        value: Any,
        parent_data: Dict[str, Any],
        path: str,
        issues: List[SchemaIssue],
        stats: Dict[str, int],
        currency: Optional[str] = None
    ) -> None:
        """
        Check computed fields using inline arithmetic consistency.
        
        For fields like 'total', 'tax', etc., verify against
        related fields using exact Decimal comparison (no float noise).
        When a currency is supplied, the total is compared at that
        currency's declared precision with ROUND_HALF_EVEN — the same
        quantization UCP uses — so a currency-rounded total (e.g. USD
        subtotal=1.005 with total=1.00) is not rejected by the generic
        check before the currency-aware one runs.
        """
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return
        
        # Example: total = subtotal + tax - discount
        if field_name.lower() == "total":
            subtotal = parent_data.get("subtotal")
            tax = parent_data["tax"] if "tax" in parent_data else parent_data.get("tax_amount", 0)
            discount = parent_data.get("discount", 0)
            
            if (
                subtotal is not None
                and isinstance(subtotal, (int, float)) and not isinstance(subtotal, bool)
                and isinstance(tax, (int, float)) and not isinstance(tax, bool)
                and isinstance(discount, (int, float)) and not isinstance(discount, bool)
            ):
                stats["constraints_checked"] += 1
                expected = (
                    Decimal(str(subtotal)) + Decimal(str(tax)) - Decimal(str(discount))
                )
                actual = Decimal(str(value))
                
                # Currency-aware comparisons quantize both operands to the
                # currency precision (half-even) before comparing. Without a
                # currency we fall back to exact Decimal comparison.
                actual = self._quantize_currency_amount(actual, currency)
                expected = self._quantize_currency_amount(expected, currency)
                
                # Exact Decimal comparison; operand scales are preserved in messages.
                if actual != expected:
                    issues.append(SchemaIssue(
                        path=path,
                        issue_type="math_verification_failed",
                        expected=str(expected),
                        actual=str(actual),
                        message=f"Total mismatch: expected {expected}, got {actual}"
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
                expected = Decimal(str(subtotal)) * Decimal(str(tax_rate))
                actual = Decimal(str(value))
                
                # Apply the same currency-aware quantization as the total
                # branch so a legitimately rounded tax (e.g. 7.00 from
                # 7.00035) is not rejected for a currency payload.
                actual = self._quantize_currency_amount(actual, currency)
                expected = self._quantize_currency_amount(expected, currency)
                
                if actual != expected:
                    issues.append(SchemaIssue(
                        path=path,
                        issue_type="math_verification_failed",
                        expected=str(expected),
                        actual=str(actual),
                        message=f"Tax mismatch: expected {expected}, got {actual}"
                    ))
    
    def _quantize_currency_amount(self, amount: Decimal, currency: Optional[str]) -> Decimal:
        """Quantize a Decimal amount to the currency's precision using
        ROUND_HALF_EVEN, matching UCP. Uses ``_ucp_precision`` so unlisted
        currencies fall back to two decimals exactly as UCP does — without a
        currency, the amount is returned unchanged (exact comparison)."""
        if not isinstance(currency, str):
            return amount
        precision = self._ucp_precision(currency)
        quant = Decimal(1).scaleb(-precision)
        with localcontext() as ctx:
            ctx.prec = _UCP_TOTAL_PRECISION
            return amount.quantize(quant, rounding=ROUND_HALF_EVEN)

    def _check_ucp_business_rules(
        self,
        transaction: Dict[str, Any],
        currency: str,
        issues: List[Dict[str, Any]]
    ) -> None:
        """Run UCP-specific consistency checks (currency precision, computed total).

        ``currency`` is the effective currency — already resolved by the caller
        from the transaction's declared ``currency`` field (or the argument).
        """
        self._check_ucp_currency_precision(transaction, currency, issues)
        self._check_ucp_computed_total(transaction, currency, issues)

    def _ucp_precision(self, currency: str) -> int:
        """Resolve currency code to declared decimal precision."""
        return self.CURRENCY_PRECISION.get(currency, 2) if isinstance(currency, str) else 2

    def _check_ucp_currency_precision(
        self,
        transaction: Dict[str, Any],
        currency: str,
        issues: List[Dict[str, Any]]
    ) -> None:
        """Appends a WARNING issue when an amount exceeds the currency precision."""
        precision = self._ucp_precision(currency)
        for field in ["subtotal", "tax", "discount", "total"]:
            if field in transaction:
                value = transaction[field]
                if isinstance(value, float):
                    # Derive scale from Decimal exponent so scientific notation
                    # (e.g. 1e-07) and large integral floats (e.g. 1e16) count
                    # their true decimal places instead of parsing str().
                    exponent = Decimal(str(value)).normalize().as_tuple().exponent
                    decimal_places = -exponent if isinstance(exponent, int) and exponent < 0 else 0
                    if decimal_places > precision:
                        issues.append({
                            "path": f"$.{field}",
                            "type": "currency_precision",
                            "expected": f"max {precision} decimal places for {currency}",
                            "actual": f"{decimal_places} decimal places",
                            "severity": "WARNING",
                            "message": f"Currency precision exceeded for {currency}"
                        })

    def _check_ucp_computed_total(
        self,
        transaction: Dict[str, Any],
        currency: str,
        issues: List[Dict[str, Any]]
    ) -> None:
        """Verify total = subtotal + tax - discount using exact Decimal arithmetic."""
        precision = self._ucp_precision(currency)
        quant = Decimal(1).scaleb(-precision)
        
        subtotal = transaction.get("subtotal", 0)
        tax = transaction.get("tax", 0)
        discount = transaction.get("discount", 0)
        total = transaction.get("total", 0)
        
        # Quantize under a local context with a precision generous enough for
        # schema-accepted amounts (e.g. 1e300), so quantize does not raise
        # Decimal.InvalidOperation at the default 28-digit context.
        with localcontext() as ctx:
            ctx.prec = _UCP_TOTAL_PRECISION
            expected_total = Decimal(str(subtotal)) + Decimal(str(tax)) - Decimal(str(discount))
            expected_total = expected_total.quantize(quant, rounding=ROUND_HALF_EVEN)
            actual = Decimal(str(total)).quantize(quant, rounding=ROUND_HALF_EVEN)
        
        if actual != expected_total:
            issues.append({
                "path": "$.total",
                "type": "math_verification_failed",
                "expected": f"{expected_total:.{precision}f}",
                "actual": f"{actual:.{precision}f}",
                "severity": "ERROR",
                "message": (
                    f"Total mismatch: {subtotal} + {tax} - {discount} = "
                    f"{expected_total:.{precision}f}, got {actual:.{precision}f}"
                )
            })
    
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
        
        # The transaction may declare its own currency (e.g. "JPY"). Resolve
        # the effective currency ONCE so validation, developer fields, and
        # proof evidence all report and use the same value — otherwise the
        # reported currency would contradict the precision rules actually
        # applied (CodeRabbit/Sentry/Greptile). Guard for non-dict payloads.
        declared_currency = (
            transaction.get("currency") if isinstance(transaction, dict) else None
        )
        effective_currency = (
            declared_currency if isinstance(declared_currency, str) else currency
        )

        result = self.verify(transaction, schema, strict=False, currency=effective_currency)
        # Fail closed: pass through BLOCKED results as-is. Every other path
        # (whether the base verdict was valid or a deterministic violation)
        # must still produce UCP-shaped developer_fields (transaction_type,
        # currency, ucp constraint ids) so downstream consumers never hit a
        # KeyError.
        if not result.is_verified:
            return result
        
        # Additional UCP-specific checks (issue dicts, JSON-safe).
        # Base violations are preserved — they are already structured issues.
        issues = list(result.developer_fields["issues"])
        base_valid = result.developer_fields.get("is_valid", True)
        
        # Only run UCP arithmetic when the mapping is usable — the base schema
        # already flagged unusable types, and arithmetic would otherwise raise
        # TypeError/AttributeError.
        if base_valid and isinstance(transaction, dict):
            try:
                self._check_ucp_business_rules(transaction, effective_currency, issues)
            except Exception as exc:  # noqa: BLE001 - fail closed on any unexpected error
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
            "currency": effective_currency,
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
                "currency": effective_currency,
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

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="SchemaVerifier",
        )



