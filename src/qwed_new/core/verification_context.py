from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass, replace
from enum import Enum
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

SPEC_VERSION = "1.0"
_PROOF_REF_PATTERN = re.compile(r"sha256:[a-f0-9]{64}")


class VerificationContextValidationError(ValueError):
    pass


_MISSING_BOUND_FIELD_ERRORS = (KeyError, TypeError, AttributeError)
_RESOLVER_ERRORS = (
    VerificationContextValidationError,
    *_MISSING_BOUND_FIELD_ERRORS,
)


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIABLE = "UNVERIFIABLE"
    BLOCKED = "BLOCKED"


class Admission(str, Enum):
    ADMIT = "ADMIT"
    DENY = "DENY"


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    return value


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_value(item) for item in value]
    return value


@dataclass(frozen=True)
class Formalization:
    verified: bool = False
    source_query: Optional[str] = None
    translator: Optional[str] = None
    translation_confidence: Optional[float] = None

    def __post_init__(self) -> None:
        if not isinstance(self.verified, bool) or self.verified is not False:
            raise VerificationContextValidationError(
                "object.formalization.verified must be false"
            )
        if self.translation_confidence is not None:
            if isinstance(self.translation_confidence, bool):
                raise VerificationContextValidationError(
                    "object.formalization.translation_confidence must be a number"
                )
            if not isinstance(self.translation_confidence, (int, float)):
                raise VerificationContextValidationError(
                    "object.formalization.translation_confidence must be a number"
                )
            confidence = float(self.translation_confidence)
            if not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise VerificationContextValidationError(
                    "object.formalization.translation_confidence must be between 0 and 1"
                )
            object.__setattr__(self, "translation_confidence", confidence)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"verified": False}
        if self.source_query is not None:
            out["source_query"] = self.source_query
        if self.translator is not None:
            out["translator"] = self.translator
        if self.translation_confidence is not None:
            out["translation_confidence"] = self.translation_confidence
        return out


@dataclass(frozen=True)
class VerifiedObject:
    formal_statement: str
    formalization: Optional[Formalization] = None

    def __post_init__(self) -> None:
        if not isinstance(self.formal_statement, str):
            raise VerificationContextValidationError(
                "object.formal_statement must be a string"
            )
        if not self.formal_statement.strip():
            raise VerificationContextValidationError(
                "object.formal_statement must be non-empty"
            )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"formal_statement": self.formal_statement}
        if self.formalization is not None:
            out["formalization"] = self.formalization.to_dict()
        return out


@dataclass(frozen=True)
class Interpretation:
    theory: Optional[str] = None
    logic: Optional[str] = None
    dialect: Optional[str] = None
    parser_version: Optional[str] = None
    language: Optional[str] = None
    policy_version: Optional[str] = None
    algebra_domain: Optional[str] = None

    def __post_init__(self) -> None:
        values = [
            self.theory,
            self.logic,
            self.dialect,
            self.parser_version,
            self.language,
            self.policy_version,
            self.algebra_domain,
        ]
        present = [value for value in values if value is not None]
        if not present:
            raise VerificationContextValidationError(
                "context.interpretation requires at least one field"
            )
        for value in present:
            if not isinstance(value, str) or not value.strip():
                raise VerificationContextValidationError(
                    "context.interpretation fields must be non-empty strings"
                )

    def to_dict(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if self.theory is not None:
            out["theory"] = self.theory
        if self.logic is not None:
            out["logic"] = self.logic
        if self.dialect is not None:
            out["dialect"] = self.dialect
        if self.parser_version is not None:
            out["parser_version"] = self.parser_version
        if self.language is not None:
            out["language"] = self.language
        if self.policy_version is not None:
            out["policy_version"] = self.policy_version
        if self.algebra_domain is not None:
            out["algebra_domain"] = self.algebra_domain
        return out


def _validate_proof_configuration(
    configuration: Optional[Mapping[str, Any]],
) -> Optional[Mapping[str, Any]]:
    if configuration is None:
        return None
    if not isinstance(configuration, Mapping):
        raise VerificationContextValidationError(
            "context.proof.configuration must be an object"
        )
    return _freeze_value(configuration)


def _validate_trusted_dependencies(
    dependencies: Optional[Tuple[str, ...]],
) -> Optional[Tuple[str, ...]]:
    if dependencies is None:
        return None
    if not isinstance(dependencies, (list, tuple)):
        raise VerificationContextValidationError(
            "context.proof.trusted_dependencies must be an array"
        )
    normalized = tuple(dependencies)
    for dependency in normalized:
        if not isinstance(dependency, str) or not dependency.strip():
            raise VerificationContextValidationError(
                "context.proof.trusted_dependencies must contain non-empty strings"
            )
    return normalized


@dataclass(frozen=True)
class Proof:
    verifier: str
    verifier_version: str
    configuration: Optional[Mapping[str, Any]] = None
    theory_scope: Optional[str] = None
    trusted_dependencies: Optional[Tuple[str, ...]] = None
    outcome_treatment: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.verifier, str) or not self.verifier.strip():
            raise VerificationContextValidationError(
                "context.proof.verifier must be non-empty"
            )
        if not isinstance(self.verifier_version, str) or not self.verifier_version.strip():
            raise VerificationContextValidationError(
                "context.proof.verifier_version must be non-empty"
            )
        object.__setattr__(
            self,
            "configuration",
            _validate_proof_configuration(self.configuration),
        )
        object.__setattr__(
            self,
            "trusted_dependencies",
            _validate_trusted_dependencies(self.trusted_dependencies),
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "verifier": self.verifier,
            "verifier_version": self.verifier_version,
        }
        if self.configuration is not None:
            out["configuration"] = _thaw_value(self.configuration)
        if self.theory_scope is not None:
            out["theory_scope"] = self.theory_scope
        if self.trusted_dependencies is not None:
            out["trusted_dependencies"] = list(self.trusted_dependencies)
        if self.outcome_treatment is not None:
            out["outcome_treatment"] = self.outcome_treatment
        return out


@dataclass(frozen=True)
class Evidence:
    payload: Mapping[str, Any]
    proof_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping):
            raise VerificationContextValidationError(
                "context.evidence.evidence must be an object"
            )
        object.__setattr__(self, "payload", _freeze_value(self.payload))
        if self.proof_ref is None:
            return
        if not isinstance(self.proof_ref, str):
            raise VerificationContextValidationError(
                "context.evidence.proof_ref must be a string"
            )
        if not _PROOF_REF_PATTERN.fullmatch(self.proof_ref):
            raise VerificationContextValidationError(
                "context.evidence.proof_ref must match ^sha256:[a-f0-9]{64}$"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence": _thaw_value(self.payload),
            "proof_ref": self.proof_ref,
        }


@dataclass(frozen=True)
class Decision:
    admission: Admission

    def __post_init__(self) -> None:
        if not isinstance(self.admission, Admission):
            raise VerificationContextValidationError(
                "context.decision.admission must be ADMIT or DENY"
            )

    def to_dict(self) -> Dict[str, str]:
        return {"admission": self.admission.value}


@dataclass(frozen=True)
class VerificationContext:
    interpretation: Interpretation
    proof: Proof
    evidence: Evidence
    decision: Decision

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interpretation": self.interpretation.to_dict(),
            "proof": self.proof.to_dict(),
            "evidence": self.evidence.to_dict(),
            "decision": self.decision.to_dict(),
        }


def _reject_unpaired_surrogates(value: str) -> None:
    for ch in value:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise VerificationContextValidationError(
                f"unpaired UTF-16 surrogate not allowed in proof_ref payload: {value!r}"
            )


def _parse_es_decimal(value: float) -> Tuple[int, int]:
    r = repr(abs(value))
    if "e" in r:
        mant, exp_s = r.split("e")
        e10 = int(exp_s)
    else:
        mant = r
        e10 = 0
    if "." in mant:
        ip, fp = mant.split(".")
        coeff = int(ip + fp) if (ip + fp).lstrip("0") else 0
        e10 -= len(fp)
    else:
        coeff = int(mant)
    while coeff > 0 and coeff % 10 == 0:
        coeff //= 10
        e10 += 1
    return coeff, e10


def _format_es_decimal(coeff: int, e10: int) -> str:
    if coeff == 0:
        return "0"
    s_digits = str(coeff)
    k = len(s_digits)
    n = e10 + k
    if k <= n <= 21:
        return s_digits + "0" * (n - k)
    if 0 < n <= 21:
        return s_digits[:n] + "." + s_digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s_digits
    exp = n - 1
    sign = "+" if exp >= 0 else "-"
    if k == 1:
        return s_digits + "e" + sign + str(abs(exp))
    return s_digits[0] + "." + s_digits[1:] + "e" + sign + str(abs(exp))


def _es_number_to_string(value: float) -> str:
    neg = value < 0
    coeff, e10 = _parse_es_decimal(value)
    out = _format_es_decimal(coeff, e10)
    if neg and out != "0":
        return "-" + out
    return out


def _canonical_json_int(value: int) -> str:
    try:
        as_float = float(value)
    except OverflowError as exc:
        raise VerificationContextValidationError(
            f"integer not representable as IEEE-754 double: {value!r}"
        ) from exc
    if int(as_float) != value:
        raise VerificationContextValidationError(
            f"integer not representable as IEEE-754 double: {value!r}"
        )
    return _es_number_to_string(as_float)


def _canonical_json_float(value: float) -> str:
    if not math.isfinite(value):
        raise VerificationContextValidationError(
            f"non-finite number not allowed in proof_ref payload: {value!r}"
        )
    return _es_number_to_string(value)


def _canonical_json_string(value: str) -> str:
    _reject_unpaired_surrogates(value)
    return json.dumps(value, ensure_ascii=False)


def _canonical_json_sequence(value: Any) -> str:
    return "[" + ",".join(_canonical_json(item) for item in value) + "]"


def _canonical_json_object(value: Mapping[Any, Any]) -> str:
    for key in value:
        if not isinstance(key, str):
            raise VerificationContextValidationError(
                f"non-string object key not allowed in proof_ref payload: {key!r}"
            )
        _reject_unpaired_surrogates(key)
    items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
    return (
        "{"
        + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + _canonical_json(v)
            for k, v in items
        )
        + "}"
    )


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return _canonical_json_int(value)
    if isinstance(value, float):
        return _canonical_json_float(value)
    if isinstance(value, str):
        return _canonical_json_string(value)
    if isinstance(value, (list, tuple)):
        return _canonical_json_sequence(value)
    if isinstance(value, Mapping):
        return _canonical_json_object(value)
    raise VerificationContextValidationError(
        f"unsupported type in proof_ref payload: {type(value).__name__}"
    )


def compute_context_proof_ref(
    formal_statement: str,
    context: VerificationContext,
) -> str:
    context_dict = context.to_dict()
    context_dict["evidence"] = {
        key: value
        for key, value in context_dict["evidence"].items()
        if key != "proof_ref"
    }
    bound = {
        "formal_statement": formal_statement,
        "context": context_dict,
    }
    payload = _canonical_json(bound)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerificationContextDocument:
    verified_object: VerifiedObject
    context: VerificationContext
    verdict: Verdict
    spec_version: str = SPEC_VERSION

    def __post_init__(self) -> None:
        if self.spec_version != SPEC_VERSION:
            raise VerificationContextValidationError(
                f"spec_version must be {SPEC_VERSION}"
            )
        if not isinstance(self.verdict, Verdict):
            raise VerificationContextValidationError(
                "verdict must be VERIFIED, UNVERIFIABLE, or BLOCKED"
            )
        proof_ref = self.context.evidence.proof_ref
        if self.verdict is Verdict.VERIFIED:
            if proof_ref is None:
                raise VerificationContextValidationError(
                    "VERIFIED requires context.evidence.proof_ref"
                )
            expected = compute_context_proof_ref(
                self.verified_object.formal_statement,
                self.context,
            )
            if proof_ref != expected:
                raise VerificationContextValidationError(
                    "VERIFIED proof_ref does not resolve against the bound payload"
                )
        else:
            if proof_ref is not None:
                raise VerificationContextValidationError(
                    f"{self.verdict.value} requires context.evidence.proof_ref to be null"
                )
            if self.context.decision.admission is not Admission.DENY:
                raise VerificationContextValidationError(
                    f"{self.verdict.value} requires admission DENY"
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spec_version": self.spec_version,
            "object": self.verified_object.to_dict(),
            "context": self.context.to_dict(),
            "verdict": self.verdict.value,
        }

    def validate(self) -> None:
        validate_document(self.to_dict())

    def is_valid(self) -> bool:
        return is_valid_document(self.to_dict())

    @classmethod
    def verified(
        cls,
        *,
        formal_statement: str,
        context: VerificationContext,
        formalization: Optional[Formalization] = None,
        proof_ref: Optional[str] = None,
    ) -> "VerificationContextDocument":
        expected = compute_context_proof_ref(formal_statement, context)
        if proof_ref is not None and proof_ref != expected:
            raise VerificationContextValidationError(
                "supplied proof_ref does not resolve against the bound payload"
            )
        evidence = Evidence(payload=context.evidence.payload, proof_ref=expected)
        context = replace(context, evidence=evidence)
        return cls(
            verified_object=VerifiedObject(
                formal_statement=formal_statement,
                formalization=formalization,
            ),
            context=context,
            verdict=Verdict.VERIFIED,
        )

    @classmethod
    def unverifiable(
        cls,
        *,
        formal_statement: str,
        context: VerificationContext,
        formalization: Optional[Formalization] = None,
    ) -> "VerificationContextDocument":
        return cls._fail_closed(
            Verdict.UNVERIFIABLE,
            formal_statement=formal_statement,
            context=context,
            formalization=formalization,
        )

    @classmethod
    def blocked(
        cls,
        *,
        formal_statement: str,
        context: VerificationContext,
        formalization: Optional[Formalization] = None,
    ) -> "VerificationContextDocument":
        return cls._fail_closed(
            Verdict.BLOCKED,
            formal_statement=formal_statement,
            context=context,
            formalization=formalization,
        )

    @classmethod
    def _fail_closed(
        cls,
        verdict: Verdict,
        *,
        formal_statement: str,
        context: VerificationContext,
        formalization: Optional[Formalization] = None,
    ) -> "VerificationContextDocument":
        evidence = Evidence(payload=context.evidence.payload, proof_ref=None)
        decision = Decision(admission=Admission.DENY)
        context = replace(context, evidence=evidence, decision=decision)
        return cls(
            verified_object=VerifiedObject(
                formal_statement=formal_statement,
                formalization=formalization,
            ),
            context=context,
            verdict=verdict,
        )


@lru_cache(maxsize=1)
def _schema_text() -> str:
    try:
        resource = resources.files("qwed_new.core.data").joinpath(
            "verification-context.schema.json"
        )
        return resource.read_text(encoding="utf-8")
    except Exception as exc:
        raise VerificationContextValidationError(
            "packaged Verification Context schema not found"
        ) from exc


def load_schema() -> Dict[str, Any]:
    try:
        return json.loads(_schema_text())
    except json.JSONDecodeError as exc:
        raise VerificationContextValidationError(
            "packaged Verification Context schema is invalid JSON"
        ) from exc


def _reject_non_finite_numbers(value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VerificationContextValidationError(
                f"non-finite number not allowed in Verification Context: {value!r}"
            )
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_non_finite_numbers(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_finite_numbers(item)


def _expected_document_proof_ref(document: Mapping[str, Any]) -> str:
    context_copy = {
        key: copy.deepcopy(value) for key, value in document["context"].items()
    }
    context_copy["evidence"] = {
        key: copy.deepcopy(value)
        for key, value in document["context"]["evidence"].items()
        if key != "proof_ref"
    }
    bound = {
        "formal_statement": document["object"]["formal_statement"],
        "context": context_copy,
    }
    payload = _canonical_json(bound)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_document_proof_ref(document: Mapping[str, Any]) -> str:
    if not isinstance(document, Mapping):
        raise VerificationContextValidationError(
            "Verification Context document must be a JSON object"
        )
    try:
        return _expected_document_proof_ref(document)
    except _MISSING_BOUND_FIELD_ERRORS as exc:
        raise VerificationContextValidationError(
            "bound payload is missing required Verification Context fields"
        ) from exc


def resolve_document_proof_ref(document: Mapping[str, Any]) -> bool:
    try:
        if not isinstance(document, Mapping):
            return False
        if document.get("verdict") != Verdict.VERIFIED.value:
            return False
        validate_document(document)
        expected = compute_document_proof_ref(document)
        stored = document["context"]["evidence"]["proof_ref"]
        return isinstance(stored, str) and stored == expected
    except _RESOLVER_ERRORS:
        return False


def resolve_context_proof_ref(
    formal_statement: str,
    context: VerificationContext,
    proof_ref: Optional[str],
) -> bool:
    if not isinstance(formal_statement, str):
        return False
    if not isinstance(context, VerificationContext):
        return False
    if not isinstance(proof_ref, str):
        return False
    try:
        return compute_context_proof_ref(formal_statement, context) == proof_ref
    except _RESOLVER_ERRORS:
        return False


def _validate_verified_commitment(document: Mapping[str, Any]) -> None:
    if document.get("verdict") != Verdict.VERIFIED.value:
        return
    expected = compute_document_proof_ref(document)
    try:
        proof_ref = document["context"]["evidence"]["proof_ref"]
    except Exception as exc:
        raise VerificationContextValidationError(
            "context.evidence.proof_ref is required for VERIFIED"
        ) from exc
    if not isinstance(proof_ref, str) or proof_ref != expected:
        raise VerificationContextValidationError(
            "context.evidence.proof_ref does not resolve against the bound payload"
        )


def validate_document(document: Mapping[str, Any]) -> None:
    if not isinstance(document, Mapping):
        raise VerificationContextValidationError(
            "Verification Context document must be a JSON object"
        )
    _reject_non_finite_numbers(document)
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise VerificationContextValidationError(
            "jsonschema is required for Verification Context validation"
        ) from exc

    validator = Draft202012Validator(load_schema())
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (
            "/".join(str(part) for part in error.path),
            str(error.validator),
            error.message,
        ),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path) or "<root>"
        raise VerificationContextValidationError(f"{path}: {first.message}")
    _validate_verified_commitment(document)


def is_valid_document(document: Mapping[str, Any]) -> bool:
    try:
        validate_document(document)
        return True
    except VerificationContextValidationError:
        return False
