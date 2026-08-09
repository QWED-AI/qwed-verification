from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

SPEC_VERSION = "1.0"
_PROOF_REF_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


class VerificationContextValidationError(ValueError):
    pass


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIABLE = "UNVERIFIABLE"
    BLOCKED = "BLOCKED"


class Admission(str, Enum):
    ADMIT = "ADMIT"
    DENY = "DENY"


@dataclass(frozen=True)
class Formalization:
    verified: bool = False
    source_query: Optional[str] = None
    translator: Optional[str] = None
    translation_confidence: Optional[float] = None

    def __post_init__(self) -> None:
        if self.verified is not False:
            raise VerificationContextValidationError(
                "object.formalization.verified must be false"
            )
        if self.translation_confidence is not None:
            if isinstance(self.translation_confidence, bool):
                raise VerificationContextValidationError(
                    "object.formalization.translation_confidence must be a number"
                )
            if not 0 <= self.translation_confidence <= 1:
                raise VerificationContextValidationError(
                    "object.formalization.translation_confidence must be between 0 and 1"
                )

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
        if not self.formal_statement or not self.formal_statement.strip():
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
            if not value.strip():
                raise VerificationContextValidationError(
                    "context.interpretation fields must be non-empty"
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


@dataclass(frozen=True)
class Proof:
    verifier: str
    verifier_version: str
    configuration: Optional[Dict[str, Any]] = None
    theory_scope: Optional[str] = None
    trusted_dependencies: Optional[List[str]] = None
    outcome_treatment: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.verifier or not self.verifier.strip():
            raise VerificationContextValidationError(
                "context.proof.verifier must be non-empty"
            )
        if not self.verifier_version or not self.verifier_version.strip():
            raise VerificationContextValidationError(
                "context.proof.verifier_version must be non-empty"
            )
        if self.configuration is not None and not isinstance(self.configuration, dict):
            raise VerificationContextValidationError(
                "context.proof.configuration must be an object"
            )
        if self.trusted_dependencies is not None:
            for dependency in self.trusted_dependencies:
                if not isinstance(dependency, str) or not dependency.strip():
                    raise VerificationContextValidationError(
                        "context.proof.trusted_dependencies must contain non-empty strings"
                    )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "verifier": self.verifier,
            "verifier_version": self.verifier_version,
        }
        if self.configuration is not None:
            out["configuration"] = self.configuration
        if self.theory_scope is not None:
            out["theory_scope"] = self.theory_scope
        if self.trusted_dependencies is not None:
            out["trusted_dependencies"] = list(self.trusted_dependencies)
        if self.outcome_treatment is not None:
            out["outcome_treatment"] = self.outcome_treatment
        return out


@dataclass(frozen=True)
class Evidence:
    evidence: Dict[str, Any]
    proof_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, dict):
            raise VerificationContextValidationError(
                "context.evidence.evidence must be an object"
            )
        if self.proof_ref is not None and not _PROOF_REF_PATTERN.match(self.proof_ref):
            raise VerificationContextValidationError(
                "context.evidence.proof_ref must match ^sha256:[a-f0-9]{64}$"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence": self.evidence,
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

    def validate(self, schema: Optional[Mapping[str, Any]] = None) -> None:
        validate_document(self.to_dict(), schema=schema)

    def is_valid(self, schema: Optional[Mapping[str, Any]] = None) -> bool:
        return is_valid_document(self.to_dict(), schema=schema)

    @classmethod
    def verified(
        cls,
        *,
        formal_statement: str,
        context: VerificationContext,
        proof_ref: str,
        formalization: Optional[Formalization] = None,
    ) -> "VerificationContextDocument":
        evidence = Evidence(evidence=context.evidence.evidence, proof_ref=proof_ref)
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
        evidence = Evidence(evidence=context.evidence.evidence, proof_ref=None)
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


def _default_schema_path() -> Path:
    path = (
        Path(__file__).resolve().parents[3]
        / "spec"
        / "v1.0"
        / "schemas"
        / "verification-context.schema.json"
    )
    if path.exists():
        return path
    return (
        Path.cwd()
        / "spec"
        / "v1.0"
        / "schemas"
        / "verification-context.schema.json"
    )


@lru_cache(maxsize=1)
def _load_schema_cached(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_schema(schema_path: Optional[Path] = None) -> Dict[str, Any]:
    path = schema_path or _default_schema_path()
    if not path.exists():
        raise VerificationContextValidationError(
            f"Verification Context schema not found: {path}"
        )
    return _load_schema_cached(str(path))


def validate_document(
    document: Mapping[str, Any],
    schema: Optional[Mapping[str, Any]] = None,
) -> None:
    if not isinstance(document, Mapping):
        raise VerificationContextValidationError(
            "Verification Context document must be a JSON object"
        )
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise VerificationContextValidationError(
            "jsonschema is required for Verification Context validation"
        ) from exc

    schema_obj = dict(schema) if schema is not None else load_schema()
    validator = Draft202012Validator(schema_obj)
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: "/".join(str(part) for part in error.path),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path) or "<root>"
        raise VerificationContextValidationError(f"{path}: {first.message}")


def is_valid_document(
    document: Mapping[str, Any],
    schema: Optional[Mapping[str, Any]] = None,
) -> bool:
    try:
        validate_document(document, schema=schema)
        return True
    except VerificationContextValidationError:
        return False
