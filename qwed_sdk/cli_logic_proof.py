# Copyright (c) 2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""The logic proofs `qwed test` runs, and what counts as one (#660).

`qwed test` decides two claims from the premise x > 5 with the DSL engine, one
that follows and one that does not. A line is VERIFIED only when the engine
proves or refutes its claim and the verdict `/verify/logic` would return for
that answer is VERIFIED with a proof_ref bound to its evidence. A satisfiable
set of constraints is not a proof, so it is never reported as VERIFIED.
"""

from dataclasses import dataclass
from typing import Any

LOGIC_LABEL_UNSAT = "x>5 AND x<3"
# The two logic proofs share the premise x > 5 and decide one claim each (#660).
# A satisfiable set of constraints is not a proof, so `qwed test` no longer
# reports one as VERIFIED.
LOGIC_LABEL_VALID = "x>5 => x>3"
LOGIC_LABEL_INVALID = "x>5 => x>10"
LOGIC_PREMISE_DSL = "(GT x 5)"
LOGIC_CLAIM_VALID_DSL = "(GT x 3)"
LOGIC_CLAIM_INVALID_DSL = "(GT x 10)"
# x > 5 does not imply x > 10; the values of x that show it are 5 < x <= 10.
# Z3 may return any of them, so the check accepts the set, not one value.
LOGIC_COUNTEREXAMPLES = frozenset(str(value) for value in range(6, 11))


@dataclass(frozen=True)
class LogicProof:
    """What the DSL engine answered for one claim, and the verdict `/verify/logic`
    would return for that answer (#660)."""

    result: Any
    verdict: Any


def prove_logic_claim(engine, claim_dsl: str) -> LogicProof:
    """Decide one claim from the premise x > 5, for every integer x (#660).

    The engine's answer goes through the mapping `/verify/logic` uses, so a
    line is VERIFIED only when that verdict is VERIFIED and carries a
    proof_ref bound to its evidence (QWED_RULES.md). Fields the engine left
    unset are not passed: the mapping reads a missing one as its default.
    """
    from qwed_new.core.route_diagnostics import logic_diagnostic

    result = engine.prove_from_dsl(LOGIC_PREMISE_DSL, claim_dsl, [{"name": "x", "type": "Int"}])
    fields = {
        "status": result.status,
        "model": result.model,
        "dsl_code": result.dsl_code,
        "error": result.error,
        "constraint_id": result.constraint_id,
        "declarations": result.declarations,
    }
    return LogicProof(result, logic_diagnostic({name: value for name, value in fields.items() if value is not None}))


def _logic_verdict_has_proof(proof: LogicProof) -> bool:
    from qwed_new.core.diagnostics import DiagnosticStatus

    return proof.verdict.status == DiagnosticStatus.VERIFIED and bool(proof.verdict.proof_ref)


def logic_claim_follows(proof: LogicProof) -> bool:
    # Only a proof counts: SAT, VACUOUS, UNKNOWN, ERROR and BLOCKED do not.
    return proof.result.status == "VALID" and _logic_verdict_has_proof(proof)


def logic_claim_refuted(proof: LogicProof) -> bool:
    # A counterexample is a value of x that holds the premise and breaks the claim,
    # and the verdict is the proven-false one: VERIFIED with is_valid False.
    value = (proof.result.model or {}).get("x")
    return (
        proof.result.status == "INVALID"
        and isinstance(value, str)
        and value in LOGIC_COUNTEREXAMPLES
        and _logic_verdict_has_proof(proof)
        and proof.verdict.developer_fields.get("is_valid") is False
    )


def logic_proof_detail(proof: LogicProof) -> str:
    """The engine's own words for a line, so a failure can be told from an error."""
    result = proof.result
    parts = [f"status={result.status}"]
    if result.status == "INVALID":
        parts.append(f"counterexample x={(result.model or {}).get('x')}")
    for name, value in (("error", result.error), ("constraint_id", result.constraint_id)):
        if value:
            parts.append(f"{name}={value}")
    return ", ".join(parts)
