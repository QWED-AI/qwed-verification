# Architecture Decision Records

These ADRs freeze the **verification ontology** of the QWED Protocol — the
vocabulary and semantics every engine, API, and client speaks. They are the
category-level definition of *what verification is*, settled before
implementation so all engines align under one model.

Read in order; each builds on the previous.

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](ADR-001-object-of-verification.md) | The Object of Verification | Accepted |
| [ADR-002](ADR-002-verification-context.md) | The Verification Context | Accepted |
| [ADR-003](ADR-003-truth-vs-admission.md) | Truth vs Admission | Accepted |
| [ADR-004](ADR-004-formalization-boundary.md) | The Formalization Boundary | Accepted |
| [ADR-005](ADR-005-root-of-trust.md) | Root of Trust | Proposed |

## Core vocabulary (frozen)

- **Verified Object** — the formal statement being evaluated.
- **Verification Context** — everything required to interpret, reproduce, and
  trust a verification (interpretation, proof, evidence, decision).
- **VERIFIED / UNVERIFIABLE / BLOCKED** — the tri-state verdict.
- **Truth vs Admission** — VERIFIED is a truth guarantee, not a safe-to-run permit.
- **Formalization** — the NL→formal mapping; exposed but never verified.
- **proof_ref** — an evidence commitment, not a mathematical proof.
- **Admission** — the separate safe-to-run decision.
