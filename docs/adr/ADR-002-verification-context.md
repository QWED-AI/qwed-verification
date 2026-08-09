# ADR-002: The Verification Context

**Status:** Accepted
**Decided:** via adversarial architecture review (category-level)

## Context

A bare formal statement is not a verification. To interpret, reproduce, and trust
a verification you need to know *what it means*, *how it was proven*, *on what
evidence*, and *what decision followed*. [ADR-001](ADR-001-object-of-verification.md)
established the object (the formal statement); this ADR defines the context that
accompanies it.

## Definition: proof_ref

Defined once, used everywhere:

> **`proof_ref`** is an immutable commitment to the verification evidence. It
> provides **evidence integrity and reproducibility**. It is **not itself the
> mathematical proof.**

`proof_ref` is one field of the Verification Context — the evidence-integrity
field. It is not the center of the model and it is not a proof of truth.

### What it binds

`proof_ref` commits to the **formal statement together with the complete
Verification Context** required to interpret and reproduce the verification —
interpretation (theory/logic/dialect), proof (verifier + version + config), and
the evidence itself. Changing any of these changes the commitment.

### How it is computed

- **Canonical encoding:** the bound payload is serialized with a deterministic,
  canonical encoding (stable key ordering, no ambient/non-deterministic fields
  such as wall-clock time or memory addresses).
- **Commitment algorithm:** a cryptographic hash (SHA-256) of the canonical
  encoding, expressed as `sha256:<hex>`.

### Resolution and failure semantics

- A consumer **resolves** `proof_ref` by re-deriving the commitment from the
  supplied formal statement + Verification Context + evidence and comparing it to
  the stored value.
- **Missing, malformed, or mismatched** evidence/commitment is treated as
  **unverified (fail-closed)** — never as verified. A `proof_ref` that cannot be
  resolved confers no authority.

## Decision: the Verification Context is layered

The Verification Context has four layers:

| Layer | Contents | Role |
|-------|----------|------|
| **Interpretation** | theory / logic / dialect / algebra domain | Gives the object meaning (required to interpret) |
| **Proof** | verifier + version + config + theory scope + trusted deps | How the object was discharged; sets proof strength |
| **Evidence** | evidence + `proof_ref` | What was checked; evidence integrity / reproducibility |
| **Decision** | admission | The safe-to-run outcome (see [ADR-003](ADR-003-truth-vs-admission.md)) |

The **verifier is the trusted computing base.** A proof discharged by SymPy (large
TCB) is a different-strength guarantee than one checked by Lean/Coq (small trusted
kernel). Declaring the verifier declares how much to trust the proof.

### The verifier trust boundary is explicit

Naming the verifier is not enough by itself; the Proof layer records the full trust
boundary, so a consumer knows exactly what is being trusted:

- **Verifier + version** — the exact engine and release.
- **Configuration** — solver flags, timeouts, resource limits, and any options that
  affect the outcome.
- **Theory scope** — the logic / axiom set / theory the discharge is relative to.
- **Trusted dependencies/components** — libraries and sub-components inside the TCB.
- **Non-definitive outcomes** — how `unknown`, `timeout`, and `error` results are
  treated. These are **never** `VERIFIED`; they resolve to `UNVERIFIABLE` or
  `BLOCKED` (fail-closed). Soundness/determinism claims apply **only** to supported
  configurations that produce a definitive proof outcome.

## Principle

> **Every `VERIFIED` result must declare the Verification Context required to
> interpret and reproduce the proof.**

This requirement is **vacuous for engines that never emit `VERIFIED`** (advisory
engines such as Fact, Image, Reasoning). Each engine exposes only the context it
needs:

- Theorem prover → theory, logic, solver
- SQL → SQL dialect, parser version
- Code → language, verifier, policy version
- Symbolic math → algebra domain

## Interoperability

**Deferred to a later ADR.** Constraint adopted now: structure the Verification
Context so it can later be made interoperable with external standards (proof
certificates / attestation bundles); do not paint into a corner. No specific
standard is committed here — that is a strategy decision, not an architecture one.

## Rejected alternatives

- **`proof_ref` as the center of the model.** It is one field (evidence integrity),
  not the atomic unit.
- **Flat context.** The layered structure makes the *required interpretation* layer
  explicit and keeps the theory load-bearing without forcing it on every engine.

## Consequences

- A `VERIFIED` result is always accompanied by an interpretable, reproducible
  context.
- Proof strength is legible (verifier = TCB).
- The model is engine-agnostic and future-proof beyond symbolic mathematics.
