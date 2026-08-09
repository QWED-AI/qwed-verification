# ADR-001: The Object of Verification

**Status:** Accepted
**Decided:** via adversarial architecture review (category-level)

## Context

The design discussion evolved from *"how do we prevent fail-open?"* to *"what
counts as VERIFIED?"* to *"truth vs admission"* and finally to the foundational
question: **"What is the object being verified?"**

Until this question is answered precisely, the category's language is not mature.
A deterministic proof is always *of something*; if we do not name that something,
every downstream claim ("VERIFIED", "proof", "trust") is ambiguous.

## Decision

> **The Verified Object is the formal statement being evaluated.**
>
> **The Verification Context is all information required to correctly interpret,
> reproduce, and trust that verification.**

- **Object** → the formal statement, e.g. `∀x. x + 0 = x` or `x² − 4 = 0`.
- **Context** → interpretation, proof mechanism, evidence, and decision (defined
  fully in [ADR-002](ADR-002-verification-context.md)).

Changing the prover does not change the semantic proposition **when both provers
encode the same proposition under equivalent theories and encodings** (e.g. Lean vs
Coq proving the same theorem). Prover independence is **semantic, not textual** — a
different logic, axiom set, or formal encoding can change the proposition, so the
formal encoding and Verification Context remain necessary to interpret and
reproduce the object.

## The theory is required interpretation context

A formal statement is only *meaningful* relative to a theory/interpretation:
`x² = 4` over the reals, over integers mod 5, and over bitvectors are different
propositions. Therefore the **theory/logic/dialect** belongs in the Verification
Context as **required interpretation context** — it gives the object meaning, but
it is not the object itself.

This keeps the ontology uniform across engines: a theorem prover declares a
theory, SQL declares a dialect, code declares a language+policy, symbolic math
declares an algebra domain. No engine is forced to invent a "theory" it lacks.

## The formalization is exposed but never verified

QWED never claims *"we verified your intent."* It only claims *"we verified THIS
formal statement."* The mapping from natural language to the formal statement (the
**formalization**) is surfaced in the response for confirmation but is never itself
verified. See [ADR-004](ADR-004-formalization-boundary.md).

## Rejected alternatives

- **"VERIFIED binds to the translation."** Conflates the object with the process
  that produced it.
- **"VERIFIED binds to the original natural-language claim."** Natural language is
  not mathematically provable; promising this is dishonest.
- **"The theory belongs to the object."** Breaks uniformity across engines and
  conflates meaning-supplier with the object. The theory is required *context*.
- **"The Verification Context is the atomic unit."** Conflates the object with the
  record that describes it. The object is the statement; the context is metadata.

## Consequences

- Every `VERIFIED` result carries an explicit formal statement the user can read.
- The verified object is unambiguous and engine-independent.
- Downstream consumers can always answer *"verified by what, under what theory,
  with what evidence?"* via the Verification Context.
