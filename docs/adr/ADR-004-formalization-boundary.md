# ADR-004: The Formalization Boundary

**Status:** Accepted
**Decided:** via adversarial architecture review (category-level)

## Context

Verification has two steps:

1. **Formalization** — map the natural-language claim to a formal statement
   (currently LLM-driven).
2. **Discharge** — prove/discharge the formal statement (SymPy/Z3 — deterministic
   and sound *for the formal statement*).

The hard, error-prone step is **formalization**, and it is **not deterministic and
not verified**. A deterministic solver applied to a mistranslated statement yields a
*correct proof of the wrong question.* QWED must not hide this.

## Decision

> **The formalization (NL → formal) is exposed for confirmation but is never itself
> verified.**

- The **translator is untrusted** and sits **outside the trust boundary.** It
  produces a *claim candidate*, not a verified claim.
- `VERIFIED` binds to the **formal statement**, never to the original natural
  language (see [ADR-001](ADR-001-object-of-verification.md)).
- The response **surfaces the formal statement** (and a non-authoritative
  translation-confidence note) so a human can confirm *"this is what was proven —
  does it match my intent?"*

```text
Natural language  →  Formalization  →  Formal statement  →  Deterministic proof  →  VERIFIED
   (untrusted)        (unverified)        (the object)        (sound, if definitive)
```

QWED never claims *"we verified your intent."* It claims *"we verified THIS formal
statement."*

## The determinism is in the discharge, not the formalization

QWED's determinism applies to the **discharge** (the solver). The end-to-end system
is only as sound as the formalization. Treating the translator as untrusted is
*necessary but not sufficient*; the load-bearing guarantee is that the verdict is
scoped to the formal statement and the formalization is surfaced for confirmation.

**Scope of the soundness/determinism claim:** it holds only for **supported
configurations** (declared theory, verifier, version, and options) and only for
**definitive proof outcomes.** Solver results that are `unknown`, `timeout`, or
`error` are not sound, deterministic proofs and are never `VERIFIED`; they resolve
to `UNVERIFIABLE` or `BLOCKED` (fail-closed). Not every verifier result is a proof.

## Open problem

**Reliable formalization is the unsolved hard problem.** A deterministic verifier
cannot fix a wrong translation. Future work must either (a) make formalization
reliable/checked, or (b) keep the human-in-the-loop confirmation of the formal
statement. Until then, `VERIFIED` is always scoped to the formal statement.

## Rejected alternatives

- **Trust the translator.** A wrong translation silently produces a wrong VERIFIED.
- **Claim VERIFIED for the original NL.** NL is not provable; dishonest.
- **Hide the formal statement.** Removes the only mechanism a user has to detect a
  mistranslation.

## Consequences

- Users always see *what* was proven and can catch mistranslations.
- QWED's honesty is well-defined: it verifies formal statements, not intent.
- The formalization problem is named and tracked, not papered over.
