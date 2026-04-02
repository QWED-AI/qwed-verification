# QWED Enforcement Rules

QWED is not a conventional application. It is a deterministic verification and
enforcement boundary.

These rules are non-negotiable for contributors, reviewers, and automation
tools operating on this repository.

## Core Principles

1. No fallback execution
   - If verification fails, execution must stop.
   - Do not add `eval`, `exec`, or fallback logic as a backup path.

2. Fail closed
   - Block on verification or enforcement failure.
   - Availability is secondary to correctness and containment.

3. Verification before execution
   - No execution path may bypass verification.
   - No exceptions for "safe enough" shortcuts.

4. No trust in model output
   - LLM outputs are untrusted inputs.
   - Do not trust model-provided expected values, reasoning, confidence, or
     metadata as proof.

5. Security is mandatory
   - Guards must be server-side and mandatory.
   - User input must not decide whether enforcement runs.

6. No silent handling
   - Do not suppress verification or enforcement errors.
   - Do not auto-correct, auto-retry, or continue in ways that weaken the
     boundary.

7. Default deny
   - Unknown tools, inputs, and flows must be treated as high risk and blocked
     until explicitly verified.

## Forbidden Suggestions

- "Add fallback for reliability"
- "Gracefully handle failure by continuing execution"
- "Use eval/exec as backup"
- "Trust model output if confidence is high"
- "Retry automatically until success"
- "Allow temporary bypass until the verifier is available"

## Decision Rule

If a change improves usability, convenience, or availability but weakens
enforcement, reject the change.

Priority order:

1. Determinism
2. Safety
3. Control
4. Everything else
