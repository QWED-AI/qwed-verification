# QWED Enforcement Rules

QWED is not a conventional application. It is a deterministic verification and
enforcement boundary.

These rules are non-negotiable for contributors, reviewers, and automation
tools operating on this repository.

## Core Principles

### 1. Verification Before Execution

No execution path may bypass verification. Every operation that produces output
or triggers a side effect must first pass a deterministic verification gate.
No exceptions for "safe enough" shortcuts.

### 2. Fail Closed

If verification or enforcement fails—for any reason—the operation must block.
Availability is secondary to correctness and containment. A false positive
(rejecting a valid request) is always preferable to a false negative (passing
an invalid one).

### 3. Deterministic Decisions

All enforcement decisions must be based on deterministic rules—not scoring,
confidence thresholds, heuristics, or probabilistic models. If two independent
runs of the enforcement logic on the same input could produce different results,
the design is wrong.

### 4. Explicit Boundaries

Every security or verification boundary must be explicitly defined at the
architectural level. Implicit boundaries (e.g., "the LLM will not output X
because we prompted it not to") are not boundaries. A boundary must be
testable, measurable, and auditable.

### 5. Approved Paths Only

Sensitive operations (code execution, shell commands, database mutation) must
be routed through explicit, pre-approved wrapper functions. Direct calls to
`eval`, `exec`, `os.system`, `subprocess.Popen`, or raw `parse_expr` are
forbidden outside the approved wrappers.

### 6. No Silent Degradation

If a component cannot fulfill its enforcement responsibility, it must fail
loudly. Do not suppress errors. Do not auto-correct, auto-retry, or continue
execution in a degraded mode. Silent degradation is a vulnerability in waiting.

### 7. Security Boundaries Are First-Class

Security and verification boundaries are not optional features. They must be
on by default, server-side, and not configurable or bypassable by user input.
The user cannot opt out of enforcement.

### 8. Verify Claims, Not Sources

Claims must be verified by deterministic computation (SymPy, Z3, pgTAP,
SQLGlot), not by the source of the claim. LLM outputs, confidence scores,
reasoning chains, and metadata are inputs to the verification pipeline—they
are not proof. Trust comes from deterministic verification, not from origin.

### 9. Ecosystem Neutrality

QWED rules apply regardless of the model provider, framework, or deployment
environment. No LLM-specific behavior may be relied upon for enforcement -
only documented, deterministic behaviors.

### 10. Hardening Over Features

Hardening, boundary enforcement, and vulnerability mitigation take priority
over feature velocity. Treat security debt as functional debt. Do not trade
long-term safety for short-term convenience.

### 11. Vulnerability Family Thinking

Do not patch individual symptoms; fix the vulnerability family. When a single
`eval`-like pattern is found, assume the entire category of similar bypasses
is exploitable until proven otherwise by an explicit, deterministic guard.

### 12. Existing Issues Must Survive New Boundaries

Introducing a new boundary or security layer must not reduce the severity of
existing, unfixed security issues. All existing vulnerabilities retain their
priority until resolved. New enforcement layers are additive, not
substitutional.

## Forbidden Suggestions

- "Add fallback for reliability"
- "Gracefully handle failure by continuing execution"
- "Use eval/exec as backup"
- "Trust model output if confidence is high"
- "Retry automatically until success"
- "Allow temporary bypass until the verifier is available"
- "Score LLM outputs and accept if above N% confidence"
- "Rely on system prompt to prevent X from happening"

## Decision Rule

If a change improves usability, convenience, or availability but weakens
enforcement, reject the change.

Priority order:

1. Determinism
2. Safety
3. Control
4. Everything else
