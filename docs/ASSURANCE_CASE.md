# Security Assurance Case

## Overview

This document explains why we believe QWED meets its security requirements, and where it does not yet. It covers the threat model, trust boundaries, design principles and countermeasures. Each control states its current status; known gaps link to the issue or advisory that tracks them. Last reviewed: October 2026 (v7.2.2).

## 1. Threat Model

### Trust Boundaries
- **Untrusted**:
    - LLM output (non-deterministic and possibly wrong or adversarial)
    - User input (queries, prompts, uploaded data)
    - External data fetched by engines
- **Trusted**:
    - QWED verification engines and policy guards, as far as their own correctness allows (see the [security advisories](https://github.com/QWED-AI/qwed-verification/security/advisories) for past soundness and injection bugs)
    - The control plane
    - PII detection (Presidio), in the Python SDK when the optional `qwed[pii]` extra is installed

### Primary Threats
1.  **Prompt injection**: user input manipulating the LLM to bypass verification.
2.  **Code injection**: model output that reaches an evaluator (`sympify`, `parse_expr`, `eval`) or executes code.
3.  **Denial of service**: inputs that make an engine consume excessive CPU or memory.
4.  **Data leakage**: sensitive data sent to an external LLM provider.

## 2. Secure Design Principles

### Least Privilege
- Untrusted expressions are parsed only through `safe_parse_expr` (character and AST allow-lists, builtins stripped, cost-bounded); `scripts/check_boundary.py` blocks raw `eval`, `exec`, `sympify` and shell calls outside approved files in CI.
- Generated code is executed only through `SecureCodeExecutor`. Sandbox hardening is still open: [#322](https://github.com/QWED-AI/qwed-verification/issues/322), [#431](https://github.com/QWED-AI/qwed-verification/issues/431).

### Complete Mediation
- QWED is a library and API: it mediates only the outputs an integrator sends through it. Deployments must route model output through QWED before acting on it.

### Defense in Depth
1.  **Input validation**: most API routes validate input with Pydantic models; four routes in `api/main.py` (including `/verify/math`) accept a raw JSON object and check fields by hand. Request-size limits are incomplete: [#230](https://github.com/QWED-AI/qwed-verification/issues/230), [#392](https://github.com/QWED-AI/qwed-verification/issues/392).
2.  **PII masking**: optional (`qwed[pii]`, `mask_pii=True`) in the Python SDK; off by default.
3.  **Static analysis**: CodeQL, SonarCloud and Snyk run on the repository.
4.  **Runtime limits**: compute bounds in the math parser and logic/DSL engines were added in 7.2.2 ([GHSA-mxwv-x5qm-mrmf](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-mxwv-x5qm-mrmf)); remaining resource-exhaustion paths are tracked in [#331](https://github.com/QWED-AI/qwed-verification/issues/331) and [#391](https://github.com/QWED-AI/qwed-verification/issues/391).

## 3. Countermeasures

| Weakness | Mitigation | Status |
| :--- | :--- | :--- |
| **Injection** | Untrusted expressions go through `safe_parse_expr`; raw evaluators are blocked by the CI boundary gate. | Implemented. Three code-injection advisories were fixed in 5.1.2, 7.2.1 and 7.2.2 ([GHSA-q27q-98j4-9pfv](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-q27q-98j4-9pfv), [GHSA-xmm6-8r3x-j567](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-xmm6-8r3x-j567), [GHSA-4v5r-g7f4-vvgc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-4v5r-g7f4-vvgc)). |
| **Credentials** | Provider API keys come from environment variables; QWED API keys are stored hashed. | Partial: a Redis URL including its password is logged ([#228](https://github.com/QWED-AI/qwed-verification/issues/228)); expired API keys are still accepted ([#389](https://github.com/QWED-AI/qwed-verification/issues/389)). |
| **XML exploits** | The server and SDK do not parse XML. | Not applicable |
| **Insecure deserialization** | No `pickle` on untrusted data; JSON is the interchange format. | Implemented |
| **Vulnerable dependencies** | Dependabot and Snyk scanning; dependency updates are reviewed as pull requests. | Implemented |

## 4. Verification

Security controls are checked by:
- **CI**: the test suite, `scripts/check_boundary.py`, CodeQL, SonarCloud and Snyk.
- **Tests**: security-focused tests in `tests/security/` and across `tests/`.
- **External reports**: private vulnerability reporting; see [SECURITY.md](../SECURITY.md) and the published advisories.
- **Open work**: the [security tracker issues](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity).
