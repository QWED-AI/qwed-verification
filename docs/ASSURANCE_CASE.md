# Security Assurance Case

## Overview

This document explains why we believe QWED meets its security requirements, and where it does not yet. It covers the threat model, trust boundaries, design principles and countermeasures. Each control states its current status; known gaps link to the issue or advisory that tracks them. Last reviewed: October 2026 (v8.0.0).

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
5.  **Unsound verification**: a check that returns `VERIFIED` for a false or unsafe claim, so the integrator acts on it. For a verification library this is the most serious failure.

## 2. Secure Design Principles

### Least Privilege
- Untrusted expressions are parsed only through `safe_parse_expr` (character and AST allow-lists, builtins stripped, cost-bounded); `scripts/check_boundary.py` blocks raw `eval`, `exec`, `sympify` and shell calls outside approved files in CI.
- Generated code is executed only through `SecureCodeExecutor`, which in 7.3.0 isolates the execution namespace behind a capability allowlist (safe builtins only and a guarded `__import__` limited to an allowlist of analysis modules) rather than a static denylist ([GHSA-j3x4-v3p2-4mq3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-j3x4-v3p2-4mq3), completing [GHSA-6rxr-gq43-694g](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-6rxr-gq43-694g)). In 8.0.0 the sandbox runs a digest-pinned image in a hardened container ([#322](https://github.com/QWED-AI/qwed-verification/issues/322)), and the Symbolic engine runs CrossHair only inside it ([#431](https://github.com/QWED-AI/qwed-verification/issues/431)).

### Fail-Safe Defaults
- An engine that cannot settle a claim returns a fail-closed status, never `VERIFIED`: `UNVERIFIABLE` when it cannot reach a verdict, `BLOCKED` when the input is rejected (for example a SQL parse failure or a code-analysis error). For SQL, code and schema checks, `admission_decision` admits only a `VERIFIED` result whose claim holds (`developer_fields.is_valid` is true) and denies everything else.
- Several advisories so far are cases where an engine returned `VERIFIED`, or admitted a result, when it should not have: [GHSA-j622-qffp-rc27](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-j622-qffp-rc27) and [GHSA-mfh5-3c8f-975p](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-mfh5-3c8f-975p) (fixed in 7.2.2); [GHSA-6rxr-gq43-694g](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-6rxr-gq43-694g) and [GHSA-q5g6-6cw2-cjm3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-q5g6-6cw2-cjm3) (fixed in 7.2.3); and [GHSA-6p94-4f75-g2wq](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-6p94-4f75-g2wq), [GHSA-4phf-6h72-9xfg](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-4phf-6h72-9xfg), [GHSA-6cpx-8jrq-r7h3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-6cpx-8jrq-r7h3) and [GHSA-g25v-44j8-gg7x](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-g25v-44j8-gg7x) (fixed in 7.3.0; the code and logic ones complete the earlier GHSA-6rxr and GHSA-mfh5 fixes). The 7.3.0 sandbox-containment advisory [GHSA-j3x4-v3p2-4mq3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-j3x4-v3p2-4mq3) is covered under Least Privilege above. Each of the others is reproduced in the soundness eval (section 4).
- 8.0.0 fixes six advisories on the client side of that rule, where the server decided correctly but a client reported something else: the Python SDK took `is_verified` from a bare `is_valid` ([GHSA-jppc-7r58-7pjh](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-jppc-7r58-7pjh)); `QWEDClient.verify_code` and `verify_sql` answered with local blocklists instead of the server ([GHSA-4rj3-8wqj-cqwc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-4rj3-8wqj-cqwc), [GHSA-45jv-2j44-4c2q](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-45jv-2j44-4c2q)); `QWEDLocal.verify_code` did the same ([GHSA-v8qq-v427-qrqc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-v8qq-v427-qrqc)); the LlamaIndex and CrewAI integrations reported unchecked content, or a check that raised, as verified ([GHSA-83v6-6h23-pvp4](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-83v6-6h23-pvp4)); and a newline in the GitHub Action's explanation could set its `verified` output ([GHSA-j788-44pc-8hp3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-j788-44pc-8hp3)). Clients now take the server's admission, call the server or `CodeVerifier`, and fail closed. GHSA-45jv also had a server part, file and extension functions the SQL verifier admitted, which the soundness eval now reproduces; the others are client paths the eval runner does not exercise, and each has regression tests in `tests/`.

### Complete Mediation
- QWED is a library and API: it mediates only the outputs an integrator sends through it. Deployments must route model output through QWED before acting on it.

### Defense in Depth
1.  **Input validation**: most API routes validate input with Pydantic models; four routes in `api/main.py` (including `/verify/math`) accept a raw JSON object and check fields by hand. Request bodies, uploads and batch work are bounded since 7.3.0 ([#230](https://github.com/QWED-AI/qwed-verification/issues/230), [#392](https://github.com/QWED-AI/qwed-verification/issues/392)).
2.  **PII masking**: optional (`qwed[pii]`, `mask_pii=True`) in the Python SDK; off by default.
3.  **Static analysis**: CodeQL, SonarCloud and Snyk run on the repository.
4.  **Runtime limits**: compute bounds in the math parser and logic/DSL engines were added in 7.2.2 ([GHSA-mxwv-x5qm-mrmf](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-mxwv-x5qm-mrmf)); the math compute-cost and batch exhaustion paths were closed in 7.3.0 ([#331](https://github.com/QWED-AI/qwed-verification/issues/331), [#391](https://github.com/QWED-AI/qwed-verification/issues/391)).

## 3. Countermeasures

| Weakness | Mitigation | Status |
| :--- | :--- | :--- |
| **Injection** | Untrusted expressions go through `safe_parse_expr`; raw evaluators are blocked by the CI boundary gate. | Implemented. Three code-injection advisories were fixed in 5.1.2, 7.2.1 and 7.2.2 ([GHSA-q27q-98j4-9pfv](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-q27q-98j4-9pfv), [GHSA-xmm6-8r3x-j567](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-xmm6-8r3x-j567), [GHSA-4v5r-g7f4-vvgc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-4v5r-g7f4-vvgc)). |
| **Unsound results** | Engines fail closed (section 2). Claims with a known answer, including reproductions of the advisories above, run through the Math, Logic, SQL, Code and Schema engines in CI and at every release (`evals/`). | Partial: the Symbolic and Stats engines and the domain packages have no eval cases yet. In 7.2.3 the Python code verifier blocks shell and process execution ([GHSA-6rxr-gq43-694g](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-6rxr-gq43-694g)); the same classification for the other languages the verifier scans is not yet complete. The SQL verifier checks MySQL executable comments and denies tables outside a declared schema ([GHSA-q5g6-6cw2-cjm3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-q5g6-6cw2-cjm3)). In 7.3.0 the code verifier also blocks alternate process-execution routes and file/network sinks ([GHSA-4phf-6h72-9xfg](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-4phf-6h72-9xfg)), the sandbox isolates its namespace ([GHSA-j3x4-v3p2-4mq3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-j3x4-v3p2-4mq3)), the SQL verifier classifies commands across the whole statement tree and expands `SELECT *` against the schema ([GHSA-6p94-4f75-g2wq](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-6p94-4f75-g2wq), [GHSA-6cpx-8jrq-r7h3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-6cpx-8jrq-r7h3)), and the logic NL bridge rejects categorical string constants ([GHSA-g25v-44j8-gg7x](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-g25v-44j8-gg7x)). |
| **Client-side verdicts** | The SDKs, integrations and the GitHub Action take the server's admission and fail closed; nothing a client checks locally is reported as verified unless `CodeVerifier` or the server decided it. | Implemented in 8.0.0 ([GHSA-jppc-7r58-7pjh](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-jppc-7r58-7pjh), [GHSA-4rj3-8wqj-cqwc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-4rj3-8wqj-cqwc), [GHSA-45jv-2j44-4c2q](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-45jv-2j44-4c2q), [GHSA-v8qq-v427-qrqc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-v8qq-v427-qrqc), [GHSA-83v6-6h23-pvp4](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-83v6-6h23-pvp4), [GHSA-j788-44pc-8hp3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-j788-44pc-8hp3)). |
| **Authenticity of results** | Every `VERIFIED` answer carries an ES256 attestation that signs its status, `proof_ref`, statement and admission; Verification Context v1.1 documents carry the server's signature over the whole document. Keys are published at `/.well-known/jwks.json`; the Python, TypeScript, Go and Rust SDKs verify an attestation against them, and validating a Verification Context document requires its signature by default (API, CLI and Python SDK). | Partial: the server self-attests (no independent witness, ADR-005), and a deployment needs a configured signing key (`QWED_SIGNING_KEY`) for attestations to verify across restarts and replicas. |
| **Secrets in checked content** | `ConfigGuard`, `PIIGuard` and the code verifier match known API key formats. | Partial: pattern lists must follow providers' key formats. Project-scoped OpenAI keys (`sk-proj-`) were missed until 7.2.3 ([GHSA-64xf-wffc-63fm](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-64xf-wffc-63fm)). |
| **Credentials** | Provider API keys come from environment variables; QWED API keys are stored hashed. Connection URLs are redacted before logging and the auth boundary rejects expired keys (7.3.0). | Implemented: the Redis-URL password logging ([#228](https://github.com/QWED-AI/qwed-verification/issues/228)) and expired-key acceptance ([#389](https://github.com/QWED-AI/qwed-verification/issues/389)) gaps were both fixed in 7.3.0. |
| **XML exploits** | The server and SDK do not parse XML. | Not applicable |
| **Insecure deserialization** | No `pickle` on untrusted data; JSON is the interchange format. | Implemented |
| **Vulnerable dependencies** | Dependabot and Snyk scanning; dependency updates are reviewed as pull requests. | Implemented |

## 4. Verification

Security controls are checked by:
- **CI**: the test suite, `scripts/check_boundary.py`, CodeQL, SonarCloud and Snyk.
- **Tests**: security-focused tests in `tests/security/` and across `tests/`.
- **Soundness eval**: `evals/` runs claims with a known answer through the engines. `tests/test_evals.py` fails CI if any claim that does not hold is accepted, and `.github/workflows/eval.yml` attaches the report (`eval-results.json`) to every release. The 8.0.0 report: 86 claims, 0 accepted wrongly. The latest results are also shown at [qwedai.tech/evidence](https://qwedai.tech/evidence).
- **External reports**: private vulnerability reporting; see [SECURITY.md](../SECURITY.md) and the published advisories.
- **Open work**: the [security tracker issues](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity).
