# Security Assurance Case

## Overview

This document provides the assurance case for QWED's security, justifying why its security requirements are met. It outlines the threat model, trust boundaries, secure design principles, and countermeasures against common weaknesses.

## 1. Threat Model

### Trust Boundaries
- **Untrusted**: 
    - LLM Outputs (Inherently non-deterministic and potentially hallucinated)
    - User Inputs (Queries, prompts)
    - External URLs/Data sources fetched by engines
- **Trusted**:
    - QWED Verification Engines (Math, Logic, SQL, Code) running in isolated environments
    - Internal Control Plane logic
    - PII Detection System (Presidio)

### Primary Threats
1.  **Prompt Injection**: Malicious user input manipulating the LLM to bypass verification.
2.  **Code Injection**: LLM generating malicious code (e.g., `os.system('rm -rf /')`) that the verification engine executes.
3.  **Denial of Service (DoS)**: verification engines consuming excessive resources (CPU/RAM) via complex inputs (e.g., ReDoS).
4.  **Data Leakage**: PII or sensitive data being sent to external LLM providers.

## 2. Secure Design Principles

### Least Privilege
- Verification engines run with minimal permissions.
- Code execution is sandboxed or restricts imports (e.g., `ast` analysis allows only safe subsets of Python).

### Complete Mediation
- All LLM outputs *must* pass through the Verification Layer before reaching the user.
- No direct path from LLM to User exists for unverified content.

### Defense in Depth
1.  **Input Validation**: Strict typing and schema validation on all API inputs.
2.  **PII Masking**: Automatic redaction of sensitive entities before LLM processing.
3.  **Static Analysis**: Bandit and CodeQL scans in CI/CD pipelines.
4.  **Runtime Guards**: Timeouts and memory limits on meaningful verification steps.

## 3. Countermeasures

| Weakness | Mitigation Strategy | Status |
| :--- | :--- | :--- |
| **Injection** | AST parsing ensures only mathematical/logical expressions are evaluated. usage of `eval()` is strictly controlled and sanitized. | ✅ Implemented |
| **Broken Auth** | API Keys for LLM providers are managed via environment variables and never logged. | ✅ Implemented |
| **XML Exploits** | XML parsing (if any) disables DTDs and external entity processing (XXE protection). | ✅ Implemented |
| **Insecure Deserialization** | No use of `pickle` for untrusted data. JSON is the primary interchange format. | ✅ Implemented |
| **Vulnerable Dependencies** | Automated Dependabot and Snyk scanning. Critical patches applied < 7 days. | ✅ Implemented |

## 4. Verification

Status of security controls is verified via:
- **CI/CD**: GitHub Actions run `bandit` and `semgrep` on every PR.
- **Unit Tests**: Security-specific test cases in `tests/security/` cover injection attempts.
- **Manual Audit**: Periodic code reviews focusing on the `core/engines` module.
