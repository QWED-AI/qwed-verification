# Changelog

All notable changes to the QWED Protocol will be documented in this file.

## [3.0.1] - 2026-02-04
### 🦾 Ironclad Update (Security Patch)

#### 🛡️ Critical Security Hardening
- **CodeQL Remediation:** Resolved 50+ alerts including ReDoS, Clear-text Logging, and Exception Exposure.
- **Workflow Permissions:** Enforced `permissions: contents: read` across all GitHub Actions (`dogfood`, `publish`, `sdk-tests`) to adhere to Least Privilege.
- **PII Protection:** Implemented robust `redact_pii` logic in all API endpoints and exception handlers.

#### 📝 Compliance
- **Snyk Attribution:** Added Snyk attribution to README and Documentation footer for Partner Program compliance.

#### 🐛 Bug Fixes
- **API Stability:** Fixed unhandled exceptions in `verify_logic` and `agent_tool_call` endpoints.

## [2.4.1] - 2026-01-20
### 🚀 The Reasoning Engine & Enterprise Docker Support

#### New Features
- **Optimization Engine (`verify_optimization`)**: Added `LogicVerifier` support for Z3's `Optimize` context.
- **Vacuity Checker (`check_vacuity`)**: Added logical proof to detect "Vacuous Truths".

#### Enterprise Updates
- **Dockerized GitHub Action**: The main `qwed-verification` action now runs in a Docker container.


#### Fixes & Improvements
- Updated `logic_verifier.py` with additive, non-breaking methods.
- Replaced shell-based `action_entrypoint.sh` with robust Python handler `action_entrypoint.py`.
