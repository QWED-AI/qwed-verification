# Changelog

All notable changes to the QWED Protocol will be documented in this file.

## [Unreleased]
### Security
- Agent verification security checks are now enforced server-side and are no longer configurable through client request payloads.
- TypeScript SDK agent verification helpers no longer send `security_checks`; `tool_schema` remains available for server-side MCP inspection.
- Statistical verification now requires the secure Docker sandbox; Wasm and restricted in-process fallback execution paths are disabled.
- Consensus Python verification now uses the secure Docker executor instead of same-process code execution.

## [4.0.1] - 2026-03-23
### 🔄 Sentinel Guard Sync

#### 🆕 New Endpoints
- **`POST /verify/process`**: Glass-box reasoning process verifier — IRAC structural compliance and custom milestone validation with decimal scoring.
- **Agent Security Checks**: `POST /agents/{id}/verify` now accepts `security_checks: { exfiltration, mcp_poison }` to run `ExfiltrationGuard` and `MCPPoisonGuard` before verification.

#### 🔒 Security Fixes
- **Information Disclosure**: Removed raw `str(e)` from `/verify/rag` error responses; exceptions logged via `redact_pii()`, clients receive only `INTERNAL_VERIFICATION_ERROR`. (Sentry + CodeQL)
- **Symbolic Precision**: `RAGVerifyRequest.max_drm_rate` changed from `float | str` → `str` with `field_validator` enforcing Fraction-compatible values.

#### 🛠️ SDK Changes (`@qwed-ai/sdk@4.0.1`)
- **`verifyProcess()`**: Validates AI reasoning traces using IRAC or custom milestone lists.
- **`verifyRAG()`**: `maxDrmRate` type changed from `number` to `string` for symbolic precision.
- **`verifyAgent()`**: Returns `AgentVerificationResponse`, payload aligned with backend schema. Agent IDs URL-encoded.
- **Type Fixes**: `VerificationResultData.risk` and `risk_level` separated. Added `Process`, `RAG`, `Security` to `VerificationType` enum.

#### 🧪 Tests
- `test_api_phase17_endpoints.py` — covers `/verify/process`, `/verify/rag` exception masking, and agent security check blocking.

## [4.0.0] - 2026-03-12
### 🛡️ Sentinel Edition

#### 🆕 Agentic Security Guards (Phase 17)
- **RAGGuard**: Detects prompt injection, data poisoning, and context manipulation in RAG pipelines with IRAC-compliant reporting.
- **ExfiltrationGuard**: Prevents data exfiltration through AI agent tool calls by analyzing output patterns and destination validation.
- **MCP Poison Guard**: Detects poisoned or tampered Model Context Protocol (MCP) tool definitions before agent execution.
- Five rounds of security review and hardening (CodeRabbit + SonarCloud).

#### 🆕 New Standalone Guards
- **SovereigntyGuard**: Enforces data residency policies and local routing rules for compliance-sensitive deployments.
- **ToxicFlowGuard**: Stateful detection of toxic tool-chaining patterns across multi-step agent workflows.
- **SelfInitiatedCoTGuard (S-CoT)**: Verifies self-initiated Chain-of-Thought logic paths for reasoning integrity.

#### 🆕 Process Determinism
- **ProcessVerifier**: A new class of deterministic verification — IRAC/milestone-based process verification with decimal scoring, budget-aware timeouts, and structured compliance reporting. Ensures AI-driven workflows follow deterministic process steps.

#### 🔒 Critical Security Fixes
- **Code Injection Prevention**: Replaced all `eval()` calls with AST-compiled execution (SonarCloud S5334).
- **Sandbox Escape Fix**: Patched critical sandbox escape and namespace mismatch vulnerability.
- **SymPy Injection Fix**: Hardened symbolic math input parsing against injection attacks.
- **Protocol Bypass Fixes**: Fixed URL whitespace bypass and protocol wildcard bypass vulnerabilities.
- **CVE Patches**: Resolved CVE-2026-24049 (Critical, pip/wheel), CVE-2025-8869, and HTTP request smuggling (h11/httpcore).
- **Snyk Remediation**: Fixed all 19 Snyk Code findings across the codebase.
- **CodeQL Remediation**: Secured exception handling in `verify_logic`, `ControlPlane`, `verify_stats`, and `agent_tool_call`.

#### 🐳 Docker Hardening (15+ improvements)
- Pinned base image digests with hash-verified requirements.
- Non-root user execution with `gosu`/`runuser`.
- Inlined entrypoint script to fix exec format errors across platforms.
- Enforced LF line endings via `.gitattributes` and `dos2unix`.
- Automated Docker Hub publishing on release and main branch push.
- SBOM generation and Docker Scout vulnerability scanning.

#### 🔧 CI/CD Infrastructure
- **Sentry SDK**: Integrated error tracking and monitoring.
- **CircleCI**: Added Python matrix testing pipeline.
- **SonarCloud**: Added code quality and coverage workflow.
- **Snyk**: Added security scanning workflow with SARIF output.
- **Docker Auto-Publish**: Automated image publishing to Docker Hub on every release.

#### 📝 Documentation & Badges
- Added OpenSSF Best Practices badge (Silver level).
- Added Snyk security badge and partner attribution.
- Added Docker Hub pulls badge and dynamic BuildKit badge.
- Updated engine count from 8 to 11 across all documentation.
- Added Ecosystem Trust & Infrastructure section to README.

#### 🧪 Test Coverage
- ProcessVerifier: decimal scores, edge cases, IRAC long input, malformed data.
- Attestation edge cases and qwed_local execution tests.
- Logic exception handling and stats engine coverage.
- Secure executor Docker availability checks.

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
