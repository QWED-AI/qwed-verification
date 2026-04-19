# Changelog

All notable changes to the QWED Protocol will be documented in this file.

## [Unreleased]

## [5.1.0] - 2026-04-19
### Agent State Governance and Fail-Closed Hardening

Minor release expanding QWED from action verification into state governance while closing the adversarial fail-open gaps identified after v5.0.0. This release includes AgentStateGuard plus a focused hardening wave across execution, tool governance, mathematical verification, API semantics, and schema validation.

#### New Capability
- **AgentStateGuard**: Added deterministic state verification with strict structural validation, semantic transition checks, and governed atomic state commits. This extends QWED from action-only verification to state and memory governance.

#### Fail-Closed Hardening
- **Legacy CodeExecutor hard-blocked**: `CodeExecutor.execute()` now raises `RuntimeError` unconditionally. All supported execution remains on `SecureCodeExecutor`.
- **Unknown tools default-denied**: `ToolApprovalSystem` now blocks unknown tools regardless of heuristic risk score.
- **Bounded math tolerance**: `verify_math()` rejects oversized, negative, non-finite, and malformed tolerances instead of letting callers weaken correctness checks.
- **Legacy logic path fails closed**: `verify_logic_rule()` now raises `NotImplementedError` instead of returning `None`.
- **Identity sampling rejected**: `verify_identity()` now returns `BLOCKED` when numerical sampling matches but no formal proof exists.
- **Ambiguous math API rejected**: `/verify/math` now blocks ambiguous implicit-multiplication expressions instead of returning `is_valid: true`.
- **Schema uniqueness fail-closed**: `SchemaVerifier` now emits `uniqueness_validation_error` when `uniqueItems` cannot be proven deterministically.

#### Runtime and Security Follow-Through
- **Progress-aware doom loop guard**: Added LOOP-004 state-aware replay protection for repeated actions on unchanged state.
- **Security and infrastructure hardening**: Incorporated follow-up hardening across configs, CI, and infrastructure.
- **Stats verifier coverage expansion**: Added edge-case coverage for the statistics engine.
- **CodeQL and cleanup follow-ups**: Merged syntax, test, and static-analysis cleanup work after the v5.0.0 boundary release.

#### Upgrade Notes
- `CodeExecutor` is no longer usable as a legacy execution path. Migrate any direct imports to `SecureCodeExecutor`.
- Unknown tools now require explicit allowlisting and are no longer auto-approved at low heuristic risk.
- `verify_math()` may return `BLOCKED` for tolerances that exceed the deterministic policy bound.
- `verify_logic_rule()` no longer returns an ambiguous non-result; callers must migrate to `LogicVerifier`.
- Sampling-only `verify_identity()` matches now return `BLOCKED`, not `UNKNOWN`.
- Ambiguous `/verify/math` expressions now return `BLOCKED` with `is_valid: false`.
- `uniqueItems` validation failures are now explicit schema errors instead of silent passes.

#### SDK and Package Versions
- `qwed` (PyPI): `5.0.0` -> `5.1.0`
- `qwed_sdk` (Python): `5.0.0` -> `5.1.0`
- `@qwed-ai/sdk` (NPM): `5.0.0` -> `5.1.0`

#### Included PRs since v5.0.0
- `#124` feat(agent): add progress-aware doom loop guard (LOOP-004)
- `#126` security: harden configs, CI, and infrastructure -- full audit fixes
- `#127` test(stats): add edge case coverage for statistics engine
- `#136` fix(codeql): resolve remaining syntax and test cleanup alerts
- `#137` Update contributors section in README
- `#139` feat: AgentStateGuard - full implementation (structural + semantic + atomic commit)
- `#149` fix: hard-block legacy CodeExecutor execution path
- `#150` fix: default deny unknown tool approvals
- `#151` fix: bound verify_math tolerance by computed magnitude
- `#152` fix: fail closed in verify_logic_rule
- `#153` fix: fail closed in verify_identity
- `#154` fix: fail closed for ambiguous math api inputs
- `#155` fix: fail closed on uniqueItems validation errors

## [5.0.0] - 2026-04-04
### 🛡️ Enforcement Boundary Hardening

Major release focused on making QWED's verification boundary fail-closed, deterministic about what it proves, and substantially harder to bypass under adversarial conditions. Consolidates 98 commits and 20 merged PRs since v4.0.1, including the full PR 0–5 enforcement hardening series.

#### 🔐 Security Hardening
- **Fail-Closed Verification**: Disabled unsafe in-process execution fallbacks; stats and consensus paths now require secure Docker sandbox.
- **Critical Boundary Closures**: Removed logic verifier `eval()` fallback — raises `RuntimeError` if `SafeEvaluator` is unavailable (CVE-QWED-001).
- **Mandatory Guards**: Agent security guards (Exfiltration, MCP Poison) are now server-enforced and unconditional — `security_checks` field removed from request model.
- **Consensus Rate Limiting**: `/verify/consensus` endpoint now enforces `check_rate_limit` to prevent cost amplification attacks.
- **Self-Attestation Fix**: Consensus fact engine no longer calls `verify_fact(query, query)` — requires external context.
- **Redis Fail-Closed**: `RedisSlidingWindowLimiter` now denies requests on Redis errors instead of allowing them.
- **Timing-Safe Token Verification**: Agent token comparison switched to `hmac.compare_digest`.
- **Metrics Access Control**: `/metrics` and `/metrics/prometheus` now require authenticated admin access.
- **Environment Integrity**: Startup enforces `verify_environment_integrity()` before database initialization.

#### 🧠 Determinism & Trust Boundary
- Natural-language math responses now return `INCONCLUSIVE` when verifying LLM-translated expressions — never `VERIFIED`.
- Added explicit `trust_boundary` metadata in API responses describing what was actually verified.
- `verify_identity()` numerical sampling fallback now returns `UNKNOWN` instead of `LIKELY_EQUIVALENT`.
- Heuristic/non-proof outcomes are honestly labeled instead of presented as formal verification.

#### 🤖 Agent Hardening
- **Action context mandatory**: `verify_action()` requires `ActionContext` with `conversation_id` and `step_number`.
- **Replay detection**: Same `(conversation_id, step_number)` pair blocked (QWED-AGENT-LOOP-002).
- **Loop detection**: Same action repeated 3+ times triggers DENIED (QWED-AGENT-LOOP-003).
- **In-flight step reservations**: Prevents race conditions in concurrent agent calls.
- **Budget denial isolation**: Budget-exceeded denials do not consume conversation state.

#### 📜 Tool Governance (PR 0)
- Added `QWED_RULES.md` — canonical enforcement contract for contributors and tools.
- Added `.github/copilot-instructions.md` — blocks Copilot from suggesting fallback execution.
- Added `.github/pull_request_template.md` — mandatory enforcement checklist.
- Extended `.coderabbit.yaml` with enforcement-specific review instructions.

#### 🔧 Supply Chain & CI
- Pinned third-party GitHub Actions to verified commit SHAs.
- Merged security autofix PRs and dependency hardening (#100–#114).

#### 📦 SDK & Package Versions
- `qwed` (PyPI): `4.0.1` → `5.0.0`
- `qwed_sdk` (Python): `2.1.0-dev` → `5.0.0`
- `@qwed-ai/sdk` (NPM): `4.0.1` → `5.0.0`
- TypeScript SDK: Removed `security_checks` from agent verification helpers; `tool_schema` remains.

#### 🧪 Test Coverage
- `test_pr115_regressions.py` — critical boundary closures (eval removal, guard enforcement, consensus rate limit, fact self-attestation).
- `test_pr117_regressions.py` — stats fail-closed behavior, sandbox enforcement.
- `test_pr4_runtime_hardening.py` — Redis fail-closed, agent loop controls, metrics auth, environment integrity.
- `test_pr5_determinism_alignment.py` — trust boundary metadata, INCONCLUSIVE status, numerical sampling UNKNOWN.
- **Sanity sweep**: 162 passed, 11 skipped, 0 failures.

#### ⚠️ Upgrade Notes
- `INCONCLUSIVE` is now a distinct verification status — downstream consumers must handle it.
- `BLOCKED` and `UNKNOWN` are explicit outcomes, not generic failures.
- Agent integrations must provide `ActionContext` with `conversation_id` and `step_number`.
- `/metrics` endpoints now require admin role — update monitoring integrations accordingly.


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
