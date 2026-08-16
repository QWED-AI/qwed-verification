# Changelog

All notable changes to the QWED Protocol will be documented in this file.

## [Unreleased]

## [7.1.0] - 2026-08-16

### Verification Context v1.0 Rollout

#### Ontology & Spec (#301, #302)

- **ADR-001..005 — verification ontology** — formally define the object of verification, the verification context document, the truth-vs-admission separation, the formalization boundary, and the root of trust.
- **Verification Context v1.0 spec freeze** — the 4-layer JSON document contract (interpretation / proof / evidence / decision) with canonical RFC 8785 JSON encoding, UTF-16 key ordering, fail-closed schema validation, and content-bound `proof_ref`.

#### Core Model (#308, #309)

- **`VerificationContext` model + JSON schema** — `VerificationContext`, `VerificationContextDocument`, `Verdict`, `Admission`, and nested `Interpretation` / `Proof` / `Evidence` / `Decision` types with fail-closed validation.
- **Public proof_ref generation / resolution** — `compute_document_proof_ref()` and `resolve_document_proof_ref()` exposed as public API; references are content-bound SHA-256 hashes over the canonical document.

#### Bridge & Verifier Mappings (#310, #316)

- **`verification_context_from_diagnostic_result()`** — converts `DiagnosticResult` → VC document; VERIFIED without attestation demotes to UNVERIFIABLE (fail-closed, consistent with the core contract).
- **`to_verification_context()` on all 13 verifiers** — complete engine coverage: Math, Logic, Symbolic, SQL, Code, Schema, Fact, Image, Graph, Reasoning, Stats, Consensus, and SecureCodeExecutor.

#### Surface Exposure (#311, #313, #314, #315)

- **SDK / API / CLI exposure** — Verification Context surfaced across the API routes, CLI, and SDK.
- **Docker action VC outputs** — the containerized GitHub Action emits `verdict`, `admission`, `proof_ref`, and `verification_context` outputs.
- **Metadata & README alignment** — repository metadata aligned with the v7.0 architecture.
- **SDK re-exports** — all Verification Context v1.0 types re-exported from `qwed_sdk`.

> **Semver:** minor release — additive public API (VC model, mappings, resolver, routes, outputs). No breaking wire changes.

## [7.0.0] - 2026-08-08

### Engine Migration to DiagnosticResult (Meta #216)

#### SchemaVerifier → DiagnosticResult (#255)
- **`SchemaVerifier.verify()` and `verify_ucp_transaction()` now return `DiagnosticResult`** (status / `agent_message` / `developer_fields` / `proof_ref`) instead of ad-hoc dicts.
- **`proof_ref`** is computed deterministically from a canonical `json.dumps` of the schema + instance evidence on VERIFIED results; unsupported values and cyclic structures fail closed to `BLOCKED` (`schema_verifier.validation_error`).
- **Recursive schema meta-validation** — malformed keyword shapes (non-dict properties, invalid required entries, invalid numeric constraints, non-finite/NaN/±∞ bounds, negative size constraints) return `BLOCKED` (`schema_verifier.parse_error`) instead of being silently treated as empty.
- **UCP type safety** — string/None amount fields and non-dict transactions are handled deterministically instead of raising `TypeError`/`AttributeError`.
- **UCP verdict fields are complete on every path** — `verify_ucp_transaction()` always produces `transaction_type`, `currency`, and `schema_verifier.ucp_*` constraint ids in `developer_fields` for both valid and violated verdicts (BLOCKED base results pass through unchanged).
- **Money arithmetic uses `Decimal`, not float tolerance** — computed-total and tax checks quantize operands to the currency precision and compare exactly, removing 0.01-tolerance rounding noise so boundary transactions deterministically pass/fail.
- **`tax` is selected by key presence, not truthiness** — a declared `tax: 0` is used instead of silently falling back to `tax_amount`.
- **Non-finite floats (`NaN`, `±inf`) and hostile `__repr__` set members fail closed** — evidence serialization raises `ValueError` into the existing `BLOCKED` path instead of emitting non-JSON tokens or leaking `RuntimeError`.
- **`agent_message` sanitized** — no rule IDs, issue types, or schema internals leak into agent-facing output.
- **Removed orphan `math_verifier` delegation** — the lazy `SymbolicVerifier` instantiation (never called) is gone; computed-field checks use inline exact Decimal comparison.
- **Hot path cost of the migration reduced (~20% fewer instructions)** — proof evidence is traversed once instead of twice (cycles and unsupported types are detected by the canonical encoder itself), the canonical JSON encoder is reused across calls, and schema meta-validation dispatches on the keywords a schema declares instead of probing the full keyword vocabulary. `proof_ref` values are unchanged.
- **Oversized integer bounds no longer crash** — `minimum` / `maximum` / `exclusiveMinimum` / `exclusiveMaximum` / `multipleOf` values beyond float range (e.g. `10**1000`) are finite by construction and no longer raise `OverflowError` out of `verify()`.

#### CodeVerifier & SecureCodeExecutor → DiagnosticResult (#254, PR #296)
- **`CodeVerifier.verify_code()`, `verify_python_deep()`, and `verify_batch()` now return `DiagnosticResult`** (status / `agent_message` / `developer_fields` / `proof_ref`) instead of ad-hoc dicts.
- **`VERIFIED` is now emitted for unsafe code — as `VERIFIED`-as-unsafe.** A proven-unsafe snippet is `VERIFIED` with `developer_fields.is_valid = false`, a bound `proof_ref`, and a non-null `critical_count`; it is never emitted `BLOCKED`. This is `VERIFIED` as a *truth* guarantee (the code was checked), not an *admission* guarantee.
- **`AdmissionDecision` is a separate decision, exposed at the trust boundary** — `POST /verify/code` and batch `CODE` items attach `admission` (`ADMIT` / `BLOCKED`) and treat `is_valid` as the safety gate, so authority-only consumers reading `status == "VERIFIED"` cannot admit unsafe code.
- **`BLOCKED` is reserved for cases where verification itself failed** — empty code, non-string `language`, internal/execution errors, and (deep) language normalization failures. Blocked results carry **no** `proof_ref`, so they cannot be mistaken for a verdict.
- **`SecureCodeExecutor.execute()` no longer executes code wholesale on the verifier verdict** — the executor applies an unconditional OWASP LLM06 dangerous-pattern gate (`os.`, `sys.`, `subprocess`, `__import__`, `eval`, `exec`, `compile`, `open(`, `file(`, `input(`, `raw_input(`, `socket`, `urllib`, `requests`, `http`) and blocks execution with `CONSTRAINT_DANGEROUS_PATTERN`. The scan is **AST-aware**: it matches actual executable operations (imports, attribute access, calls), so dangerous keywords that appear only in comments, docstrings, or string literals (e.g. a URL in a docstring) do not cause false denials. The advisory-only fallback is retained only when verification itself fails closed.
- **`verify_batch()` returns per-item `verdicts` + a `summary` and an overall `is_valid`** — `safe` / `unsafe` / `blocked` counts and `total_critical`; `is_valid` is `true` only when **all** snippets are safe, and the batch is otherwise non-admissible.
- **`ConsensusVerifier` and `StatsVerifier` code-stages adapt** — expected-status flags were updated to require `is_verified` **and** `developer_fields.is_valid is True`, and `stats_verifier._validate_security` fails closed on any non-true `is_valid`, so consensus results can no longer admit unsafe code.

> **Breaking wire change:** `POST /verify/code` now returns **HTTP 200 with `status = "VERIFIED"`** for proven-unsafe code (previously `status = "BLOCKED"`). Admission is driven by the new `admission` field and `developer_fields.is_valid`. Consumers that branched on `status == "BLOCKED"` or `status == "VERIFIED"` for safety gating **must** switch to the `admission` / `is_valid` fields; `status == "VERIFIED"` alone must never be treated as "safe to execute".

#### StatsVerifier → DiagnosticResult (#256)
- **`StatsVerifier.verify_stats()` now returns `DiagnosticResult`** (status / `agent_message` / `developer_fields` / `proof_ref`) instead of an ad-hoc dict.
- **Execution success is **never** `VERIFIED` (computation ≠ verification).** A run that executes cleanly in the Docker sandbox and returns an observed statistic is `UNVERIFIABLE` (`stats_verifier.claim_not_verified`) — the engine has no deterministic claim-proof, so it cannot attest the original natural-language claim. `VERIFIED` + `proof_ref` is reserved for a deterministic claim evaluation tracked in #298; it is never emitted from execution success alone.
- **`BLOCKED` is reserved for failure states** — translation/validation failure (`stats_verifier.validation_error`), execution failure (`stats_verifier.execution_failure`), and secure Docker sandbox unavailable (`stats_verifier.runtime_unavailable`). Blocked results carry **no** `proof_ref`.
- **Execution evidence is preserved, not lost.** On `UNVERIFIABLE` the observed result, generated code, columns, a deterministic dataset fingerprint (`dataset_sha256`), sandbox type, timing, and security checks are retained in `developer_fields` for audit/review.
- **`agent_message` is sanitized** — no raw subprocess output, sandbox identifiers, or error strings leak into the agent-facing layer.
- **API boundary is now a thin pass-through** — `POST /verify/stats` forwards the engine's `DiagnosticResult` through `enforce_trust_decision()` unchanged instead of re-deriving status from dict fields.
- **Logging is fail-closed and claim-aware** — the verification log records `is_verified` from the authoritative proof bit AND the claim-validity signal (`dr.is_authoritative and developer_fields.is_valid is True`). A non-authoritative result (BLOCKED / UNVERIFIABLE, `proof_ref = None`) can never be persisted as verified, even if the mutable `developer_fields.is_valid` metadata is `True`.
- **`compute_statistics()` and `get_sandbox_info()` are deliberately unchanged** — they are utilities (safe direct computation / sandbox introspection), not claim-verification boundaries, so they stay on their existing dict return.
- **Deferred architecture is tracked, not silently dropped** — deterministic statistical claim evaluation (#298) and deterministic DataFrame schema validation (#299) do not exist in the codebase and were not invented here; both are filed as dedicated issues rather than being fabricated to force a `VERIFIED`.
- **`FactVerifier`/`ImageVerifier` batch verification now returns `DiagnosticResult`** — `BatchFactVerifier.verify_batch()` and `ImageVerifier.verify_batch()` return a single `DiagnosticResult` with per-claim verdicts in `developer_fields.results` and a `summary`. The batch is authoritative (`VERIFIED` + `proof_ref`) only when **every** claim is deterministically verified; any refuted/blocked claim fails the whole batch closed (`fact_verifier.batch_blocked` / `image_verifier.batch_blocked`), and an empty batch is `BLOCKED` (`*.empty_batch`). The batch `proof_ref` binds full claim digests **and the shared input** (image digest for image batches, context digest for fact batches), never truncated display text. Aggregation is shared via `diagnostics.aggregate_batch_diagnostic()` so the fail-closed logic cannot drift between engines. This closes the last two public engine entry points still returning ad-hoc dicts under META #216.
- **Stats `observed_result` is JSON-safe** — a non-serializable sandbox result (e.g. a DataFrame) is coerced before entering `developer_fields`, so a legitimate `UNVERIFIABLE` verdict can no longer be silently downgraded to `BLOCKED` when the trust gate snapshots developer fields.

> **Breaking wire change:** `POST /verify/stats` now returns the unified `DiagnosticResult` schema (`status` / `agent_message` / `developer_fields` / `proof_ref`) instead of the legacy `{"status": "SUCCESS" | "ERROR" | "BLOCKED", "result": ..., "code": ...}` shape. Successful execution now reports `status = "UNVERIFIABLE"` with the observed value in `developer_fields.observed_result` — execution success alone is never presented as a proven claim.

#### Version Propagation
- `qwed` (PyPI): `6.0.0` -> `7.0.0`
- `qwed_sdk` (Python): `6.0.0` -> `7.0.0`
- `@qwed-ai/sdk` (NPM): `6.0.0` -> `7.0.0`
- `qwed` (crates.io/Rust): `6.0.0` -> `7.0.0`
- API version marker: `6.0.0` -> `7.0.0`
- Kubernetes deployment image: stays pinned to the published `6.0.0` here; bumped to `7.0.0` only after the release publishes the image (avoids `ImagePullBackOff`)
- Deployment docs version references updated

#### Included PRs (merged after v6.0.0)
- `#294` feat(core): migrate SchemaVerifier to DiagnosticResult (#255)
- `#295` fix(sql): migrate SQLVerifier to DiagnosticResult (#253)
- `#296` feat(core): migrate CodeVerifier and SecureCodeExecutor to DiagnosticResult (#254)
- `#297` feat(stats): migrate StatsVerifier.verify_stats to DiagnosticResult (#256)

#### GitHub Action
- The **QWED Verification GitHub Action** is maintained in its own repository — [`QWED-AI/qwed-verification-action`](https://github.com/QWED-AI/qwed-verification-action). It wraps the `qwedai/qwed-verification` Docker image and is versioned independently of this release; it is **not** published from this repository, so no action release is part of v7.0.0.

## [6.0.0] - 2026-08-02

### Trust Boundary Completion (Epic #263)

Completes the Trust Boundary Completion epic — all 12/12 sub-issues closed. Every verification API pathway now returns `DiagnosticResult` and routes through `enforce_trust_decision`. The trust boundary is no longer advisory: the control plane requires and verifies attestation before admitting VERIFIED results, and VERIFIED is a protocol guarantee backed by a non-empty, deterministic `proof_ref`, never by execution, agreement, confidence, or provenance. Engine-level migrations to `DiagnosticResult` remain tracked under META #216.

> **⚠️ Breaking change:** `/verify/*` API responses now use the unified `DiagnosticResult` schema (status / `agent_message` / `developer_fields` / `proof_ref`). Consumers of the previous ad-hoc dict responses must migrate.

#### Architecture: Observation vs Admission (#264, #265)
- **All `/verify/*` endpoints return `DiagnosticResult`** (PR #276)
- **Control plane enforces mandatory attestation** — `require_attestation=True`, attestation issued + verified, enforced status drives HTTP response status (PR #278)
- **Batch math** routes through `DiagnosticResult` + attestation + `enforce_trust_decision` (PR #282)
- **Attestation scope alignment** — attest translated expression, not natural-language query, so `query_hash` binds to what was actually verified (#279, PR #285)

#### VERIFIED is a protocol guarantee (#266, #267, #269, #270)
- **ConsensusResult** uses `DiagnosticStatus` enum with `proof_ref` + `verified_evidence` (PR #280)
- **FactVerifier** heuristic SUPPORTED verdict → UNVERIFIABLE with `advisory_checks` (PR #283)
- **Consensus code execution** advisory-only, VERIFIED → UNVERIFIABLE (PR #281)
- **Consensus stats computation** advisory-only, never VERIFIED (PR #277)
- **LogicVerifier** migrated to `DiagnosticResult` (PR #262)
- **AgentStateGuard** `proof_ref` = real sha256 of committed bytes, not a static sentence (#268, PR #284)

#### Engineering & Security Hardening
- **TOCTOU closure** in `enforce_trust_decision` — `developer_fields` snapshotted via recursive rebuild (no `deepcopy` alias window), fail-closed snapshot (#273, PR #290)
- **Attestation signature verified before claim decode** — silent generic error for all failure modes (#275, PR #287)
- **Tenant-isolated verification cache** — `VerificationCache` keys namespaced by normalized `tenant_id` (#274, PR #286)
- **Unicode normalization** in AgentStateGuard canonicalization — NFC collisions rejected (#272, PR #288)
- **Mandatory proof artifact** for VERIFIED attestations (issuance + consumption, PR #248)
- **Credential / JWT / dockerignore security alerts** resolved (PR #249)
- **Math whitelist injection bypass** removed (PR #251)
- **Engine classification docs** — Proof / Policy Enforcement / Advisory (PR #247)

#### Rules & Protocol Semantics
- `QWED_RULES.md` codifies the trust-boundary contract: **#13 Separation of Responsibilities**, **#14 Verification Semantics**, **#15 Truth Before Policy**; rules #7/#8 updated to capture admission-boundary and deterministic-proof semantics

#### Version Propagation
- `qwed` (PyPI): `5.3.0` -> `6.0.0`
- `qwed_sdk` (Python): `5.3.0` -> `6.0.0`
- `@qwed-ai/sdk` (NPM): `5.3.0` -> `6.0.0`
- `qwed` (crates.io/Rust): `5.3.0` -> `6.0.0`
- API version marker: `5.3.0` -> `6.0.0`
- Kubernetes deployment image: `5.3.0` -> `6.0.0`
- Deployment docs + historical roadmap version references updated

#### Included PRs
- `#247` docs: engine classification — Proof / Policy Enforcement / Advisory
- `#248` fix(#191): enforce mandatory proof artifact on VERIFIED attestations (issuance + consumption)
- `#249` fix: resolve credential / JWT / dockerignore security alerts
- `#251` fix(#227): remove math whitelist injection bypass
- `#260` fix(#257): hybrid engine advisory-only — never VERIFIED without proof
- `#261` fix(#259): FactVerifier advisory-only
- `#262` feat(#252): LogicVerifier migrated to DiagnosticResult
- `#276` fix(api): migrate all /verify/* endpoints to return DiagnosticResult (#264)
- `#277` fix(#270): consensus stats advisory-only, never VERIFIED
- `#278` fix(#265): control plane trust enforcement mandatory
- `#280` fix(#266): ConsensusResult DiagnosticStatus enum + proof_ref + verified_evidence
- `#281` fix(#269): consensus code execution advisory-only
- `#282` fix(#271): batch math DiagnosticResult → proof_ref + attestation + enforce_trust_decision
- `#283` fix(#267): FactVerifier SUPPORTED → UNVERIFIABLE with heuristic advisory_checks
- `#284` fix(#268): AgentStateGuard proof_ref real sha256
- `#285` fix(#279): attest translated expression, not natural language query
- `#286` fix(#274): VerificationCache tenant isolation
- `#287` fix(#275): attestation verify-before-decode + silent generic error
- `#288` fix(#272): NFC-normalize AgentStateGuard canonicalization
- `#289` fix: mock network in secret redaction tests (CI)
- `#290` fix(#273): close TOCTOU in enforce_trust_decision

## [5.3.0] - 2026-07-25
### SymbolicVerifier: DiagnosticResult Reference Implementation

SymbolicVerifier is the first fully `DiagnosticResult`-conformant verification engine and serves as the reference implementation for future engine migrations. The unified diagnostic model is no longer aspirational — one of 13 engines now demonstrates the complete pattern.

#### Completed (Phase 1 + Phase 2, META #216)
- **Phase 1** — 6 public methods migrated to `DiagnosticResult`: `verify_code`, `verify_function_contract`, `verify_safety_properties`, `verify_bounded`, `analyze_complexity`, `get_verification_budget`
- **Phase 2** — All internal code paths produce `AdvisoryCheck` for non-proof-bearing analysis; `developer_fields` provides structured evidence; `verification_mode` field tracks bounded vs. unbounded analysis
- **Fail-closed math bugs (#129-#131)** — All three resolved, ensuring safety constraints always block when out of budget (PRs #217-#219)
- **Key rotation (#224)** — Secure key attestation rotation implemented (PR #232)

#### Version Propagation
- `qwed` (PyPI): `5.2.0` -> `5.3.0`
- `qwed_sdk` (Python): `5.2.0` -> `5.3.0`
- `@qwed-ai/sdk` (NPM): `5.2.0` -> `5.3.0`
- `qwed` (crates.io/Rust): `5.2.0` -> `5.3.0`
- API version marker: `5.2.0` -> `5.3.0`
- Kubernetes deployment image: `5.2.0` -> `5.3.0`

#### Ecosystem Status
- **1 of 13 engines conformant** — SymbolicVerifier as reference implementation
- **Remaining engines tracked under META #216** (12 engines + security hardening + attestation consumption)
- Open audit issues: #162-#164 (Logic/Graph/Reasoning), #205 (SecureCodeExecutor), #221-#231 (security hardening), #191 (attestation consumption)

#### Included PRs

**Core: SymbolicVerifier Migration (Phase 1 + Phase 2)**
- `#212` feat: migrate SymbolicVerifier to DiagnosticResult (Phase 1)
- `#239` feat: add verification_mode to SymbolicVerifier DiagnosticResults (#237)
- `#240` feat(#236): migrate verify_bounded to return DiagnosticResult
- `#241` feat(#234): migrate get_verification_budget to return DiagnosticResult
- `#242` feat(#233): migrate analyze_complexity to return DiagnosticResult
- `#243` feat(#235): migrate verify_safety_properties to return DiagnosticResult

**Fail-Closed Bug Fixes (Math)**
- `#217` fix(math): fail-closed on ambiguous mode — block multi-mode datasets (#129)
- `#218` fix(math): require eigenvalue cardinality match before verification (#130)
- `#219` fix(math): require IRR convergence proof before VERIFIED (#131)

**Security & Key Rotation**
- `#220` fix: remove unused check_assertions parameter from verify_code
- `#232` fix: use PBKDF2 instead of raw SHA-256 for key rotation hashing

**Code Quality & Tooling**
- `#208` docs: archive stale docs — roadmap.md, ARCHITECTURE.md (historical), update DEPLOYMENT.md version refs
- `#209` docs: sync README with v5.2.0 codebase — engines, guards, architecture
- `#210` fix: Potential fix for code scanning alert no. 515: Log Injection
- `#211` fix: replace polynomial regex with O(n) str.find loop for data URI removal
- `#213` fix: silence CodeQL clear-text-logging false positives in security demo
- `#215` Add GitLab badge to README

## [5.2.0] - 2026-06-19
### Architecture: Structured Verification Diagnostics (#204)

Establishes the unified 3-layer `DiagnosticResult` model — the diagnostic contract that all verification engines will conform to. This is an **additive** release: no existing engine return types are changed. Engine conformance is tracked in blocked issues (#129, #130, #131, #133, #134, #162, #163, #164, #190, #205).

#### New: `DiagnosticResult` Model (`src/qwed_new/core/diagnostics.py`)

Three disclosure layers:
- **Layer 1 — Agent-Safe**: `agent_message: str` — agent/model-facing summary, no internals leaked
- **Layer 2 — Developer**: `developer_fields: dict` — structured evidence (constraint_id, advisory_checks, methods_used, evidence)
- **Layer 3 — Proof**: `proof_ref: Optional[str]` — sha256 hash of retained proof artifact; the authority bit

Key design:
- `DiagnosticStatus`: tri-state only (`VERIFIED` / `UNVERIFIABLE` / `BLOCKED`) — no proliferation
- `proof_ref` is the authority bit: present = admissible for control flow, None = reject
- `VERIFIED` requires `proof_ref` — structurally enforced in `__post_init__`
- `AdvisoryCheck`: non-proof-bearing analysis (LLM fallback, NLI, VLM) — `advisory_only=True` enforced
- `compute_proof_ref()`: deterministic sha256 hashing of JSON-serialized evidence
- `from_legacy_dict()`: migration helper for ad-hoc engine dicts (fail-closed states only)
- Both `DiagnosticResult` and `AdvisoryCheck` are `frozen=True` dataclasses — prevents post-construction bypass

#### Version Propagation
- `qwed` (PyPI): `5.1.2` -> `5.2.0`
- `qwed_sdk` (Python): `5.1.1` -> `5.2.0`
- `@qwed-ai/sdk` (NPM): `5.1.2` -> `5.2.0`
- `qwed` (crates.io/Rust): `5.1.2` -> `5.2.0`
- API version marker: `5.1.2` -> `5.2.0`
- Kubernetes deployment image: `5.1.2` -> `5.2.0`

#### Tests
- 83 new tests covering status taxonomy, all 3 layers, authority contract, fail-closed enforcement, advisory checks, proof hashing, serialization round-trip, legacy migration, frozen dataclass immutability, and realistic scenarios drawn from the 10 blocked issues.

#### Included PRs
- `#206` feat(diagnostics): unified 3-layer DiagnosticResult model (#204)

## [5.1.2] - 2026-06-14
### Security: SymPy Expression Injection Fix (CWE-95)

Emergency patch fixing a **High severity (CVSS 8.8) authenticated RCE vulnerability** in SymPy `parse_expr()` across all math verification paths.

#### Security Fix
- **CWE-95 mitigation**: Added `safe_parse_expr()` wrapper with denylist, stripped `__builtins__`, allow-listed math namespace, per-call global dict copy, and post-parse validation. Replaced all 17 direct `parse_expr()` call sites in `main.py`, `verifier.py`, `batch.py`, and `validator.py`.
- **Symbol consistency**: Added `get_safe_symbol()` to ensure calculus variables (`n`, Greek letters) match special SymPy assumptions, preventing incorrect `diff`/`integrate`/`limit` results.
- **Defense-in-depth**: Pre-parse AST depth limit, post-parse SymPy tree depth validation, `sympy.Expr` type enforcement, `extra_symbols` key/value validation, and sanitized exception handling.

#### Fixes and Hardening
- **Cache Redis fail-closed**: Enforced fail-closed Redis backend for distributed cache mode (PR #199).
- **Benchmarks CI**: CodSpeed performance benchmark workflow added (PR #198).
- **TS SDK lockfile**: Restored `package-lock.json` for reliable `npm ci` in publish workflow (PR #197).

#### Included PRs since v5.1.1
- `#197` fix(ts-sdk): lockfile restore for npm ci publish
- `#198` ci: CodSpeed performance benchmarks
- `#199` fix(cache): fail-closed Redis backend for distributed mode
- `#200` fix(math): restrict sympy expression parsing (CWE-95)

## [5.1.1] - 2026-05-21
### Release Consistency and Fail-Closed Follow-Through

Patch release packaging the post-v5.1.0 trust-boundary and fail-closed corrections into a coherent publishable state across core package metadata, SDKs, deployment references, and release automation.

#### Trust Boundary and Correctness Fixes
- **Cache trust-context binding**: Bound verification cache artifacts to provider/model/policy/session trust context to prevent cross-context replay.
- **Attestation hardening**: Strengthened attestation verification with fail-closed behavior and follow-up review remediations.
- **Audit integrity improvements**: Tightened audit logging semantics around malformed payload handling, organization isolation, and transactional durability.
- **Proof-path corrections**: Refined reasoning, symbolic, batch, and agent-service fail-closed behavior where proof prerequisites or safe defaults were ambiguous.

#### Release and Deployment Alignment
- **Version propagation**: Aligned core package, API version marker, Python SDK metadata, TypeScript SDK metadata, and Rust SDK crate version on `5.1.1`.
- **Container reference alignment**: Updated Kubernetes deployment example to the published Docker Hub image/tag convention.
- **Release metadata cleanup**: Prepared package metadata and deployment references for a clean `v5.1.1` publish flow.

#### Included PRs and merged work since v5.1.0
- `#157` docs: README follow-up
- `#158` fix(docker): python 3.13 upgrade follow-up
- `#159` chore(deps): npm/yarn dependency follow-up in `sdk-ts`
- `#160` fix(schema): strict additional-properties enforcement follow-up
- `#161` fix(symbolic): fail closed when no proof exists
- `#168` fix(executor): secure executor fail-closed follow-up
- `#176` fix(agent): deny and handle unknown agent actions safely
- `#177` fix(reasoning): require proof prerequisites before reasoning acceptance
- `#178` and `#192` fix(cache): bind verification cache keys to trust context and address review follow-ups
- `#179` fix(audit): fail-closed audit logging, chain isolation, and transaction hardening
- `#180` fix(batch): separate batch math simplification from proof path
- `#186` chore(deps): pip dependency maintenance
- `#193` fix(tests): test-secret cleanup and PowerShell encoding hygiene

#### Upgrade Notes
- Deployments using the Kubernetes example should pull `docker.io/qwedai/qwed-verification:5.1.1` instead of the older `ghcr.io/qwed-ai/qwed-core` reference.
- This patch release focuses on stricter semantics, release consistency, and fail-closed enforcement rather than end-user feature expansion.

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
