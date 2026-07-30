# QWED Verification Framework — Adversarial Security Architecture Audit

**Auditor:** Principal Security Researcher / Formal Methods Reviewer  
**Date:** 2026-07-29  
**Scope:** Architectural trust guarantees, verification bypass, trust forgery, fail-open paths  
**Methodology:** Red-team analysis of implementation as source of truth  
**Prior Work Reviewed:** GitHub issues #162–#259, PRs #161–#261 (to avoid duplication)

---

## Executive Summary

The QWED verification framework has a well-designed `DiagnosticResult` model with structurally enforced invariants (VERIFIED requires `proof_ref`, non-VERIFIED forbids it). However, **the majority of verification endpoints bypass this model entirely**, returning raw dicts where `status: "VERIFIED"` is set without cryptographic proof artifacts. The `enforce_trust_decision` gate exists but is called in advisory-only mode (`require_attestation=False`) on the main code path. Several engines emit VERIFIED based on heuristic/probabilistic methods rather than deterministic proof. These are architectural failures that can violate the core verification thesis.

**Critical findings: 3 | High: 5 | Medium: 4 | Low: 2**

---

## FINDING 1: Consensus Verifier Emits VERIFIED Without proof_ref

**Severity:** Critical  
**Category:** Trust Boundary Violation / DiagnosticResult Invariant Violation  
**Affected Components:** `consensus_verifier.py`, `api/main.py` (`/verify/consensus`)

### Attack Scenario
An attacker submits a query to `/verify/consensus` with `verification_mode: "single"`. The SymPy engine evaluates the expression and returns `is_correct: True`. The consensus verifier sets `diagnostic_status = "VERIFIED"` and `confidence = 1.0`. The API endpoint returns this to the caller with `agreement_status: "unanimous"`. The caller treats this as authoritative verification.

### Why It Works
`_calculate_consensus` in `consensus_verifier.py` (line 789):
```python
diagnostic_status = "VERIFIED" if (status == "unanimous" and not blocked) else "UNVERIFIABLE"
```
This sets a string `"VERIFIED"` based on engine agreement, but:
1. The `ConsensusResult` dataclass has no `proof_ref` field — it's not a `DiagnosticResult`.
2. The "VERIFIED" is based on `is_correct` from `verify_math`, which is a **numerical tolerance comparison** (`diff <= tolerance_decimal`), not a formal proof.
3. The API endpoint at `/verify/consensus` returns the result without routing through `enforce_trust_decision`.
4. The `is_verified` field in `VerificationLog` is set as `result.confidence >= request.min_confidence` — a confidence threshold, not proof presence.

### Potential Impact
An attacker can obtain "VERIFIED" consensus results that are based on floating-point tolerance comparison rather than formal proof. These results carry no `proof_ref` and cannot be cryptographically validated downstream. The trust guarantee is forged.

### Recommended Fix
1. `ConsensusResult` must either be a `DiagnosticResult` or carry a `proof_ref` that is `None` unless a proof-bearing engine produced it.
2. `diagnostic_status = "VERIFIED"` must require `proof_ref is not None` — same invariant as `DiagnosticResult.__post_init__`.
3. The `/verify/consensus` endpoint must route through `enforce_trust_decision`.
4. Tolerance-based math comparison (`is_correct`) must not produce VERIFIED — it should produce UNVERIFIABLE with advisory_checks, or the math engine must be migrated to produce a proof artifact (convergence trace, symbolic simplification trace).

### Architectural Impact
**Can this violate the core verification thesis? YES** — VERIFIED is emitted without proof, based on numerical tolerance.

---

## FINDING 2: API Endpoints Return Raw Dicts with `status: "VERIFIED"` Bypassing DiagnosticResult

**Severity:** Critical  
**Category:** Trust Boundary Violation / State Machine Audit  
**Affected Components:** `api/main.py` (all `/verify/*` endpoints), `core/verifier.py`, `core/batch.py`

### Attack Scenario
An attacker calls `/verify/math` with `expression: "2+2"`. The endpoint parses the expression, simplifies it with SymPy, evaluates to `4.0`, and returns:
```json
{"is_valid": true, "value": 4.0, "simplified": "4", "original": "2 + 2"}
```
The `is_verified` field in the audit log is set to `true` based on `result.get("is_valid", False)`. No `DiagnosticResult` is constructed. No `proof_ref` exists. No attestation is issued or validated.

### Why It Works
Every API endpoint in `main.py` returns raw dicts from verifiers:
- `/verify/math` (line 590): `is_verified=result.get("is_valid", False)` — string-keyed dict check
- `/verify/sql` (line 646): `is_verified=result.get("is_valid", False)`
- `/verify/code` (line 424): `is_verified=result.get("is_safe", False)`
- `/verify/natural_language` (line 218): `is_verified=result.get("status") == "VERIFIED"`
- `/verify/logic` (line 258): `is_verified=(result["status"] == "SAT" or result["status"] == "UNSAT")`

None of these endpoints:
1. Construct a `DiagnosticResult` (which would enforce the proof_ref invariant)
2. Call `enforce_trust_decision` (the trust boundary gate)
3. Issue or validate attestations
4. Check for `proof_ref` presence

The `VerificationEngine` in `verifier.py` returns dicts with `"status": "VERIFIED" if is_correct else "CORRECTION_NEEDED"` (line 157) — this is tolerance-based comparison, not proof. The `from_legacy_dict` guard exists but is never invoked for these endpoints.

### Potential Impact
Every verification endpoint can return "VERIFIED" (or equivalent `is_valid: true`) without any proof artifact. Downstream consumers checking `is_verified` in the audit log or the response dict will trust these results. The `DiagnosticResult` invariant enforcement is completely bypassed.

### Recommended Fix
1. Every `/verify/*` endpoint must construct a `DiagnosticResult` from the engine output.
2. Every endpoint must call `enforce_trust_decision(result, require_attestation=True, query=...)` before returning.
3. The `VerificationLog.is_verified` field must be set based on `result.is_authoritative` (proof_ref presence), not string comparison.
4. Engines not yet migrated to `DiagnosticResult` (open issues #252–#256) must use `from_legacy_dict` which correctly refuses to produce VERIFIED without proof.

### Architectural Impact
**Can this violate the core verification thesis? YES** — VERIFIED is emitted and consumed without proof across all primary endpoints.

---

## FINDING 3: Control Plane Trust Enforcement Is Advisory-Only (Fail-Open)

**Severity:** Critical  
**Category:** Fail-Closed Verification / Trust Boundary Violation  
**Affected Components:** `core/control_plane.py`

### Attack Scenario
An attacker calls `/verify/natural_language`. The control plane translates the query, runs `verify_math`, gets `status: "VERIFIED"`. The trust boundary enforcement code runs:
```python
enforced = enforce_trust_decision(
    dr,
    require_attestation=False,  # ← ADVISORY MODE
    query=query,
)
```
Because `require_attestation=False`, the function returns the original result even if no attestation token exists. The response includes `trust_enforced: "VERIFIED"` and `attestation_policy: "advisory"`. The caller sees "VERIFIED" and trusts it.

### Why It Works
In `control_plane.py` (line 142):
```python
enforced = enforce_trust_decision(
    dr,
    require_attestation=False,
    query=query,
)
```
The comment says "Advisory mode (require_attestation=False) until engines are fully migrated to DiagnosticResult." But this means:
1. VERIFIED results pass through without attestation validation.
2. No attestation token is issued or required.
3. The `trust_enforced` field in the response is set to the enforced status, but since enforcement is advisory, it's always the original status.
4. If `from_legacy_dict` raises (which it does for legacy VERIFIED results), the code catches the exception and sets `trust_enforced: "not_applicable"` — but still returns the original VERIFIED result to the caller.

### Potential Impact
The trust boundary gate exists but is effectively disabled. Any VERIFIED result from the math engine passes through to the caller without attestation. The "enforcement" is cosmetic.

### Recommended Fix
1. Set `require_attestation=True` for all production paths.
2. Issue attestations via `create_verification_attestation` for every VERIFIED result.
3. If attestation issuance fails (BLOCKED/UNVERIFIABLE), the result must be downgraded to UNVERIFIABLE — not returned as VERIFIED.
4. The `except ValueError` block that catches `from_legacy_dict` failures must not return the original VERIFIED result — it must return UNVERIFIABLE.

### Architectural Impact
**Can this violate the core verification thesis? YES** — the trust gate is disabled, making VERIFIED results non-authoritative by default.

---

## FINDING 4: FactVerifier Emits VERIFIED for TF-IDF Heuristic Similarity

**Severity:** High  
**Category:** DiagnosticResult Invariant Violation / Advisory-Only Engine Emitting VERIFIED  
**Affected Components:** `core/fact_verifier.py`

### Attack Scenario
An attacker submits a claim "The sky is blue" with context "The sky appears blue during clear weather." The FactVerifier computes:
- `semantic_score` = TF-IDF cosine similarity (0.85)
- `keyword_score` = keyword overlap (0.75)
- `entity_match` = entity matching (1.0)
- `has_negation` = False
- `aggregate` = 0.85 * 0.3 + 0.75 * 0.3 + 1.0 * 0.2 + 0.2 = 0.88

Since `aggregate >= 0.7` and support citations >= refute citations, `verdict = "SUPPORTED"`, `confidence = 0.88`. The verifier returns `DiagnosticResult.verified(...)` with `evidence = {"citations": ..., "reasoning": ...}`.

The `proof_ref` is computed as `compute_proof_ref(evidence)` where evidence is `{"citations": [...], "reasoning": "..."}`. This is a hash of heuristic analysis output, not a cryptographic proof of factual correctness.

### Why It Works
In `fact_verifier.py` (line 223-229):
```python
if verdict == "SUPPORTED":
    evidence = {"citations": developer_fields["citations"], "reasoning": reasoning}
    return DiagnosticResult.verified(
        "Fact claim verified by deterministic analysis",
        developer_fields,
        evidence,
    )
```
The "SUPPORTED" verdict is based on:
1. TF-IDF cosine similarity — a lexical overlap metric, not semantic proof
2. Keyword overlap — set intersection, not meaning
3. Entity matching — regex-extracted numbers/names
4. Negation detection — word-list matching

These are **heuristic methods**. The `evidence` dict contains citations and reasoning strings, but hashing heuristic output produces a `proof_ref` that binds to the heuristic analysis, not to a proof of factual correctness. Two different claims with similar word distributions could produce the same "SUPPORTED" verdict.

### Potential Impact
An attacker can craft claims with high keyword overlap and entity match scores that get VERIFIED despite being factually incorrect. The `proof_ref` provides false assurance — it proves the heuristic ran, not that the claim is true.

### Recommended Fix
1. FactVerifier should be classified as **advisory-only** (like Image, Graph, Reasoning engines per PR #260).
2. Replace `DiagnosticResult.verified(...)` with `DiagnosticResult.unverifiable(...)` with `advisory_checks` containing the heuristic analysis.
3. The `evidence` dict should not be hashed into a `proof_ref` for heuristic methods.

### Architectural Impact
**Can this violate the core verification thesis? YES** — VERIFIED is emitted for heuristic analysis, not deterministic proof.

---

## FINDING 5: AgentStateGuard Emits VERIFIED with String "proof" Instead of proof_ref

**Severity:** High  
**Category:** Trust Boundary Violation / DiagnosticResult Invariant Violation  
**Affected Components:** `guards/agent_state_guard.py`

### Attack Scenario
An agent submits a state payload that matches the configured JSON schema. The `AgentStateGuard.verify_state_payload` returns:
```python
{
    "verified": True,
    "status": "VERIFIED",
    "proof": "State payload matched the configured strict schema.",
    "normalized_state": self._canonicalize(state_data),
}
```
A downstream consumer checks `result["verified"]` or `result["status"] == "VERIFIED"` and admits the state transition. No `proof_ref` exists. The "proof" is a human-readable string, not a cryptographic hash.

### Why It Works
`AgentStateGuard` returns plain dicts, not `DiagnosticResult` objects. The `"proof"` field is a descriptive string ("State payload matched the configured strict schema."), not a `sha256:...` proof reference. The `"verified": True` flag is set based on schema validation passing, but:
1. Schema validation is structural, not semantic — it checks types and required fields, not correctness.
2. No `proof_ref` is computed from the normalized state.
3. No attestation is issued.
4. The dict format bypasses `DiagnosticResult.__post_init__` invariant enforcement.

### Potential Impact
An attacker can submit a state payload that structurally matches the schema but is semantically invalid. The guard returns VERIFIED, and downstream consumers trust it. The "proof" string provides no cryptographic binding to the verified state.

### Recommended Fix
1. Return `DiagnosticResult` instead of raw dicts.
2. Compute `proof_ref = compute_proof_ref(normalized_state)` for VERIFIED results.
3. The "proof" string should be in `developer_fields`, not a top-level field masquerading as cryptographic proof.

### Architectural Impact
**Can this violate the core verification thesis? YES** — VERIFIED is emitted without proof_ref, with a string "proof" that is not cryptographic.

---

## FINDING 6: Consensus `_verify_with_code` Emits VERIFIED for Successful Code Execution

**Severity:** High  
**Category:** Trust Boundary Violation / Proof Integrity  
**Affected Components:** `consensus_verifier.py` (`_verify_with_code`)

### Attack Scenario
An attacker submits a query to consensus verification with `mode: "high"`. The Python engine generates code `result = 2+2`, executes it in Docker, gets `output = 4`. The engine returns:
```python
EngineResult(
    engine_name="Python",
    method="code_execution",
    result=output,
    confidence=0.99,
    success=True,
    status="VERIFIED",  # ← Based on execution success, not proof
)
```
The consensus calculator sees unanimous agreement and sets `diagnostic_status = "VERIFIED"`.

### Why It Works
In `consensus_verifier.py` (line 641-646):
```python
return EngineResult(
    engine_name="Python", method="code_execution",
    result=output, confidence=0.99,
    latency_ms=(time.time() - start) * 1000, success=True,
    status="VERIFIED",
)
```
Code execution success means the code ran without errors and produced output — it does **not** prove the output is correct. Running `result = 2+2` and getting `4` is empirical testing, not formal verification. The code could have a bug that happens to produce the expected output for the test input but fails for other inputs.

### Potential Impact
An attacker can get "VERIFIED" consensus results based on code execution, which is empirical testing, not proof. This is especially dangerous in "maximum" mode where code execution is one of multiple engines — its "VERIFIED" vote contributes to consensus.

### Recommended Fix
1. `_verify_with_code` should return `status="UNVERIFIABLE"` with `advisory_checks` containing the execution result.
2. Code execution is advisory — it can disprove (by crashing) but cannot prove correctness.
3. Only formal methods (Z3, symbolic execution with completeness proof) should emit VERIFIED.

### Architectural Impact
**Can this violate the core verification thesis? YES** — empirical code execution is treated as proof.

---

## FINDING 7: Attestation Verification Only Supports Self-Issued Tokens (Single-Node Trust)

**Severity:** High  
**Category:** Attestation Integrity / Cryptographic Hygiene  
**Affected Components:** `core/attestation.py` (`verify_attestation`)

### Attack Scenario
A distributed deployment has Node A issue an attestation. Node B receives the attestation token and calls `verify_attestation`. Since the issuer DID doesn't match Node B's `self.issuer_did`, the code reaches:
```python
return False, None, "External issuer key resolution not implemented"
```
The attestation is rejected. Node B cannot verify any attestation issued by Node A.

### Why It Works
In `attestation.py` (line 411-413):
```python
else:
    # Would need to resolve DID and get public key
    return False, None, "External issuer key resolution not implemented"
```
The attestation system only supports self-issued tokens. The `trusted_issuers` parameter accepts a list of DIDs, but there's no mechanism to resolve a DID to a public key. This means:
1. In distributed deployments, attestations issued by one node cannot be verified by another.
2. The trust model is fundamentally single-node.
3. After a process restart (ephemeral key policy), all previously issued attestations become unverifiable — even by the same node.

### Potential Impact
In any multi-node deployment, the attestation system is non-functional. Nodes cannot verify each other's attestations, making `enforce_trust_decision` useless for cross-node trust. If `require_attestation=True` were enabled, all cross-node verification would fail-closed (BLOCKED), which is safe but non-functional.

### Recommended Fix
1. Implement DID resolution to retrieve public keys for external issuers.
2. Support persistent key storage (not just "ephemeral") for production deployments.
3. Document that the current implementation is single-node only and `enforce_trust_decision` with `require_attestation=True` will fail-closed in distributed mode.

### Architectural Impact
**Can this violate the core verification thesis? NO** — it fails closed, but it makes the trust system non-functional in distributed deployments.

---

## FINDING 8: Attestation `jti` and `iat` Use Non-Deterministic Defaults (Issue #250)

**Severity:** High  
**Category:** Determinism / Attestation Integrity  
**Affected Components:** `core/attestation.py` (`create_attestation`)

### Attack Scenario
An auditor attempts to reproduce an attestation by re-running the same verification with the same inputs. The new attestation has a different `jti` (UUID) and `iat` (timestamp), producing a different JWT. The auditor cannot verify that the original attestation was deterministically issued from the verification result.

### Why It Works
In `attestation.py` (lines 282-284):
```python
now = issued_at if issued_at is not None else int(time.time())
expiry = now + (self.validity_days * 24 * 60 * 60)
attestation_id = jti if jti is not None else f"att_{uuid.uuid4().hex[:12]}"
```
While `issued_at` and `jti` are injectable for determinism, the defaults use `time.time()` and `uuid.uuid4()`. This means:
1. Two identical verification results produce different attestations.
2. The attestation cannot be reproduced from the verification result alone.
3. The `proof_hash` in the attestation is bound to the proof data, but the attestation itself is non-deterministic.

### Potential Impact
Non-deterministic attestations break reproducibility guarantees. An attacker could argue that a given attestation was fabricated because it cannot be reproduced. Audit trails become non-verifiable.

### Recommended Fix
This is already tracked in Issue #250. The fix should:
1. Remove `time.time()` and `uuid.uuid4()` defaults.
2. Require `issued_at` and `jti` to be explicitly provided.
3. Derive `jti` deterministically from the verification result hash.

### Architectural Impact
**Can this violate the core verification thesis? NO** — non-determinism affects reproducibility, not trust correctness. But it weakens auditability.

---

## FINDING 9: Batch Math Verification Returns `is_valid: True` Without Proof

**Severity:** Medium  
**Category:** Trust Boundary Violation / Proof Integrity  
**Affected Components:** `core/batch.py` (`_verify_item`)

### Attack Scenario
An attacker submits a batch with `{"query": "x**2 + 2*x + 1 = (x+1)**2", "type": "math"}`. The batch processor:
```python
left, right = expression.split("=", 1)
left_expr = safe_parse_expr(left)
right_expr = safe_parse_expr(right)
diff = simplify(left_expr - right_expr)
is_valid = diff == 0
return {"is_valid": is_valid, "type": "math", "message": "Identity verified"}
```
Returns `is_valid: True` based on SymPy simplification. No `DiagnosticResult`, no `proof_ref`, no attestation.

### Why It Works
The batch math path (line 222-237) directly uses `simplify(left - right) == 0` to determine validity. While SymPy simplification is deterministic, the result is returned as a raw dict without:
1. `DiagnosticResult` construction
2. `proof_ref` computation
3. `enforce_trust_decision` validation
4. Attestation issuance

### Potential Impact
Batch verification results carry the same trust as individual verification but without any of the trust boundary enforcement. An attacker can use batch endpoints to obtain "verified" results that bypass the (already advisory) trust gate in the control plane.

### Recommended Fix
1. Route batch math verification through `DiagnosticResult.verified()` with evidence.
2. Call `enforce_trust_decision` on each batch item result.
3. Set `is_verified` in batch results based on `proof_ref` presence.

### Architectural Impact
**Can this violate the core verification thesis? YES** — VERIFIED (as `is_valid: True`) is emitted without proof in batch mode.

---

## FINDING 10: `verify_attestation` Decodes Payload Before Signature Verification (Information Leakage)

**Severity:** Medium  
**Category:** Cryptographic Hygiene / Attestation Integrity  
**Affected Components:** `core/attestation.py` (`verify_attestation`)

### Attack Scenario
An attacker sends a malformed JWT with a valid structure but invalid signature. The `verify_attestation` function:
1. Splits the JWT and extracts the payload segment
2. Base64-decodes the payload
3. Parses it as JSON
4. Extracts the `iss` claim
5. Checks if `iss` is in `trusted_issuers`
6. Only then attempts cryptographic verification

The attacker can observe different error messages for "Untrusted issuer" vs "Invalid token" vs "Token too large", enabling issuer enumeration and format probing.

### Why It Works
In `attestation.py` (lines 381-413):
```python
# Decode without verification first to get issuer.
unverified = json.loads(payload_data)
issuer = unverified.get("iss")
if issuer not in trusted_issuers:
    return False, None, f"Untrusted issuer: {safe_issuer}"
# ... then verify signature
claims = jwt.decode(jwt_token, public_key, algorithms=["ES256"], ...)
```
The `iss` claim is checked before signature verification. While the claims aren't "trusted" until after signature verification, the error message difference reveals whether the `iss` value matches a trusted issuer.

### Potential Impact
An attacker can enumerate trusted issuer DIDs by observing error messages. This is information leakage, not direct trust forgery, but it aids reconnaissance.

### Recommended Fix
1. Perform signature verification first, then check `iss` against `trusted_issuers`.
2. Return a generic "Invalid token" error for all failures (untrusted issuer, invalid signature, expired, etc.).
3. Log detailed errors server-side only.

### Architectural Impact
**Can this violate the core verification thesis? NO** — information leakage, not trust forgery.

---

## FINDING 11: AgentStateGuard Canonicalization Lacks Unicode Normalization

**Severity:** Medium  
**Category:** Canonicalization  
**Affected Components:** `guards/agent_state_guard.py` (`_canonicalize`)

### Attack Scenario
An attacker submits two state payloads:
1. `{"name": "caf\u00e9", "value": 1}` (NFC form: `é` = U+00E9)
2. `{"name": "cafe\u0301", "value": 1}` (NFD form: `é` = U+0065 + U+0301)

Both are semantically identical, but `_canonicalize` sorts dict keys and recursively processes values without Unicode normalization. The two payloads produce different `normalized_state` outputs and different verification results if compared.

### Why It Works
In `agent_state_guard.py` (line 903-911):
```python
@classmethod
def _canonicalize(cls, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: cls._canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [cls._canonicalize(item) for item in value]
    return value
```
No `unicodedata.normalize()` is applied. String values and keys are compared as-is. Python's `sorted()` uses code-point ordering, which differs between NFC and NFD forms of the same character.

### Potential Impact
Logically equivalent state payloads with different Unicode representations can produce different verification outcomes. An attacker could exploit this to bypass transition rules by submitting NFD-encoded state that differs from the NFC-encoded current state at the byte level but is semantically identical.

### Recommended Fix
1. Apply `unicodedata.normalize("NFC", value)` to all string values and keys in `_canonicalize`.
2. Document the normalization policy in the guard's contract.

### Architectural Impact
**Can this violate the core verification thesis? NO** — but it can create inconsistent verification states for equivalent inputs.

---

## FINDING 12: `enforce_trust_decision` Has TOCTOU Between Validation and Return

**Severity:** Medium  
**Category:** Time-of-Check / Time-of-Use (TOCTOU)  
**Affected Components:** `core/diagnostics.py` (`enforce_trust_decision`)

### Attack Scenario
`enforce_trust_decision` validates the attestation token against the `result` object, then returns the original `result` object:
```python
validation = _validate_attestation_claims(result, token_claims, query, policy)
if validation is not None:
    return validation
return result  # ← Original mutable reference returned
```
If the caller modifies `result` after `enforce_trust_decision` returns (e.g., changing `developer_fields`), the validated state diverges from the returned state.

### Why It Works
`DiagnosticResult` is `frozen=True`, so `status` and `proof_ref` are immutable. However, `developer_fields` is a `Dict[str, Any]` which is **mutable**. The `result.developer_fields` dict can be modified after enforcement, and the attestation token's claims (which were validated against `result.status` and `result.proof_ref`) would still appear valid but no longer match the modified result.

### Potential Impact
An attacker who can modify the `developer_fields` dict after enforcement can change the evidence associated with a VERIFIED result without invalidating the attestation. The `proof_ref` and `status` are immutable, but the developer-facing evidence can be tampered with.

### Recommended Fix
1. Deep-copy `developer_fields` before returning from `enforce_trust_decision`.
2. Or make `developer_fields` immutable (e.g., `MappingProxyType`).

### Architectural Impact
**Can this violate the core verification thesis? NO** — `proof_ref` and `status` are immutable. But developer evidence can be tampered with post-verification.

---

## FINDING 13: Cache Keys for `cached_verify` Don't Include Tenant Context

**Severity:** Low  
**Category:** Trust Boundary Violation / Cache Integrity  
**Affected Components:** `core/cache.py` (`cached_verify`, `VerificationCache._generate_key`)

### Attack Scenario
Tenant A verifies `(AND (GT x 5) (LT y 10))` and the result is cached. Tenant B submits the same DSL code. Since `cached_verify` uses `LOCAL_ONLY` mode with no tenant_id, the cache key is `hash({"dsl": "...", "vars": None})` — same for both tenants. Tenant B gets Tenant A's cached result.

### Why It Works
`cached_verify` (line 813):
```python
cache = get_cache(use_redis=False, mode=CacheBackendMode.LOCAL_ONLY)
```
This creates a global `VerificationCache` with no tenant isolation. The `_generate_key` method only uses `dsl_code` and `variables`, not tenant context. While `get_cache` supports `tenant_id` for Redis mode, the `LOCAL_ONLY` convenience wrapper doesn't pass it.

### Potential Impact
Cross-tenant cache leakage in single-process deployments using `cached_verify`. Tenant B can receive Tenant A's verification results, including potentially sensitive evidence in the result dict.

### Recommended Fix
1. `cached_verify` should accept and pass `tenant_id` to `get_cache`.
2. Or document that `cached_verify` is for single-tenant use only.

### Architectural Impact
**Can this violate the core verification thesis? NO** — but it's a data isolation violation.

---

## FINDING 14: `_verify_with_stats` in Consensus Emits VERIFIED for Statistical Computation

**Severity:** Low  
**Category:** Trust Boundary Violation  
**Affected Components:** `consensus_verifier.py` (`_verify_with_stats`)

### Attack Scenario
An attacker submits "What is the average of 1, 2, 3?" to consensus verification. The Stats engine computes `statistics.mean([1, 2, 3]) = 2.0` and returns `status="VERIFIED"`. But computing a mean is not verification — it's computation. There's no claim being verified, just a calculation being performed.

### Why It Works
In `consensus_verifier.py` (line 697-704):
```python
return EngineResult(
    engine_name="Stats", method="statistical_analysis",
    result=result,
    confidence=0.98 if result is not None else 0.0,
    success=result is not None,
    status="VERIFIED" if result is not None else "UNVERIFIABLE",
)
```
`status="VERIFIED"` is set whenever a statistical computation succeeds, regardless of whether a claim was actually verified.

### Recommended Fix
1. Statistical computation should produce `UNVERIFIABLE` with advisory_checks containing the computed value.
2. Only comparison against a claimed value (with proof of correctness) should produce VERIFIED.

### Architectural Impact
**Can this violate the core verification thesis? YES** — computation is conflated with verification.

---

## AREAS THAT APPEAR SOUND

### Attestation Issuance Fail-Closed (Issue #188 — Fixed)
`create_verification_attestation` correctly returns `AttestationResult` with `BLOCKED` or `UNVERIFIABLE` status on failure. The `verified and not proof_data` check (line 520) correctly blocks VERIFIED attestations without proof. The `AttestationResult.is_issued` property provides a clear contract.

### DiagnosticResult Invariant Enforcement
`DiagnosticResult.__post_init__` correctly enforces:
- VERIFIED requires `proof_ref is not None`
- Non-VERIFIED requires `proof_ref is None`
- `agent_message` must be non-empty

The `from_legacy_dict` method correctly refuses to produce VERIFIED from legacy data. The `AdvisoryCheck.advisory_only` field is structurally enforced to `True`.

### Cache Fail-Closed (Issue #189 — Fixed)
`RedisCache` in `STRICT_DISTRIBUTED` mode correctly raises `CacheBackendUnavailableError` when Redis is unavailable. The `EXPLICIT_DEGRADED` mode tags results with `_degraded_mode=True`. The per-tenant cache isolation in `get_cache` prevents cross-tenant leakage in Redis mode.

### Safe Parser (CWE-95 — Fixed)
`safe_parse_expr` correctly:
- Removes `__builtins__` from eval global dict
- Uses a denylist for dangerous constructs
- Enforces AST depth limits (30) and SymPy tree depth limits (40)
- Validates expression length (5000 chars)
- Restricts the evaluation namespace to math symbols only

### Audit Logger Chain Integrity (Issue #173 — Fixed)
`AuditLogger` correctly:
- Requires `QWED_AUDIT_SECRET_KEY` environment variable (fail-closed)
- Uses HMAC-SHA256 for signatures with `hmac.compare_digest`
- Verifies chain continuity before appending
- Uses `BEGIN IMMEDIATE` for SQLite serialization

### Reasoning Verifier Advisory-Only (Issue #164 — Fixed)
`ReasoningVerifier._to_diagnostic_result` correctly returns `DiagnosticResult.unverifiable(...)` for all cases, with heuristic analysis in `advisory_checks`. No VERIFIED is emitted.

### Symbolic Verifier Fail-Closed (Issue #161 — Fixed)
`SymbolicVerifier` correctly returns `UNVERIFIABLE` for "no counterexample found" (not VERIFIED), acknowledging that timeout-bounded search is not a completeness proof.

---

## SUMMARY TABLE

| # | Finding | Severity | Core Thesis Violation | Already Tracked? |
|---|---------|----------|----------------------|------------------|
| 1 | Consensus emits VERIFIED without proof_ref | Critical | YES | No |
| 2 | API endpoints bypass DiagnosticResult | Critical | YES | Partially (#258) |
| 3 | Control plane trust enforcement is advisory-only | Critical | YES | No |
| 4 | FactVerifier emits VERIFIED for heuristics | High | YES | No |
| 5 | AgentStateGuard emits VERIFIED with string "proof" | High | YES | No |
| 6 | Code execution treated as proof in consensus | High | YES | No |
| 7 | Attestation only supports self-issued tokens | High | NO | No |
| 8 | Non-deterministic attestation defaults | High | NO | YES (#250) |
| 9 | Batch math returns is_valid without proof | Medium | YES | No |
| 10 | Payload decoded before signature verification | Medium | NO | No |
| 11 | No Unicode normalization in canonicalization | Medium | NO | No |
| 12 | TOCTOU in enforce_trust_decision | Medium | NO | No |
| 13 | Cache keys lack tenant context | Low | NO | No |
| 14 | Stats computation treated as verification | Low | YES | No |

---

## RECOMMENDED PRIORITY ORDER

1. **Finding 3** (Control plane advisory-only) — Flip `require_attestation=True` and issue attestations. This is the single change that activates the trust boundary.
2. **Finding 2** (API endpoints bypass DiagnosticResult) — Route all endpoints through `DiagnosticResult` + `enforce_trust_decision`.
3. **Finding 1** (Consensus VERIFIED without proof) — Add `proof_ref` to `ConsensusResult` or convert to `DiagnosticResult`.
4. **Finding 4** (FactVerifier VERIFIED for heuristics) — Reclassify as advisory-only.
5. **Finding 5** (AgentStateGuard string "proof") — Convert to `DiagnosticResult` with `proof_ref`.
6. **Finding 6** (Code execution as proof) — Reclassify as advisory-only in consensus.
7. **Finding 7** (Single-node attestation) — Implement DID resolution or document limitation.
8. **Finding 8** (Non-deterministic defaults) — Already tracked in #250.

---

*This audit was conducted with red-team mindset, treating the implementation as the source of truth. Existing documentation was not assumed correct. Every finding was verified against the actual code.*