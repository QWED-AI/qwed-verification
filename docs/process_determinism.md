# Process Determinism: The "Glass Box" Architecture

**Status:** Completed (Phase 15)  
**Authors:** QWED Research & Engineering  
**Version:** 3.1.0 (Category Definition Release)

---

## 1. Abstract: The Shift to Glass Box Verification

Traditional evaluation verifies **correctness** (Did the model get the right answer?).  
QWED Process Determinism verifies **reasoning integrity** (Did the model follow the required logical path?).

In high-stakes domains (Law, Finance, Statistics), a correct answer derived from flawed reasoning is a liability (e.g., a correct tax calculation based on a repealed law).

> **"We verify not just what the model concluded, but how it reached that conclusion."**

---

## 2. The Determinism Spectrum

Determinism in AI verification is not binary. We categorize it into layers:

| Layer | Determinism Type | Mechanism | Certainty |
| :--- | :--- | :--- | :--- |
| **Math** | Computational | Symbolic Solvers (SymPy/Z3) | Absolute (100%) |
| **Logic** | Formal | SMT Provers | Absolute (100%) |
| **Code** | Structural | AST Analysis | High (>99%) |
| **Process** | **Structural** | **Pattern + Milestone Checks** | **High (>95%)** |
| **Facts** | Probabilistic | Retrieval Scoring | Variable |

**Process Determinism** sits in the "High" certainty tier. It is structural, not semantic. It ensures the *skeleton* of the reasoning is intact.

---

## 3. Core Architecture

### 3.1 The Process Verifier (Reasoned Elaboration)
Located in `src/qwed_new/guards/process_guard.py`.

#### A. IRAC Structure Enforcement (Legal Standard)
Inspired by evaluation methodologies in the **MSLR Benchmark** [Source 154], we enforce the "Reasoned Elaboration" standard.
We use **structural detection, not semantic scoring**.

> **Note:** Our Regex detection ensures *completeness*, not legal validity. It guarantees the model *attempted* an analysis, not that the analysis is legally sound (a higher-order logic problem).

#### B. Milestone Verification (Process Rate)
Inspired by **LegalAgentBench** [Source 716], we verify **Process Rate**: the percentage of mandatory intermediate steps successfully executed.

### 3.2 System Flow

```mermaid
graph TD
    UserQuery[User Query] --> LLM[LLM Reasoning Trace]
    LLM --> PV[ProcessVerifier]
    PV --> IRAC[IRAC Structural Check]
    PV --> Milestone[Milestone Coverage]
    PV --> Continuity[Trace Continuity]
    IRAC --> Verdict{Verified?}
    Milestone --> Verdict
    Continuity --> Verdict
    Verdict -- Pass --> OutputVerifier[Output Verifier (Math/Code)]
    Verdict -- Fail --> Block[Security Event (Sentry)]
```

---

## 4. Failure Modes: What Traditional Eval Misses

| Scenario | Output | Traditional Eval | QWED Process |
| :--- | :--- | :--- | :--- |
| **Correct tax calc via wrong law** | Correct | ✅ Pass | ❌ **Fail** (Rule Missing) |
| **Contract ruling without jurisdiction check** | Correct | ✅ Pass | ❌ **Fail** (Milestone Missed) |
| **Loan approval without risk scoring** | Correct | ✅ Pass | ❌ **Fail** (Step Skipped) |
| **ERP action without reconciliation** | Correct | ✅ Pass | ❌ **Fail** (Process Rate < 1.0) |

This demonstrates why **Process Determinism** is critical for enterprise safety: it catches the "Right Answer, Wrong Method" risks.

---

## 5. Verification Integrity Controls ("Code Determinism")

We verify the verifier. To guarantee audit reproducibility, our verification engine itself must be deterministic.
This is enforced via **CodeRabbit** configuration (`.coderabbit.yaml`):

1.  **No Non-Determinism:** Usage of `random`, `uuid4`, `datetime.now()` is blocked in verification logic.
2.  **Symbolic Math:** Floats are banned in favor of `decimal` or `sympy`.
3.  **Security:** `eval()` is strictly controlled.

This prevents "Heisenbugs" in the audit layer itself.

---

## 6. Observability: Audit Control Plane

Failed reasoning is treated as a **Security Violation**, not just a model error.
Using **Sentry**, we provide a **Verification Telemetry Control Plane**:

*   **Hallucination Frequency:** How often does the model attempt invalid reasoning?
*   **Domain Risk Hotspots:** Which legal areas (e.g., Torts vs. Contracts) fail most often?
*   **Agent Failure Heatmaps:** Which agent version has the lowest Process Rate?

---

## 7. Supply Chain Trust

Our CI/CD pipeline (Snyk Container Scanning + Hash Pinning) ensures the verifier cannot be compromised by poisoned dependencies. This preserves **trust in the trust layer itself**.

---

## 8. Strategic Implication

QWED Process Determinism shifts AI verification from:
*   **Output Validation** &rarr; **Decision Auditing**
*   **Model Safety** &rarr; **Workflow Governance**
*   **Guardrails** &rarr; **Trust Infrastructure**

We are not just building a verifier; we are defining the **Audit Infrastructure** for the Agentic Economy.
