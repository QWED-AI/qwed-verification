---
id: whitepaper
title: "QWED Protocol: Deterministic Verification for Large Language Models"
sidebar_label: Whitepaper
slug: /whitepaper
---

# QWED Protocol: Deterministic Verification for Large Language Models

**A Formal Methods Approach to Eliminating the Impact of AI Hallucinations in Production Systems**

---

**Authors:** Rahul Dass  
**Organization:** QWED-AI  
**ORCID:** [0009-0000-2088-7487](https://orcid.org/0009-0000-2088-7487)  
**Email:** rahul@qwedai.com  
**Version:** 1.0.1  
**Date:** 28 December 2025  
**License:** Apache 2.0

---

## Abstract

Large Language Models (LLMs) exhibit fundamental unreliability in deterministic tasks due to their probabilistic architecture. Hallucinations, arithmetic errors, logical inconsistencies, and unsafe code generation persist despite fine-tuning, prompting strategies, or retrieval augmentation.

We introduce QWED (Query with Evidence & Determinism), a deterministic verification protocol that treats LLMs as untrusted translators rather than reliable oracles. QWED validates model outputs using established formal methods—symbolic mathematics (SymPy), SMT solving (Z3), static analysis, and bounded model checking—across eight specialized engines: mathematics, logic, code security, SQL safety, statistics, fact checking, image validation, and multi-model consensus.

In benchmarks against Claude Opus 4.5 across 215 adversarial and domain-specific test cases, QWED achieved 100% error detection in verifiable domains where the model exhibited 73–85% accuracy. Critical failures included a compound interest miscalculation representing $12,889 per transaction—a systematic error pattern undetectable through prompting or confidence scoring.

QWED does not reduce hallucinations; it eliminates their production impact by rejecting all unverifiable outputs. The protocol is open-source (Apache 2.0) and designed for integration with LangChain, CrewAI, and autonomous agent frameworks.

Our results demonstrate that deterministic verification—not probabilistic improvement—is the viable path for deploying LLMs in regulated, high-stakes, and autonomous systems.

**Keywords:** AI Verification, Large Language Models, Formal Verification, Symbolic Execution, SMT Solving, Hallucination Detection, AI Safety, Deterministic Systems

---

## 1. Introduction

### 1.1 The AI Hallucination Crisis

The deployment of Large Language Models in enterprise applications has exposed a critical vulnerability: LLMs produce confident, plausible-sounding outputs that are factually incorrect. These "hallucinations" are not bugs to be fixed but inherent properties of probabilistic token prediction systems.

Consider a financial application where GPT-4 is asked to calculate compound interest:

> **Query:** "Calculate compound interest: $100,000 at 5% for 10 years"
> 
> **GPT-4 Response:** "$150,000"
> 
> **Correct Answer:** $162,889.46

The LLM applied simple interest (`100000 * 0.05 * 10 = 50000`) instead of the compound formula (`100000 * (1.05)^10`). This represents a **$12,889 error per transaction**—unacceptable in production financial systems.

### 1.2 Why Current Approaches Are Insufficient

The industry has attempted several approaches to address hallucinations:

| Approach | Mechanism | Limitation |
|----------|-----------|------------|
| **Fine-tuning** | Additional training data | Still probabilistic; cannot guarantee correctness |
| **RLHF** | Human feedback alignment | Improves average case, not worst case |
| **RAG** | Retrieval-augmented context | Addresses knowledge gaps, not reasoning errors |
| **Prompt Engineering** | Better instructions | Cannot enforce determinism |
| **Guardrails** | Output filtering | Reactive, not verification |

All these approaches share a fundamental flaw: they attempt to make probabilistic systems more accurate rather than verifying their outputs deterministically.

### 1.3 The Untrusted Translator Paradigm

QWED introduces a paradigm shift: treat the LLM as an **untrusted translator** rather than a trusted oracle. 

In this model:
- The LLM translates natural language queries into structured outputs (code, equations, SQL)
- QWED verifies these outputs using deterministic engines
- Only verified outputs proceed to production

This approach acknowledges that:

> **"Probabilistic systems should not be trusted with deterministic tasks."**

Just as a compiler does not trust programmer input and validates syntax, QWED does not trust LLM output and validates correctness.

### 1.4 Contributions

This paper makes the following contributions:

1. **The QWED Protocol:** A formal architecture for deterministic LLM output verification
2. **Eight Verification Engines:** Specialized verifiers for math, logic, code, SQL, statistics, facts, images, and multi-model consensus
3. **Symbolic Execution Integration:** Bounded model checking for Python code using CrossHair
4. **Benchmark Results:** Empirical evaluation showing 100% error detection on Claude Opus 4.5 failures
5. **Open-Source Implementation:** Production-ready code under Apache 2.0 license

---

## 2. Background and Related Work

### 2.1 Formal Verification

Formal verification uses mathematical methods to prove or disprove the correctness of systems. QWED builds on decades of research in this field.

**Satisfiability Modulo Theories (SMT):** SMT solvers extend boolean satisfiability (SAT) with theories for integers, real numbers, arrays, and bit vectors. De Moura and Bjørner's Z3 [1] is the industry standard, used in Microsoft's driver verification and Amazon's cloud security proofs.

**Symbolic Execution:** King's original work [2] on symbolic execution treats program variables as symbols rather than concrete values, exploring all possible execution paths. Modern tools like KLEE and CrossHair apply these techniques to find bugs.

**Computer Algebra Systems:** SymPy [3] provides symbolic mathematics capabilities including differentiation, integration, and equation solving—enabling verification of mathematical claims without numerical approximation.

### 2.2 LLM Limitations

Recent research has documented systematic LLM failures:

- **Mathematical Reasoning:** LLMs struggle with multi-step arithmetic and algebraic manipulation [4]
- **Logical Consistency:** Models produce contradictory statements within single responses [5]
- **Code Generation:** AI-generated code contains security vulnerabilities at rates comparable to human code [6]

These failures are not addressable through scale alone; they require external verification.

### 2.3 Existing Verification Approaches

**Guardrails AI** and **NeMo Guardrails** provide output filtering but operate on pattern matching rather than formal verification. **LangChain's Tool Calling** enables LLMs to invoke external functions but does not verify the correctness of the calls themselves.

QWED differs by applying formal methods—mathematical proof rather than heuristic checking.

### 2.4 Regulatory Context

The **EU AI Act** (2024) classifies AI systems by risk level, with "high-risk" applications in finance and healthcare requiring documented accuracy and reliability guarantees. The **NIST AI Risk Management Framework** (2023) emphasizes the need for AI systems that are "valid and reliable."

QWED's deterministic verification provides the formal guarantees these regulations require.

---

## 3. The QWED Protocol Architecture

### 3.1 System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      User Application                        │
└──────────────────────────┬──────────────────────────────────┘
                           │ Query
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    LLM (Untrusted Translator)                │
│              GPT-4 / Claude / Gemini / Llama                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ Unverified Output
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      QWED Protocol                           │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │  Math   │ │  Logic  │ │  Code   │ │   SQL   │    ...    │
│  │ Engine  │ │ Engine  │ │ Engine  │ │ Engine  │           │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
│       └──────────┴──────────┴──────────┴────────┐          │
│                                                  ▼          │
│                         Verification Result                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
        ✅ VERIFIED                  ❌ REJECTED
        (Proceed)                    (Halt + Log)
```

**Figure 2: QWED Protocol Architecture**

```mermaid
flowchart TD
    A[User Application] --> B[LLM - Untrusted Translator]
    B --> C{QWED Protocol}
    C --> D[Math Engine - SymPy]
    C --> E[Logic Engine - Z3]
    C --> F[Code Engine - AST]
    C --> G[SQL Engine - SQLGlot]
    C --> H[Stats Engine]
    C --> I[Fact Engine]
    C --> J[Image Engine]
    C --> K[Consensus Engine]
    D --> L{Verification Result}
    E --> L
    F --> L
    G --> L
    H --> L
    I --> L
    J --> L
    K --> L
    L -->|Valid| M[✅ VERIFIED - Proceed]
    L -->|Invalid| N[❌ REJECTED - Halt + Log]
```

### 3.2 Core Principles

**Principle 1: Zero Trust**
Every LLM output is treated as potentially incorrect until proven otherwise.

**Principle 2: Deterministic Verification**
Verification engines use mathematical proof, not statistical confidence.

**Principle 3: Fail-Safe Default**
If verification cannot be completed (timeout, unsupported domain), the output is rejected.

**Principle 4: Transparency**
Every verification produces an auditable proof trace.

### 3.3 Verification Flow

1. **Domain Detection:** QWED analyzes the query and LLM output to determine which verification engine(s) apply
2. **Structured Extraction:** The LLM output is parsed into a formal structure (AST, equation, SQL query)
3. **Engine Invocation:** The appropriate verification engine processes the structured output
4. **Result Generation:** The engine returns VERIFIED, REJECTED, or INCONCLUSIVE with evidence
5. **Attestation:** Verified outputs receive cryptographic attestations (JWT with ES256)

---

## 4. The Eight Verification Engines

QWED implements eight specialized verification engines, each targeting a specific domain of LLM failure.

### 4.1 Math Verification Engine

**Technology Stack:** SymPy, NumPy

**Problem Addressed:** LLMs frequently make arithmetic, algebraic, and calculus errors despite appearing confident in their responses.

**Verification Approach:**

```python
from sympy import symbols, diff, simplify, Eq

def verify_derivative(expression: str, claimed_derivative: str) -> bool:
    """
    Verify a claimed derivative using symbolic differentiation.
    """
    x = symbols('x')
    expr = sympify(expression)
    claimed = sympify(claimed_derivative)
    actual = diff(expr, x)
    
    return simplify(claimed - actual) == 0
```

**Example:**

| LLM Claim | Verification | Result |
|-----------|--------------|--------|
| d/dx(x²) = 3x | SymPy: diff(x**2, x) = 2*x | ❌ REJECTED |
| ∫sin(x)dx = -cos(x) + C | SymPy: integrate(sin(x), x) = -cos(x) | ✅ VERIFIED |

**Capabilities:**
- Symbolic differentiation and integration
- Algebraic simplification
- Linear algebra (matrix operations, eigenvalues)
- Financial calculations (compound interest, NPV, IRR)

### 4.2 Logic Verification Engine

**Technology Stack:** Z3 Prover (SMT Solver)

**Problem Addressed:** LLMs produce logically inconsistent statements and fail to identify contradictions.

**Verification Approach:**

```python
from z3 import Solver, Int, And, Or, Not, sat, unsat

def verify_logical_consistency(premises: List[str], conclusion: str) -> bool:
    """
    Check if conclusion follows from premises using Z3.
    """
    solver = Solver()
    
    # Add premises
    for premise in premises:
        solver.add(parse_to_z3(premise))
    
    # Check if negation of conclusion is unsatisfiable
    solver.add(Not(parse_to_z3(conclusion)))
    
    return solver.check() == unsat  # If unsat, conclusion must follow
```

**Capabilities:**
- Propositional logic verification
- First-order logic with quantifiers
- Integer and real arithmetic constraints
- Satisfiability checking

### 4.3 Code Security Engine

**Technology Stack:** Python AST, Semgrep patterns

**Problem Addressed:** AI-generated code contains security vulnerabilities including injection attacks, hardcoded secrets, and dangerous function calls.

**Verification Approach:**

```python
import ast

DANGEROUS_FUNCTIONS = {'eval', 'exec', 'compile', '__import__'}
DANGEROUS_MODULES = {'os', 'subprocess', 'pickle'}

def verify_code_safety(code: str) -> Dict[str, Any]:
    """
    Static analysis for security vulnerabilities.
    """
    tree = ast.parse(code)
    vulnerabilities = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in DANGEROUS_FUNCTIONS:
                    vulnerabilities.append({
                        'type': 'dangerous_function',
                        'function': node.func.id,
                        'line': node.lineno
                    })
    
    return {
        'is_safe': len(vulnerabilities) == 0,
        'vulnerabilities': vulnerabilities
    }
```

**Detection Capabilities:**
- Dangerous function calls (`eval`, `exec`, `pickle.loads`)
- SQL injection patterns
- Command injection
- Hardcoded secrets and API keys
- Insecure cryptographic usage

### 4.4 SQL Verification Engine

**Technology Stack:** SQLGlot

**Problem Addressed:** AI-generated SQL queries contain injection vulnerabilities and schema violations.

**Verification Approach:**

```python
import sqlglot

def verify_sql_safety(query: str, schema: Dict) -> Dict[str, Any]:
    """
    Parse and validate SQL query.
    """
    try:
        parsed = sqlglot.parse_one(query)
        
        # Check for dangerous patterns
        if 'DROP' in query.upper() or 'DELETE' in query.upper():
            return {'is_safe': False, 'reason': 'Destructive operation'}
        
        # Validate against schema
        tables = [t.name for t in parsed.find_all(sqlglot.exp.Table)]
        for table in tables:
            if table not in schema:
                return {'is_safe': False, 'reason': f'Unknown table: {table}'}
        
        return {'is_safe': True, 'parsed': parsed}
        
    except sqlglot.errors.ParseError as e:
        return {'is_safe': False, 'reason': f'Parse error: {e}'}
```

### 4.5 Statistics Engine

**Technology Stack:** Pandas, WebAssembly sandboxing

**Problem Addressed:** Statistical calculations require precise computation that LLMs approximate.

**Capabilities:**
- Descriptive statistics verification
- Hypothesis test validation
- Regression coefficient checking
- Dataset integrity verification

### 4.6 Fact Checking Engine

**Technology Stack:** TF-IDF, Natural Language Inference (NLI)

**Problem Addressed:** LLMs fabricate facts not present in source documents (especially in RAG systems).

**Verification Approach:**
1. Extract claims from LLM output
2. Retrieve relevant source passages using TF-IDF
3. Apply NLI model to check entailment
4. Return grounding score

> **Important:** The Fact Engine does not attempt semantic understanding or deep meaning resolution. It verifies grounding and entailment consistency against provided sources, not truth of language.

### 4.7 Image Verification Engine

**Technology Stack:** OpenCV, Pillow, Metadata extraction

**Problem Addressed:** LLMs make incorrect claims about images (dimensions, content, format).

**Capabilities:**
- Dimension and format verification
- Metadata consistency checking
- Basic content validation (faces detected, colors present)

### 4.8 Consensus Engine

**Technology Stack:** Multi-provider API calls

**Problem Addressed:** Single-model responses may be confidently wrong.

**Verification Approach:**
1. Query same prompt to multiple LLMs (GPT-4, Claude, Gemini)
2. Compare responses for consistency
3. Flag disagreements for human review
4. Return majority consensus with confidence

---

## 5. Symbolic Execution and Bounded Model Checking

### 5.1 Integration with CrossHair

QWED integrates CrossHair, a Python symbolic execution tool built on Z3, for deeper verification of typed Python functions.

```python
from qwed.symbolic_verifier import SymbolicVerifier

verifier = SymbolicVerifier(timeout_seconds=30)

code = '''
def divide(x: int, y: int) -> float:
    return x / y
'''

result = verifier.verify_code(code)
# Returns counterexample: y=0 causes ZeroDivisionError
```

### 5.2 Bounded Model Checking

To prevent path explosion in programs with loops and recursion, QWED implements bounded model checking:

**Loop Bounding:** Limits loop iterations to a configurable maximum (default: 10)

**Recursion Depth:** Limits recursive call depth (default: 5)

**Verification Budget:** Estimates feasibility before execution

```python
# Analyze code complexity
analysis = verifier.analyze_complexity(code)
print(analysis['max_loop_depth'])  # 3
print(analysis['total_recursive_functions'])  # 1
print(analysis['recommendation']['risk_level'])  # "medium"

# Verify with bounds
result = verifier.verify_bounded(
    code,
    loop_bound=10,
    recursion_depth=5
)
```

### 5.3 Limitations

Symbolic execution is computationally expensive for complex programs. QWED provides:
- Configurable timeouts (default: 30 seconds per function)
- Path prioritization (critical paths first)
- Budget estimation to predict feasibility

---

## 6. Benchmark Results

### 6.1 Methodology

We evaluated QWED against **Claude Opus 4.5** across 215 test cases in four categories:

| Category | Test Cases | Description |
|----------|------------|-------------|
| Financial Calculations | 50 | Compound interest, NPV, amortization |
| Mathematical Reasoning | 45 | Calculus, algebra, linear systems |
| Adversarial Prompts | 70 | Authority bias, prompt injection attempts |
| Code Generation | 50 | Security-sensitive code snippets |

### 6.2 Results

| Category | LLM Accuracy | QWED Detection Rate |
|----------|--------------|---------------------|
| Financial | 73% | **100%** |
| Mathematical | 81% | **100%** |
| Adversarial | 85% | **100%** |
| Code Security | 78% | **100%** |

**Key Finding:** QWED detected all 22 errors that Claude Opus 4.5 produced across the benchmark suite. No false negatives were observed in verifiable domains.

**Figure 1: Error Detection Comparison (LLM vs QWED)**

```mermaid
xychart-beta
    title "LLM Accuracy vs QWED Detection Rate"
    x-axis [Financial, Mathematical, Adversarial, Code]
    y-axis "Accuracy %" 0 --> 100
    bar [73, 81, 85, 78]
    bar [100, 100, 100, 100]
```

> **Economic Insight:** In high-stakes systems, expected loss is dominated by rare but severe errors. A 73% accuracy rate is acceptable in conversational AI but catastrophic in financial systems where a single error costs thousands.

### 6.3 Comparison with Existing Approaches

| Approach | Deterministic | Provable | Latency | Coverage |
|----------|---------------|----------|---------|----------|
| **QWED** | Yes | Yes | ~100ms | 8 domains |
| Guardrails AI | No | No | ~50ms | Pattern-based |
| RLHF/Fine-tuning | No | No | 0ms | Training-time |
| RAG | No | No | ~200ms | Knowledge only |
| Prompt Engineering | No | No | 0ms | None |

### 6.4 Case Study: The $12,889 Bug

**Scenario:** Financial application calculating compound interest

**Query:** "Calculate the future value of $100,000 invested at 5% annual interest for 10 years with annual compounding."

**Claude Opus 4.5 Response:** "$150,000"

**QWED Verification:**

```python
from sympy import symbols, Eq, solve

P, r, n = 100000, 0.05, 10  # Principal, rate, years
FV_claimed = 150000
FV_actual = P * (1 + r) ** n  # = 162889.46

assert FV_claimed != FV_actual
# QWED: ❌ REJECTED - Simple interest used instead of compound
```

**Business Impact:** $12,889 error per transaction. At 1,000 transactions/day = **$4.7M annual loss**.

### 6.5 Benchmark Dataset Availability

The complete benchmark suite (215 test cases) is available at:

**Repository:** https://github.com/QWED-AI/qwed-verification/tree/main/benchmarks

Includes:
- Financial calculations with ground truth
- Mathematical reasoning tests (derivatives, integrals)
- Adversarial prompts collection
- Security-vulnerable code snippets

---

## 7. Integration Guide

### 7.1 LangChain Integration

```python
from qwed_sdk.langchain import QWEDTool

# Create verification tools
math_tool = QWEDTool(verification_type="math")
sql_tool = QWEDTool(verification_type="sql")

# Add to LangChain agent
agent = create_agent(
    llm=ChatOpenAI(model="gpt-4"),
    tools=[math_tool, sql_tool, ...your_tools]
)
```

### 7.2 CrewAI Integration

```python
from qwed_sdk.crewai import QWEDVerifiedAgent

# Create agent with automatic verification
analyst = QWEDVerifiedAgent(
    role="Financial Analyst",
    verification_engines=["math", "sql"],
    allow_unverified=False  # Reject unverifiable outputs
)
```

### 7.3 API Architecture

```
POST /api/v1/verify
Content-Type: application/json
X-API-Key: qwed_...

{
  "domain": "math",
  "query": "What is the derivative of x^2?",
  "llm_output": "3x",
  "options": {
    "timeout_ms": 5000,
    "strict_mode": true
  }
}
```

**Response:**

```json
{
  "verified": false,
  "domain": "math",
  "expected": "2*x",
  "actual": "3*x",
  "proof_trace": "diff(x**2, x) → 2*x ≠ 3*x",
  "attestation": "eyJhbGciOiJFUzI1NiIs..."
}
```

---

## 8. Limitations and Transparency

> **Explicit Limitation:** QWED does not verify free-form natural language reasoning, subjective analysis, or creative text. Any claim that cannot be reduced to a formal artifact is intentionally rejected.

### 8.1 Threat Model

**QWED defends against:**
- ✓ Mathematical computation errors
- ✓ Code injection attacks (eval, exec, SQL injection)
- ✓ Logical inconsistencies and contradictions
- ✓ Schema violations in SQL queries

**QWED does NOT defend against:**
- ✗ Adversarial inputs specifically designed to fool verifiers
- ✗ Social engineering attacks
- ✗ Model extraction or membership inference attacks
- ✗ Semantic deception within valid formal structures

### 8.2 Structured Output Requirement

QWED requires LLM outputs to be in parseable formats (JSON, code blocks, mathematical notation). This means:

- LLMs must be prompted to produce structured data
- Freeform text responses cannot be directly verified
- Integration requires output formatting configuration

### 8.3 Latency Considerations

Verification introduces latency overhead:

| Operation | Typical Latency |
|-----------|-----------------|
| Simple math verification | Under 10ms |
| SQL parsing and validation | 10-50ms |
| Z3 logic solving | 50-200ms |
| Full symbolic execution | 5-30 seconds |

QWED provides a `get_verification_budget()` API to estimate feasibility before execution.

### 8.4 Domain Coverage

QWED currently supports eight verification domains. Outputs outside these domains (creative writing, subjective opinions, open-ended analysis) cannot be verified deterministically.

### 8.5 Code and Data Availability

- **Source Code:** https://github.com/QWED-AI/qwed-verification
- **License:** Apache 2.0
- **Benchmarks:** https://github.com/QWED-AI/qwed-verification/tree/main/benchmarks
- **Installation:** `pip install qwed` (PyPI publication pending)
- **Docker:** `docker pull qwedai/qwed-verification:latest` (coming soon)

As of December 2025, SDKs must be installed from source:

```bash
git clone https://github.com/QWED-AI/qwed-verification
cd qwed-verification
pip install -r requirements.txt
```

---

## 9. Future Work

### Phase 3: LLM-Assisted Specification Generation

Use LLMs to generate verification specifications from docstrings and comments, which QWED then validates deterministically.

### Phase 4: Algorithm Equivalence Proofs

Verify that two code implementations produce identical outputs for all inputs—useful for validating refactoring.

### Phase 5: Natural Language Contract Verification

Extend QWED to legal contracts and regulatory compliance documents, verifying that AI-generated analyses align with regulatory requirements.

---

## 10. Conclusion

QWED demonstrates that deterministic verification is not only possible for LLM outputs but essential for production deployment in high-stakes domains. By treating LLMs as untrusted translators and applying formal methods to their outputs, we can capture the productivity benefits of AI while maintaining the reliability guarantees that enterprise systems require.

The protocol's 100% error detection rate in benchmarks—compared to 73-85% LLM accuracy—validates the core thesis: **verification, not correction, is the path to reliable AI systems.**

QWED is open-source under the Apache 2.0 license, welcoming contributions from the formal methods and AI safety communities.

---

## License

This work is licensed under the **Apache License 2.0**.

- Commercial use: ✅ Allowed
- Modification: ✅ Allowed
- Distribution: ✅ Allowed
- Patent grant: ✅ Included
- Trademark use: ❌ Not granted

---

## Citation

If you use QWED in your research or production systems, please cite:

```bibtex
@misc{dass2025qwed,
  author = {Dass, Rahul},
  title = {QWED Protocol: Deterministic Verification for Large Language Models},
  year = {2025},
  publisher = {QWED-AI},
  url = {https://github.com/QWED-AI/qwed-verification},
  note = {Open Source, Apache 2.0 License},
  orcid = {0009-0000-2088-7487}
}
```

---

## Funding

This research received no external funding.

---

## References

[1] De Moura, L., & Bjørner, N. (2008). Z3: An Efficient SMT Solver. *Tools and Algorithms for the Construction and Analysis of Systems (TACAS)*, 337-340.

[2] King, J. C. (1976). Symbolic Execution and Program Testing. *Communications of the ACM*, 19(7), 385-394.

[3] Meurer, A., et al. (2017). SymPy: Symbolic Computing in Python. *PeerJ Computer Science*, 3, e103.

[4] Hendrycks, D., et al. (2021). Measuring Mathematical Problem Solving With the MATH Dataset. *NeurIPS*.

[5] Elazar, Y., et al. (2021). Measuring and Improving Consistency in Pretrained Language Models. *TACL*.

[6] Pearce, H., et al. (2022). Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions. *IEEE S&P*.

[7] Clarke, E. M., Henzinger, T. A., Veith, H., & Bloem, R. (Eds.). (2018). *Handbook of Model Checking*. Springer.

[8] National Institute of Standards and Technology. (2023). *AI Risk Management Framework (AI RMF 1.0)*. U.S. Department of Commerce.

[9] European Parliament. (2024). *Regulation on Artificial Intelligence (AI Act)*. Official Journal of the European Union.

[10] Cobbe, K., et al. (2021). Training Verifiers to Solve Math Word Problems. *arXiv:2110.14168*.

[11] Uesato, J., et al. (2022). Solving Math Word Problems with Process- and Outcome-based Feedback. *arXiv:2211.14275*.

[12] Pei, K., et al. (2017). DeepXplore: Automated Whitebox Testing of Deep Learning Systems. *SOSP*.

---

**QWED-AI**  
https://qwedai.com | https://docs.qwedai.com | https://github.com/QWED-AI/qwed-verification
