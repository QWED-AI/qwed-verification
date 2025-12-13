# QWED Architecture Guide

**For Internal Developers & Contributors**

---

## System Overview

QWED is a **Model-Agnostic Verification Engine**. It treats LLMs as "untrusted translators" and uses symbolic engines as "trusted verifiers".

### The 8-Engine Architecture

QWED now supports 8 distinct verification engines:

1.  **Engine 1: Math Verifier (SymPy)**
    *   **Goal**: Verify mathematical calculations.
    *   **Mechanism**: LLM translates to Python expression -> SymPy evaluates.
    *   **Status**: Production.

2.  **Engine 2: Logic Verifier (Z3 + QWED-DSL)**
    *   **Goal**: Verify logic puzzles and constraint problems.
    *   **Mechanism**: LLM translates to **QWED-Logic DSL** (S-Expressions).
    *   **Pipeline**: DSL -> Parser -> Security Whitelist -> Z3 Compiler -> Z3 Solver.
    *   **Status**: Production (Secured).

3.  **Engine 3: Statistical Verifier (Pandas)**
    *   **Goal**: Verify claims about tabular data.
    *   **Mechanism**: **Active Interceptor**. QWED generates Pandas code, executes it in a **Secure Sandbox**, and returns the fact.
    *   **Status**: Production.

4.  **Engine 4: Fact Verifier (Citation)**
    *   **Goal**: Verify claims against a text context (RAG).
    *   **Mechanism**: **Citation Extraction**. LLM extracts exact quotes to support/refute the claim.
    *   **Status**: Production.

5.  **Engine 5: Code Security Verifier (Static Analysis)**
    *   **Goal**: Detect vulnerabilities in generated code.
    *   **Mechanism**: **AST & Regex**. Scans for dangerous functions (`eval`, `exec`) and secrets.
    *   **Status**: Production.

6.  **Engine 6: SQL Verifier (SQLGlot)**
    *   **Goal**: Detect SQL Injection and syntax errors.
    *   **Mechanism**: AST parsing via SQLGlot to validate query structure and safety.
    *   **Status**: Production.

7.  **Engine 7: Image Verifier (Vision)**
    *   **Goal**: Verify claims against image evidence.
    *   **Mechanism**: Multi-modal LLM (Claude Opus/GPT-4V) analysis.
    *   **Status**: Production.

8.  **Engine 8: Reasoning Verifier (Chain-of-Thought)**
    *   **Goal**: checking step-by-step logical validity.
    *   **Mechanism**: Neuro-symbolic entailment checking.
    *   **Status**: Experimental.

---

## Core Components

### 1. QWED-Logic DSL (New)
A secure, whitelist-based Domain Specific Language for logic verification.
*   **Format**: S-Expressions (Lisp-like), e.g., `(AND (GT x 5) (LT y 10))`.
*   **Security**: Replaces unsafe `eval()` with strict operator whitelisting.
*   **Components**: `src/qwed_new/core/dsl/`.

### 2. Verification Cache
*   **Mechanism**: LRU (Least Recently Used) in-memory cache.
*   **TTL**: Results are cached for 1 hour by default.
*   **Impact**: drastically reduces latency for repeated queries.

### 3. Security Gateway
*   **Prompt Injection Detection**: Blocks malicious inputs before they reach engines.
*   **PII Redaction**: Scrubs sensitive data from logs.

---

## Directory Structure

```
src/qwed_new/
├── api/                # FastAPI Interface
│   └── main.py         # Endpoints & Middleware
├── core/               # Core Logic
│   ├── dsl/            # [NEW] QWED-Logic DSL Modules
│   │   ├── parser.py
│   │   └── compiler.py
│   ├── translator.py   # Orchestrates translation
│   ├── cache.py        # [NEW] Caching Layer
│   ├── verifier.py     # Engine 1: SymPy
│   ├── dsl_logic_verifier.py # [NEW] Engine 2: DSL+Z3
│   ├── stats_verifier.py # Engine 3: Pandas
│   ├── fact_verifier.py  # Engine 4: Citation
│   ├── code_verifier.py  # Engine 5: Static Analysis
│   ├── sql_verifier.py   # Engine 6: SQL
│   ├── image_verifier.py # Engine 7: Vision
│   ├── reasoning_verifier.py # Engine 8: CoT
│   ├── consensus_verifier.py # Multi-engine consensus
│   ├── security.py     # Security Gateway
│   └── database.py     # SQLModel Database
├── providers/          # LLM Adapters
│   ├── base.py         # Interface
│   ├── azure_openai.py # GPT-4
│   ├── anthropic.py    # Claude Sonnet
│   └── claude_opus.py  # Claude Opus
└── config.py           # Settings & Env Vars
```

---

## Database Layer

*   **Technology**: SQLModel (SQLite default).
*   **Schema**: `VerificationLog`
    *   Stores ID, Query, Result, Verdict, Latency, and Cost.
