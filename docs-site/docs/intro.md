---
sidebar_position: 1
slug: /
---

# Welcome to QWED

> **"Trust, but Verify."** — QWED treats LLMs as untrusted translators and uses symbolic engines as trusted verifiers.

## What is QWED?

**QWED** (Query-Wise Engine for Determinism) is the **verification protocol for AI**. It provides deterministic verification of LLM outputs using symbolic engines like Z3, SymPy, and AST analysis.

```
┌─────────────────────────────────────────────────────────────┐
│                    QWED VERIFICATION FLOW                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  User Query ──▶ LLM (Translator) ──▶ QWED (Verifier) ──▶ ✅ │
│                     ↓ (Probabilistic)    ↓ (Deterministic)  │
│                  "2+2=5"              "CORRECTED: 4"        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Why QWED?

| Problem | QWED Solution |
|---------|---------------|
| LLMs hallucinate math | Symbolic verification with SymPy |
| LLMs break logic | SAT solving with Z3 |
| LLMs generate unsafe code | AST analysis + pattern detection |
| LLMs produce SQL injection | Query parsing + validation |

## Quick Start

```bash
# Install the Python SDK
pip install qwed-new

# Verify math
qwed verify "Is 2+2=5?"
# → ❌ CORRECTED: The answer is 4, not 5.

# Verify logic
qwed verify-logic "(AND (GT x 5) (LT y 10))"
# → ✅ SAT: {x=6, y=9}
```

## Features

- **8 Verification Engines** — Math, Logic, Stats, Fact, Code, SQL, Image, Reasoning
- **4 SDKs** — Python, TypeScript, Go, Rust
- **3 Framework Integrations** — LangChain, LlamaIndex, CrewAI
- **Cryptographic Attestations** — JWT-based verification proofs
- **Agent Verification** — Pre-execution checks for AI agents

## Next Steps

- [Installation Guide](/docs/getting-started/installation)
- [Quick Start Tutorial](/docs/getting-started/quickstart)
- [SDK Documentation](/docs/sdks/overview)
- [Protocol Specifications](/docs/specs/overview)
