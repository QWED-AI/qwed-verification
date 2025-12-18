# QWED: The Protocol for Verifiable Intelligence 🛡️

> **Version:** 1.2 (Enterprise Beta)  
> **Core:** Python 3.11 + FastAPI + Z3 Solver + PostgreSQL  
> **Architecture:** Hybrid Formal Assurance System (HFAS)

---

## "Trust, but Verify."

QWED is a **Model-Agnostic Verification Middleware** that acts as a firewall between your LLM and your critical business logic. It translates probabilistic AI hallucinations into deterministic mathematical guarantees.

---

## 🚀 New in v1.2 (The "Beast" Update)

### 🏦 Deterministic Financial Engine
- **Problem:** LLMs use floating-point math, leading to money errors (e.g., `0.1 + 0.2 = 0.300000004`).
- **Solution:** Replaced `float` with **Arbitrary-Precision Decimal Arithmetic**.
- **Unit Safety:** Strict **Currency Awareness**. Throws `UnitMismatchError` if adding incompatible currencies without conversion.

### 🧠 Explainable Logic (XAI)
- **Problem:** Traditional validators just return "False" when a rule breaks.
- **Solution:** Z3 Engine now extracts **Counter-Models**.
- **Impact:** Instead of just blocking, we tell you *why*:
  > *"Rejected. Violation: tax_rate is 12% but 'Electronics' requires 18%."*

### ⚡ High-Concurrency Infrastructure
- **Database:** Migrated from SQLite to **PostgreSQL (Dockerized)**.
- **Scale:** Handles hundreds of concurrent verification requests.

---

## 🧠 The 8 Verification Engines

| # | Engine | Technology | Function |
|---|--------|------------|----------|
| 1 | **Math & Finance** | `SymPy` + `Decimal` | Verifies calculations with infinite precision & unit safety |
| 2 | **Logic & Constraint** | `Z3` + `QWED-DSL` | Proves satisfiability of complex business rules (SMT Solving) |
| 3 | **Statistics** | `Pandas` + `SciPy` | Verifies claims about tabular data |
| 4 | **Fact Checker** | `NLP` | Verifies text claims with exact citations |
| 5 | **Code Security** | `AST` | Static analysis for vulnerabilities & secrets |
| 6 | **SQL Safety** | `SQLGlot` | Parses & sanitizes AI-generated SQL (Anti-Injection) |
| 7 | **Image Verification** | `Vision API` | Verifies image-based claims |
| 8 | **Chain-of-Thought** | `Multi-LLM` | Cross-validates reasoning across providers |

---

## 🛡️ Security Features

- **Prompt Injection Detection**: Pre-flight scan of user inputs
- **PII Redaction**: Automatic scrubbing of sensitive data from logs
- **Sandboxed Execution**: Code verification runs in isolated environments
- **OWASP LLM Top 10 2025**: Full compliance

---

## Quick Links

| 🚀 Getting Started | 🏛️ Architecture | 📚 API | 🛡️ Security |
|:------------------:|:---------------:|:------:|:-----------:|
| [Installation](getting-started/installation.md) | [Architecture Guide](architecture.md) | [API Docs](api.md) | [Security Overview](security.md) |

---

*Built with ❤️ for a deterministic future.*
