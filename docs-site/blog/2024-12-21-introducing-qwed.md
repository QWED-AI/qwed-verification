---
slug: introducing-qwed
title: "Introducing QWED: The Deterministic Verification Protocol for AI"
authors: [rahul]
tags: [announcements, verification, ai-safety]
---

**Today, we're open-sourcing QWED** — a protocol that brings mathematical certainty to AI outputs.

## The Problem

LLMs are incredible at understanding natural language. But they're terrible at math. They hallucinate facts. They generate unsafe code.

The industry's solution? Train them more. Fine-tune with RLHF. Add guardrails.

**We took a different approach.**

<!-- truncate -->

## Don't Fix the Liar. Verify the Lie.

Instead of trying to make LLMs more accurate, we treat them as **untrusted translators**. The LLM converts natural language to symbolic form. Then deterministic engines verify the result.

```
User Query → [LLM Translation] → [QWED Verification] → ✅ Guaranteed Correct
```

This is a fundamental shift. We're not training models to be better calculators — we're using actual calculators to verify their output.

## What QWED Provides

### 8 Verification Engines

| Engine | What it Verifies |
|--------|------------------|
| **Math** | Arithmetic, algebra, calculus |
| **Logic** | Propositional logic, constraints |
| **Statistics** | Statistical claims on data |
| **Fact** | Factual claims with citations |
| **Code** | Security vulnerabilities |
| **SQL** | Query safety and validity |
| **Image** | Visual claim verification |
| **Reasoning** | Chain-of-thought accuracy |

### Enterprise-Grade Security

- SQL injection firewall (AST-based)
- Prompt injection detection
- Rate limiting per API key
- Secure Docker sandboxing for code execution

## Quick Start

```bash
pip install qwed
```

```python
from qwed import QWEDClient

client = QWEDClient()
result = client.verify("Is 2+2=5?")

print(result.verified)  # False
print(result.message)   # "2+2 = 4, not 5"
```

## Why Open Source?

AI verification is too important to be locked behind a paywall. Every developer building with LLMs needs these tools.

We're releasing the core protocol under **Apache 2.0**. Use it. Fork it. Build on it.

## What's Next

- **Enterprise features** — Observability, multi-tenancy, attestations
- **More engines** — Financial calculations, regulatory compliance
- **Community** — Your contributions and feedback

## Get Involved

- 🌟 [Star on GitHub](https://github.com/QWED-AI/qwed-verification)
- 📖 [Read the Docs](https://docs.qwedai.com)
- 📧 [Contact Us](mailto:rahul@qwedai.com)

---

**The future of AI is verified AI.**

Safe AI is the only AI that scales.
