# Contributing to QWED

> **QWED** = **Q**uery with **E**vidence and **D**eterminism

Thank you for your interest in contributing! Before you start, please read this guide to understand QWED's philosophy and avoid common misunderstandings.

---

## 📚 Required Reading (Before Contributing)

| File | Why It Matters |
|------|----------------|
| [README.md](./README.md) | Understand what QWED is |
| [docs/architecture.md](./docs/architecture.md) | System design and engine architecture |
| [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) | Community standards |
| [SECURITY.md](./SECURITY.md) | How to report vulnerabilities |

---

## 🧠 Understanding QWED's Philosophy

### The Core Principle: Deterministic First

QWED is NOT just another LLM wrapper. Our philosophy:

1. **LLMs are untrusted translators** - They convert natural language to structured queries
2. **Symbolic engines are trusted verifiers** - SymPy, Z3, SQLGlot, etc. do the actual verification
3. **Determinism is required** - Given the same input, output must be identical every time
4. **LLM fallback is last resort** - Only when deterministic methods cannot handle the query

### ❌ Common Misunderstandings

| Wrong Approach | Correct Approach |
|----------------|------------------|
| "Let the LLM verify the math" | Use SymPy to compute, LLM only translates |
| "Add more LLM prompts to fix edge cases" | Add deterministic patterns/rules |
| "Cache LLM responses" | Deterministic verification doesn't need caching |
| "Trust LLM confidence scores" | Use symbolic proof verification |

---

## 🔧 Development Setup

```bash
# Clone the repo
git clone https://github.com/QWED-AI/qwed-verification.git
cd qwed-verification

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

---

## 🎯 Current Focus (Phase 1: Logic Verification)

We are building **symbolic execution capabilities**. Here are the priority issues:

| Priority | Issue | Description |
|----------|-------|-------------|
| 🔴 High | [#15 CrossHair Integration](https://github.com/QWED-AI/qwed-verification/issues/15) | Python-native symbolic execution |
| 🟡 Medium | [#16 Bounded Model Checking](https://github.com/QWED-AI/qwed-verification/issues/16) | Loop depth limits for path explosion |
| 🟢 Easy | Documentation improvements | Help improve docs |

**Pick an issue labeled `good first issue` or `help wanted` to get started!**

---

## 🚀 How to Contribute

### 1. Reporting Bugs

Open an issue with:
- QWED version (`pip show qwed`)
- Python version
- Input that caused the bug
- Expected vs actual output
- Full traceback

### 2. Proposing Features

Before coding, open an issue to discuss:
- What problem does it solve?
- Does it require LLM or is it deterministic?
- Which engine does it affect?

### 3. Submitting Pull Requests

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/qwed-verification.git

# 2. Create a branch
git checkout -b feat/your-feature

# 3. Make changes

# 4. Run tests
pytest tests/ -v

# 5. Commit with conventional commits
git commit -m "feat(engine): add capability X"

# 6. Push and create PR
git push origin feat/your-feature
```

### Commit Message Format

```
type(scope): description

feat(math): add matrix determinant support
fix(sql): handle nested subqueries
docs: update architecture diagram
test: add edge cases for logic engine
```

---

## 📁 Repository Structure

```
qwed-verification/
├── src/qwed_new/
│   └── core/           # 🔴 Core verification engines
│       ├── *_verifier.py   # One file per engine
│       └── control_plane.py # Request routing
├── qwed_sdk/           # Python SDK
├── sdk-ts/             # TypeScript SDK
├── sdk-go/             # Go SDK
├── sdk-rust/           # Rust SDK
├── tests/              # Unit tests
├── examples/           # Usage examples
└── docs/               # Documentation
```

---

## ⚠️ What NOT to Contribute

These features are in a **separate enterprise repo** and not accepted here:

- ❌ Audit logging / compliance exports
- ❌ SSO / authentication systems
- ❌ Multi-tenancy features
- ❌ Telemetry / observability
- ❌ Enterprise RBAC

If you're interested in enterprise features, contact us at rahul@qwedai.com.

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](./LICENSE).

---

## ⚖️ Governance & Legal

### Developer Certificate of Origin (DCO)

To contribute to this project, you must sign off on your commits, certifying that you have the right to submit the code under the project's license. This is done by adding a `Signed-off-by` line to your commit messages.

```
Signed-off-by: Random J. Developer <random@developer.example.org>
```

By signing off, you certify the following:

> I certify that the contribution is original work, or I have the right to submit it under the  open source license. I understand that my contribution and personal information (including name and email) will be permanently recorded in the project's commit history.

Build tools and bots may enforce this requirement. You can sign off commits automatically with `git commit -s`.

### Project Governance

This project is governed under a BDFL model. See [GOVERNANCE.md](./GOVERNANCE.md) for details on decision making, roles, and continuity planning.

---

## 💬 Questions?

- Open an issue with the `question` label
- Join discussions in GitHub Discussions
- Email: rahul@qwedai.com

