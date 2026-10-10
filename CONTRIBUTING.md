# Contributing to QWED

> **QWED** = **Q**uery with **E**vidence and **D**eterminism

Thank you for your interest in contributing! Before you start, please read this guide to understand QWED's philosophy and avoid common misunderstandings.

---

## 📚 Required Reading (Before Contributing)

| File | Why It Matters |
|------|----------------|
| [README.md](./README.md) | Understand what QWED is |
| [QWED_RULES.md](./QWED_RULES.md) | Canonical enforcement rules for contributors and tools |
| [Architecture](https://docs.qwedai.com/architecture) | System design and engine architecture |
| [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) | Community standards |
| [SECURITY.md](./SECURITY.md) | How to report vulnerabilities |

---

## 🧠 Understanding QWED's Philosophy

### The Core Principle: Deterministic First

QWED is NOT just another LLM wrapper. Our philosophy:

1. **LLMs are untrusted translators** - They convert natural language to structured queries
2. **Symbolic engines are trusted verifiers** - SymPy, Z3, SQLGlot, etc. do the actual verification
3. **Determinism is required** - Given the same input, output must be identical every time
4. **LLM output is never proof** - Models may assist with translation or enrichment, but they must not weaken deterministic enforcement

When contributor guidance and enforcement guidance appear to conflict, follow
`QWED_RULES.md` as the authoritative source for boundary behavior.

### ✅ Approved Paths

Sensitive operations must go through approved wrappers — never bare calls:

| Dangerous Operation | Approved Path |
|---------------------|---------------|
| `eval()` | `SafeEvaluator.safe_eval()` in `src/qwed_new/core/safe_evaluator.py` |
| `exec()` / running generated code | `SecureCodeExecutor.execute()` in `src/qwed_new/core/secure_code_executor.py` |
| `parse_expr()` / `sympify()` | `safe_parse_expr()` in `src/qwed_new/core/safe_parser.py` |
| `os.system()` / `subprocess.*` | Not allowed outside the files listed in `APPROVED_WRAPPER_PATHS` in `scripts/check_boundary.py`. A shared shell wrapper does not exist yet. |

Direct calls to these dangerous functions outside their approved wrappers will
be caught by the CI boundary gate (see `scripts/check_boundary.py`).

### ❌ Common Misunderstandings

| Wrong Approach | Correct Approach |
|----------------|------------------|
| "Let the LLM verify the math" | Use SymPy to compute, LLM only translates |
| "Add more LLM prompts to fix edge cases" | Add deterministic patterns/rules |
| "Cache LLM responses" | Deterministic verification doesn't need caching |
| "Trust LLM confidence scores" | Use symbolic proof verification |
| "The system prompt will prevent X" | Add an explicit deterministic guard |
| "The model said it's correct" | Verify with deterministic computation |

---

## 🔧 Development Setup

```bash
# Clone the repo
git clone https://github.com/QWED-AI/qwed-verification.git
cd qwed-verification

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows

# Install in development mode (CI installs the same extras)
pip install -e ".[server,dev]"

# Run tests
pytest tests/ -v
```

---

## 🎯 Where to Start

Current priorities are in [ROADMAP.md](./ROADMAP.md) and the [open issues](https://github.com/QWED-AI/qwed-verification/issues). Issues labelled [`good first issue`](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and [`help wanted`](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) are good places to begin.

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

### 4. Code Review Standards

QWED currently has a single maintainer (see [GOVERNANCE.md](./GOVERNANCE.md)), so reviews work like this:

- **External PRs** are reviewed by the maintainer before merge.
- **Maintainer PRs** are reviewed by automated reviewers (CodeQL, SonarCloud, CodeRabbit and similar) and merged by the maintainer. Independent human review of maintainer changes is not guaranteed.
- **CI** (tests, the boundary check, CodeQL, SonarCloud) is expected to pass before merge.
- **Review Checklist**:
    - [ ] Logic correctness and edge case handling
    - [ ] Test coverage (tests added for new features)
    - [ ] Security implications (no hardcoded secrets, safe input handling)
    - [ ] Documentation updates
    - [ ] Compliance with coding standards (PEP 8, type hints)

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

Some enterprise features (such as SSO) are developed in a separate, private repository. This repository does include basic authentication, tenant isolation, audit logging and RBAC: bug fixes and security fixes for them are welcome here. Please open an issue before proposing new enterprise-scope features.

For enterprise questions, contact support@qwedai.com.

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](./LICENSE).

---

## ⚖️ Governance & Legal

### Developer Certificate of Origin (DCO)

We ask contributors to sign off their commits, certifying under the [Developer Certificate of Origin](https://developercertificate.org/) that they have the right to submit the code under the project's license. Sign-off is not currently enforced by CI. It is done by adding a `Signed-off-by` line to your commit messages.

```
Signed-off-by: Random J. Developer <random@developer.example.org>
```

By signing off, you certify the statements in [DCO 1.1](https://developercertificate.org/), including that your name and email will be permanently recorded in the project's commit history. You can sign off commits automatically with `git commit -s`.

### Project Governance

This project is governed under a BDFL model. See [GOVERNANCE.md](./GOVERNANCE.md) for details on decision making, roles, and continuity planning.

---

## 💬 Questions?

- Open an issue with the `question` label
- Join discussions in GitHub Discussions
- Email: support@qwedai.com (security reports: see [SECURITY.md](./SECURITY.md))

