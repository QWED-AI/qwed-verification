<div align="center">
  <img src="assets/logo.svg" alt="QWED Logo - AI Verification Engine" width="80" height="80">
  <h1>QWED Protocol</h1>
  <h3>Model Agnostic Verification Layer for AI</h3>
  
  > **QWED Verification** - Production-grade deterministic verification layer for Large Language Models. Works with **ANY LLM** - OpenAI, Anthropic, Gemini, Llama (via Ollama), or any local model. Detect and prevent AI hallucinations through 8 specialized verification engines. **Your LLM, Your Choice, Our Verification.**
  
  <p>
    <b>Don't fix the liar. Verify the lie.</b><br>
    <i>QWED does not reduce hallucinations. It makes them irrelevant.</i>
  </p>

  <p>
    <b>If an AI output cannot be proven, QWED will not allow it into production.</b>
  </p>

  <p>
    <b>🌐 Model Agnostic:</b> Local ($0) • Budget ($5/mo) • Premium ($100/mo) - You choose!
  </p>

  [![CI](https://github.com/QWED-AI/qwed-verification/actions/workflows/ci.yml/badge.svg)](https://github.com/QWED-AI/qwed-verification/actions/workflows/ci.yml)
  [![codecov](https://codecov.io/gh/QWED-AI/qwed-verification/branch/main/graph/badge.svg)](https://codecov.io/gh/QWED-AI/qwed-verification)
  [![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
  [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
  [![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
  [![DOI](https://zenodo.org/badge/1115581942.svg)](https://doi.org/10.5281/zenodo.18111675)
  [![PyPI version](https://img.shields.io/pypi/v/qwed.svg)](https://pypi.org/project/qwed/)
  [![Contributors](https://img.shields.io/github/contributors/QWED-AI/qwed-verification)](https://github.com/QWED-AI/qwed-verification/graphs/contributors)
  
  [![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-verification?style=social)](https://github.com/QWED-AI/qwed-verification)
  [![GitHub forks](https://img.shields.io/github/forks/QWED-AI/qwed-verification?style=social)](https://github.com/QWED-AI/qwed-verification/fork)
  [![GitHub watchers](https://img.shields.io/github/watchers/QWED-AI/qwed-verification?style=social)](https://github.com/QWED-AI/qwed-verification)

  <a href="https://www.nvidia.com/en-us/startups/"><img src="./assets/badges/nvidia-inception.png" alt="NVIDIA Inception Program" height="40"></a>
  <a href="https://github.com/developer-program"><img src="https://img.shields.io/badge/GitHub_Developer_Program-Member-4183C4?style=for-the-badge&logo=github&logoColor=white" alt="GitHub Developer Program" height="40"></a>

  <br>

  **💖 Support QWED Development:**
  
  <a href="https://github.com/sponsors/QWED-AI"><img src="https://img.shields.io/github/sponsors/QWED-AI?style=for-the-badge&logo=githubsponsors&label=Sponsor&color=EA4AAA" alt="Sponsor QWED on GitHub"></a>

  <br>
  
  [![Twitter](https://img.shields.io/badge/Twitter-@rahuldass29-1DA1F2?style=flat&logo=twitter&logoColor=white)](https://x.com/rahuldass29)
  [![LinkedIn](https://img.shields.io/badge/LinkedIn-Rahul%20Dass-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/rahul-dass-23b370b0/)
  [![Blog](https://img.shields.io/badge/Blog-Unreadable%20Code%20Benchmark-FF5722?style=flat&logo=docusaurus&logoColor=white)](https://docs.qwedai.com/blog/unreadable-code-agi-benchmark)

  <br>
  <a href="#-quick-start-install--verify-in-30-seconds">Quick Start</a> · 
  <a href="#-new-in-v210-client-side-verification">🆕 QWEDLocal</a> ·
  <a href="#-the-llm-hallucination-problem-why-ai-cant-be-trusted">The Problem</a> · 
  <a href="#-the-8-verification-engines-how-qwed-validates-llm-outputs">The 8 Engines</a> ·
  <a href="docs/INTEGRATION.md">🔌 Integration</a> ·
  <a href="docs/QWED_LOCAL.md">⚡ QWEDLocal</a> ·
  <a href="docs/CLI.md">🖥️ CLI</a> ·
  <a href="docs/OLLAMA_INTEGRATION.md">🆓 Ollama (FREE!)</a> ·
  <a href="https://docs.qwedai.com">📖 Full Documentation</a>
</div>

---

> **⚠️ What QWED Is (and Isn't)**
> 
> **QWED is:** An open-source engineering tool that combines existing verification libraries (SymPy, Z3, SQLGlot, AST) into a unified API for LLM output validation.
> 
> **QWED is NOT:** Novel research. We don't claim algorithmic innovation. We claim practical integration for production use cases.
> 
> **Works when:** Developer provides ground truth (expected values, schemas, contracts) and LLM generates structured output.
> 
> **Doesn't work when:** Specs come from natural language, outputs are freeform text, or verification domain is unsupported.

> **🔬 On "Deterministic" Verification**
> 
> QWED uses **deterministic computation** (no neural networks, no embeddings, no vibes) wherever possible. Math, Logic, SQL, Code, and Schema engines produce 100% reproducible results using symbolic solvers. For fact-checking, we use TF-IDF (not embeddings) because it's transparent and inspectable—same query always returns same score. For image/reasoning domains that require LLM fallback, we clearly mark outputs as `HEURISTIC` in the response.

---

## 🚀 Quick Start: Install & Verify in 30 Seconds

### Python SDK (PyPI)
```bash
pip install qwed
```

### Go SDK
```bash
go get github.com/QWED-AI/qwed-verification/sdk-go
```

### TypeScript SDK (npm)
```bash
npm install @qwed-ai/sdk
```

### From Source
```bash
git clone https://github.com/QWED-AI/qwed-verification.git
cd qwed-verification
pip install -e .
```

---

```python
from qwed_sdk import QWEDClient

client = QWEDClient(api_key="your_key")

# The LLM says: "Derivative of x^2 is 3x" (Hallucination!)
response = client.verify_math(
    query="What is the derivative of x^2?",
    llm_output="3x" 
)

print(response)
# -> ❌ CORRECTED: The derivative is 2x. (Verified by SymPy)
```

**💡 Want to use QWED locally without our backend?** Check out [QWEDLocal](docs/QWED_LOCAL.md) - works with Ollama (FREE), OpenAI, Anthropic, or any LLM provider.

---

## 🚨 The LLM Hallucination Problem: Why AI Can't Be Trusted

Everyone is trying to fix AI hallucinations by **Fine-Tuning** (teaching it more data).

This is like forcing a student to memorize 1,000,000 math problems.

**What happens when they see the 1,000,001st problem? They guess.**

---

## 📊 The Proof: Why Enterprise AI Needs QWED Verification

We benchmarked **Claude Opus 4.5** (one of the world's best LLMs) on 215 critical tasks.

![QWED Benchmark Results - LLM Accuracy Testing](assets/benchmark_chart.png)

| Finding | Implication |
|---------|-------------|
| **Finance:** 73% accuracy | Banks can't use raw LLM for calculations |
| **Adversarial:** 85% accuracy | LLMs fall for authority bias tricks |
| **QWED:** 100% error detection | All 22 errors caught before production |

> **QWED doesn't compete with LLMs. We ENABLE them for production use.**

📄 [Full Benchmark Report →](docs/benchmarks.md)

---

## 🎯 Use Cases & Applications

QWED is designed for industries where AI errors have real consequences:

| Industry | Use Case | Risk Without QWED |
|----------|----------|-------------------|
| 🏦 **Financial Services** | Transaction validation, fraud detection | $12,889 error per miscalculation |
| 🏥 **Healthcare AI** | Drug interaction checking, diagnosis verification | Patient safety risks |
| ⚖️ **Legal Tech** | Contract analysis, compliance checking | Regulatory violations |
| 📚 **Educational AI** | AI tutoring, assessment systems | Misinformation to students |
| 🏭 **Manufacturing** | Process control, quality assurance | Production defects |

---

## ✅ The Solution: Verification Layer

**QWED** is the first open-source **Neurosymbolic AI Verification Layer**.

We combine:
- **Neural Networks** (LLMs) for natural language understanding
- **Symbolic Reasoning** (SymPy, Z3, AST) for deterministic verification

### The Core Philosophy: "The Untrusted Translator"

QWED operates on a strict principle: **Don't trust the LLM to compute or judge; trust it only to translate.**

**Example Flow:**
```
User Query: "If all A are B, and x is A, is x B?"

↓ (LLM translates)

Z3 DSL: Implies(A(x), B(x))

↓ (Z3 proves)

Result: TRUE (Proven by formal logic)
```

The LLM is an **Untrusted Translator**. The Symbolic Engine is the **Trusted Verifier**.

---

## 💡 How QWED Compares

### The "Judge" Problem

Most AI safety tools use **"LLM-as-a-Judge"** (asking GPT-4 to grade GPT-3.5). This is fundamentally unsafe:

- **Recursive Hallucination:** If the judge has the same bias as the generator, errors go undetected
- **Probabilistic Evaluation:** LLMs give probability, not proof
- **Subjectivity:** Different judges = different answers

**QWED introduces "Solver-as-a-Judge"**: Replace neural network opinions with compiler execution and mathematical proof.

### Comparison Table

| Feature | **QWED Protocol** | BEAVER | NeMo Guardrails | LangChain Evaluators |
|---------|-------------------|--------|-----------------|----------------------|
| **The "Judge"** | Deterministic Solver (Z3/SymPy) | Probability Bounds | Semantic Matcher | Another LLM (GPT-4) |
| **Mechanism** | Translation to DSL | Token Trie Search | Vector Similarity | Prompt Engineering |
| **Verification Type** | Mathematical Proof | Probabilistic Bounds | Policy Adherence | Consensus/Opinion |
| **Primary Goal** | Correctness (Truth) | Constraint Satisfaction | Safety (Appropriateness) | Quality Score |
| **False Positives** | Near Zero (Logic-based) | Low (Statistical) | Medium (Semantic drift) | High (Subjectivity) |
| **Works Offline** | ✅ Yes (QWEDLocal) | ✅ Yes | ❌ No | ❌ No |
| **Privacy** | ✅ 100% Local | ✅ Local | ❌ Cloud-based | ❌ Cloud-based |

**QWED's Advantage:** When you need **proof**, not opinion.

---

## 🔬 The Verification Engines

QWED routes queries to specialized engines that act as DSL interpreters:


```
┌──────────────┐
│  User Query  │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ LLM (The Guesser)│
│ GPT-4 / Claude   │
└──────┬───────────┘
       │ Unverified Output
       ▼
┌────────────────────┐
│  QWED Protocol     │
│  (Verification)    │
└──────┬─────────────┘
       │
   ┌───┴────┐
   ▼        ▼
❌ Reject  ✅ Verified
            │
            ▼
   ┌────────────────┐
   │ Your Application│
   └────────────────┘
```

---

## QWED 🆚 Traditional AI Safety Approaches

| Approach | Accuracy | Deterministic | Explainable | Best For |
|----------|----------|---------------|-------------|----------|
| **QWED Verification** | ✅ 99%+ | ✅ Yes | ✅ Full trace | Production AI |
| Fine-tuning / RLHF | ⚠️ ~85% | ❌ No | ❌ Black box | General improvement |
| RAG (Retrieval) | ⚠️ ~80% | ❌ No | ⚠️ Limited | Knowledge grounding |
| Prompt Engineering | ⚠️ ~70% | ❌ No | ⚠️ Limited | Quick fixes |
| Guardrails | ⚠️ Variable | ❌ No | ⚠️ Reactive | Content filtering |

> **QWED doesn't replace these - it complements them with mathematical certainty.**

---

## 🔧 The 8 Verification Engines: How QWED Validates LLM Outputs

We don't use another LLM to check your LLM. **That's circular logic.**

We use **Hard Engineering**:

| Engine | Tech Stack | What it Solves |
|--------|------------|----------------|
| **🧮 Math Verifier** | `SymPy` + `NumPy` | Calculus, Linear Algebra, Finance. No more `$1 + $1 = $3`. |
| **⚖️ Logic Verifier** | `Z3 Prover` | Formal Verification. Checks for logical contradictions. |
| **🛡️ Code Security** | `AST` + `Semgrep` | Catches `eval()`, secrets, vulnerabilities before code runs. |
| **📊 Stats Engine** | `Pandas` + `Wasm` | Sandboxed execution for trusted data analysis. |
| **🗄️ SQL Validator** | `SQLGlot` | Prevents Injection & validates schema. |
| **🔍 Fact Checker** | `TF-IDF` + `NLI` | Checks grounding against source docs. |
| **👁️ Image Verifier** | `OpenCV` + `Metadata` | Verifies image dimensions, format, pixel data. |
| **🤝 Consensus Engine** | `Multi-Provider` | Cross-checks GPT-4 vs Claude vs Gemini. |

---

## 🧠 The QWED Philosophy: Verification Over Correction

| ❌ Wrong Approach | ✅ QWED Approach |
|-------------------|------------------|
| "Let's fine-tune the model to be more accurate" | "Let's verify the output with math" |
| "Trust the AI's confidence score" | "Trust the symbolic proof" |
| "Add more training data" | "Add a verification layer" |
| "Hope it doesn't hallucinate" | "Catch hallucinations deterministically" |

**QWED = Query with Evidence and Determinism**

> **Probabilistic systems should not be trusted with deterministic tasks.**
> **If it can't be verified, it doesn't ship.**

---

## 🔌 LLM Framework Integrations

Already using an Agent framework? QWED drops right in.

### 🦜 LangChain (Native Integration)

**Install:** `pip install 'qwed[langchain]'`

```python
from qwed_sdk.integrations.langchain import QWEDTool
from langchain.agents import initialize_agent
from langchain_openai import ChatOpenAI

# Initialize QWED verification tool
tool = QWEDTool(provider="openai", model="gpt-4o-mini")

# Add to your agent
llm = ChatOpenAI()
agent = initialize_agent(tools=[tool], llm=llm)

# Agent automatically uses QWED for verification
agent.run("Verify: what is the derivative of x^2?")
```

### 🤖 CrewAI

```python
from qwed_sdk.integrations.crewai import QWEDVerifiedAgent

agent = QWEDVerifiedAgent(role="Analyst", verify_math=True)
```

### 🦙 LlamaIndex

```python
from qwed_sdk.integrations.llamaindex import QWEDQueryEngine

# Add Fact Guard verification to any query engine
verified_engine = QWEDQueryEngine(base_engine, verify_facts=True)
```

---

## 🌐 The QWED Ecosystem

QWED verification is available as specialized packages for different industries:

### 📦 Packages

| Package | Description | Install | Repo |
|---------|-------------|---------|------|
| **qwed** | Core 8-engine verification protocol | `pip install qwed` | [GitHub](https://github.com/QWED-AI/qwed-verification) |
| **qwed-finance** 🏦 | Banking, loans, NPV, ISO 20022 | `pip install qwed-finance` | [GitHub](https://github.com/QWED-AI/qwed-finance) |
| **qwed-legal** 🏛️ | Contracts, deadlines, citations, jurisdiction | `pip install qwed-legal` | [GitHub](https://github.com/QWED-AI/qwed-legal) |
| **qwed-ucp** 🛒 | E-commerce cart/transaction verification | `pip install qwed-ucp` | [GitHub](https://github.com/QWED-AI/qwed-ucp) |
| **qwed-mcp** 🔌 | Claude Desktop MCP integration | `pip install qwed-mcp` | [GitHub](https://github.com/QWED-AI/qwed-mcp) |
| **open-responses** 🤖 | OpenAI Responses API + QWED guards | `pip install qwed-open-responses` | [GitHub](https://github.com/QWED-AI/qwed-open-responses) |

### 🎬 GitHub Actions

Use QWED verification in your CI/CD pipelines:

| Action | Use Case | Marketplace |
|--------|----------|-------------|
| `QWED-AI/qwed-legal@v0.2.0` | Contract deadline, jurisdiction, citations | [View](https://github.com/marketplace/actions/qwed-legal-verification) |
| `QWED-AI/qwed-finance@v1` | NPV, loan calculations, compliance | [View](https://github.com/marketplace/actions/qwed-finance-guard) |
| `QWED-AI/qwed-ucp@v1` | E-commerce transactions | [View](https://github.com/marketplace/actions/qwed-commerce-auditor) |

```yaml
# Example: Verify legal contracts in CI
- uses: QWED-AI/qwed-legal@v0.2.0
  with:
    mode: all
```

### 🎓 Free Course on AI Verification

**Learning Path: From Zero to Production-Ready AI Verification**

[![Course](https://img.shields.io/badge/🎓_Free_Course-AI_Verification-4CAF50?style=for-the-badge)](https://github.com/QWED-AI/qwed-learning)

- 💡 Artist vs. Accountant: Why LLMs are creative but terrible at math
- 🧮 Neurosymbolic AI: How deterministic verification catches errors
- 🏗️ Production Patterns: Build guardrails that actually work
- 🦜 Framework Integration: LangChain, LlamaIndex, and more

**🚀 [Start the Free Course →](https://github.com/QWED-AI/qwed-learning)**

📖 [Full Ecosystem Documentation](https://docs.qwedai.com)

---

## 🌍 Multi-Language SDK Support

| Language | Package | Status |
|----------|---------|--------|
| [🐍 Python](./qwed_sdk/) | `qwed` | ✅ Available on PyPI |
| [🟦 TypeScript](./sdk-ts/) | `@qwed-ai/sdk` | ✅ Available on npm |
| [🐹 Go](./sdk-go/) | `qwed-go` | ✅ Available |
| [🦀 Rust](./sdk-rust/) | `qwed` | ✅ Available on crates.io |

```bash
# Python
pip install qwed

# Go
go get github.com/QWED-AI/qwed-verification/sdk-go

# TypeScript
npm install @qwed-ai/sdk

# Rust
cargo add qwed
```

---

## 🎯 Real Example: The $12,889 Bug

**User asks AI:** "Calculate compound interest: $100K at 5% for 10 years"

**GPT-4 responds:** "$150,000"  
*(Used simple interest by mistake)*

**With QWED:**
```python
response = client.verify_math(
    query="Compound interest: $100K, 5%, 10 years",
    llm_output="$150,000"
)
# -> ❌ INCORRECT: Expected $162,889.46
#    Error: Used simple interest formula instead of compound
```

**Cost of not verifying:** $12,889 error per transaction 💸

---

## ❓ Frequently Asked Questions

### Q: How does QWED differ from RAG (Retrieval Augmented Generation)?
**A:** RAG improves the *input* to the LLM by grounding it in documents. QWED verifies the *output* deterministically. RAG adds knowledge; QWED adds certainty.

### Q: Can QWED work with any LLM?
**A:** Yes! QWED is model-agnostic and works with GPT-4, Claude, Gemini, Llama, Mistral, and any other LLM. We verify outputs, not models.

### Q: Does QWED replace fine-tuning?
**A:** No. Fine-tuning makes models better at tasks. QWED verifies they got it right. Use both.

### Q: Is QWED open source?
**A:** Yes! Apache 2.0 license. Enterprise features (audit logs, multi-tenancy) are in a separate repo.

### Q: What's the latency overhead?
**A:** Typically <100ms for most verifications. Math and logic proofs are instant. Consensus checks take longer (multiple API calls).

---

## 📚 Documentation & Resources

**Main Documentation:**
| Resource | Description |
|----------|-------------|
| [📖 Full Documentation](https://docs.qwedai.com) | Complete API reference and guides |
| [🔧 API Reference](https://docs.qwedai.com/docs/api/overview) | Endpoints and schemas |
| [⚡ QWEDLocal Guide](docs/QWED_LOCAL.md) | Client-side verification setup |
| [🖥️ CLI Reference](docs/CLI.md) | Command-line interface |
| [🔒 PII Masking Guide](docs/PII_MASKING.md) | HIPAA/GDPR compliance |
| [🆓 Ollama Integration](docs/OLLAMA_INTEGRATION.md) | Free local LLM setup |

**Project Documentation:**
| Resource | Description |
|----------|-------------|
| [📊 Benchmarks](docs/benchmarks.md) | LLM accuracy testing results |
| [🗺️ Project Roadmap](docs/roadmap.md) | Future features and timeline |
| [📋 Changelog](docs/changelog.md) | Version history summary |
| [📜 Release Notes](docs/releases/) | Detailed version release notes |
| [🎬 GitHub Action Guide](docs/github-action.md) | CI/CD integration |
| [🏗️ Architecture](docs/ARCHITECTURE.md) | System design and engine internals |

**Community:**
| Resource | Description |
|----------|-------------|
| [🤝 Contributing Guide](CONTRIBUTING.md) | How to contribute to QWED |
| [📜 Code of Conduct](CODE_OF_CONDUCT.md) | Community guidelines |
| [🔒 Security Policy](SECURITY.md) | Reporting vulnerabilities |
| [📖 Citation](docs/CITATION.cff) | Academic citation format |

---

## 🏢 Enterprise Features

Need **observability**, **multi-tenancy**, **audit logs**, or **compliance exports**?

📧 Contact: **rahul@qwedai.com**

---



## 📄 License

Apache 2.0 - See [LICENSE](LICENSE)

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=QWED-AI/qwed-verification&type=Date)](https://star-history.com/#QWED-AI/qwed-verification&Date)

<details>
<summary>If chart doesn't load, click here for alternatives</summary>

**Current Stars:** [![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-verification?style=social)](https://github.com/QWED-AI/qwed-verification/stargazers)

**View trend:** [Star History Page](https://star-history.com/#QWED-AI/qwed-verification&Date)

</details>

---

## 👥 Contributors

<a href="https://github.com/QWED-AI/qwed-verification/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=QWED-AI/qwed-verification" alt="QWED Contributors" />
</a>

---

## 📄 Citation

If you use QWED in your research or project, please cite our archived paper:

```bibtex
@software{dass2025qwed,
  author = {Dass, Rahul},
  title = {QWED Protocol: Deterministic Verification for Large Language Models},
  year = {2025},
  publisher = {Zenodo},
  version = {v1.0.0},
  doi = {10.5281/zenodo.18110785},
  url = {https://doi.org/10.5281/zenodo.18110785}
}
```

**Plain text:**
> Dass, R. (2025). QWED Protocol: Deterministic Verification for Large Language Models (Version v1.1.0). Zenodo. https://doi.org/10.5281/zenodo.18110785

---

## ✅ Using QWED in Your Project?

Add this badge to your README to show you're using verified AI:

```markdown
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification#%EF%B8%8F-what-does-verified-by-qwed-mean)
```

**Preview:**  
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification#%EF%B8%8F-what-does-verified-by-qwed-mean)

This badge tells users that your LLM outputs are deterministically verified, not just "hallucination-prone guesses."

## 🛡️ What does "Verified by QWED" mean?

When you see the **[Verified by QWED]** badge on a repository or application, it is a **technical guarantee**, not a marketing claim.

It certifies that the software adheres to the **QWED Protocol** for AI Safety:

1.  **The Zero-Hallucination Warranty:**
    The application does not rely on LLM probabilities for Math, Logic, or Code. It uses **Deterministic Engines** (SymPy, Z3, AST) to prove correctness before outputting data.

2.  **The "Untrusted Translator" Architecture:**
    The system treats the LLM solely as a translator (Natural Language → DSL), never as a judge. If the translation cannot be mathematically proven, the system refuses to answer rather than guessing.

3.  **Cryptographic Accountability:**
    The application generates **JWT-based Attestations** (ES256 signatures) for its critical operations. Every "Verified" output comes with a cryptographic receipt proving a solver validated it.

**In short: The badge means "We don't trust the AI. We trust the Math."**

---

## 🙏 Contributors Wanted

We're actively looking for contributors! Whether you're a first-timer or experienced developer, there's a place for you.

[![Good First Issues](https://img.shields.io/github/issues/QWED-AI/qwed-verification/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
[![Help Wanted](https://img.shields.io/github/issues/QWED-AI/qwed-verification/help%20wanted?label=help%20wanted&color=008672)](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)

### 🎯 Ways to Contribute

| Area | What We Need |
|------|-------------|
| 🧪 **Testing** | Add test cases for edge scenarios |
| 📝 **Docs** | Improve examples and tutorials |
| 🌍 **i18n** | Translate docs to other languages |
| 🔧 **SDKs** | Enhance Go/Rust/TypeScript SDKs |
| 🐛 **Bugs** | Fix issues or report new ones |

**[→ Read CONTRIBUTING.md](CONTRIBUTING.md)** | **[→ Browse Good First Issues](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)**

---

<div align="center">
  
  ### ⭐ Star us if you believe AI needs verification
  
  <a href="https://github.com/QWED-AI/qwed-verification">
    <img src="https://img.shields.io/github/stars/QWED-AI/qwed-verification?style=social" alt="GitHub Stars">
  </a>
  
  <br><br>
  
  <h3>Ready to trust your AI?</h3>
  <p><i>"Safe AI is the only AI that scales."</i></p>
  <br>
  <a href="CONTRIBUTING.md">Contribute</a> · 
  <a href="docs/ARCHITECTURE.md">Architecture</a> · 
  <a href="SECURITY.md">Security</a> · 
  <a href="https://docs.qwedai.com">Documentation</a>
</div>
