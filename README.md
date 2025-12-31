<div align="center">
  <img src="assets/logo.svg" alt="QWED Logo - AI Verification Engine" width="80" height="80">
  <h1>QWED Protocol</h1>
  <h3>The Deterministic Verification Layer for AI</h3>
  
  > **QWED Verification** - Production-grade deterministic verification layer for Large Language Models (LLMs). Detect and prevent AI hallucinations through 8 specialized verification engines. Open-source Python framework for AI safety, LLM accuracy testing, and model output validation.
  
  <p>
    <b>Don't fix the liar. Verify the lie.</b><br>
    <i>QWED does not reduce hallucinations. It makes them irrelevant.</i>
  </p>

  <p>
    <b>If an AI output cannot be proven, QWED will not allow it into production.</b>
  </p>

  [![CI](https://github.com/QWED-AI/qwed-verification/actions/workflows/ci.yml/badge.svg)](https://github.com/QWED-AI/qwed-verification/actions/workflows/ci.yml)
  [![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
  [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
  [![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
  [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18110785.svg)](https://doi.org/10.5281/zenodo.18110785)
  [![status](https://joss.theoj.org/papers/385abbd3a6733fc907f1780eb5b6c927/status.svg)](https://joss.theoj.org/papers/385abbd3a6733fc907f1780eb5b6c927)
  [![PyPI version](https://img.shields.io/pypi/v/qwed.svg)](https://pypi.org/project/qwed/)
  [![Contributors](https://img.shields.io/github/contributors/QWED-AI/qwed-verification)](https://github.com/QWED-AI/qwed-verification/graphs/contributors)
  
  [![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-verification?style=social)](https://github.com/QWED-AI/qwed-verification)
  [![GitHub forks](https://img.shields.io/github/forks/QWED-AI/qwed-verification?style=social)](https://github.com/QWED-AI/qwed-verification/fork)
  [![GitHub watchers](https://img.shields.io/github/watchers/QWED-AI/qwed-verification?style=social)](https://github.com/QWED-AI/qwed-verification)

  <br>
  
  [![Twitter](https://img.shields.io/badge/Twitter-@rahuldass29-1DA1F2?style=flat&logo=twitter&logoColor=white)](https://x.com/rahuldass29)
  [![LinkedIn](https://img.shields.io/badge/LinkedIn-Rahul%20Dass-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/rahul-dass-23b370b0/)
  [![Blog](https://img.shields.io/badge/Blog-Unreadable%20Code%20Benchmark-FF5722?style=flat&logo=docusaurus&logoColor=white)](https://docs.qwedai.com/blog/unreadable-code-agi-benchmark)

  <br>
  <a href="#-quick-start-install--verify-in-30-seconds">Quick Start</a> · 
  <a href="#-the-llm-hallucination-problem-why-ai-cant-be-trusted">The Problem</a> · 
  <a href="#-the-8-verification-engines-how-qwed-validates-llm-outputs">The 8 Engines</a> · 
  <a href="#-frequently-asked-questions">FAQ</a> · 
  <a href="docs/WHITEPAPER.md">📄 Whitepaper</a> · 
  <a href="https://docs.qwedai.com">📚 Docs</a>
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

---

## 🚀 Quick Start: Install & Verify in 30 Seconds

```bash
# Install from PyPI (Recommended)
pip install qwed

# Or install from source
git clone https://github.com/QWED-AI/qwed-verification.git
cd qwed-verification
pip install -e .
```

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

📄 [Full Benchmark Report →](BENCHMARKS.md)

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

## ✅ The Solution: Give the AI a Calculator

**QWED** doesn't try to make the LLM "smarter". 

It treats the LLM as an **untrusted translator** and verifies its output using **Deterministic Engines** (SymPy, Z3, SQLGlot, AST).

> *"If an AI writes code, QWED runs the security audit.*  
> *If an AI does math, QWED runs the calculus."*

```mermaid
graph LR
    User[User Query] --> LLM[LLM - The Guesser]
    LLM -.->|Unverified Output| QWED{QWED Protocol}
    QWED -->|❌ Hallucination| LLM
    QWED -->|✅ Mathematically Proven| App[Your Application]
    
    style QWED fill:#00C853,stroke:#333,stroke-width:2px,color:white
    style LLM fill:#FF5252,stroke:#333,stroke-width:2px,color:white
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

### 🦜 LangChain

```python
from qwed_sdk.langchain import QWEDTool

tools = [QWEDTool(verification_type="math"), QWEDTool(verification_type="sql")]
```

### 🤖 CrewAI

```python
from qwed_sdk.crewai import QWEDVerifiedAgent

agent = QWEDVerifiedAgent(role="Analyst", allow_dangerous_code=False)
```

---

## 🌍 Multi-Language SDK Support

| Language | Package | Status |
|----------|---------|--------|
| 🐍 Python | `qwed` | ✅ Available on PyPI |
| 🟦 TypeScript | `@qwed-ai/sdk` | ✅ Available on npm |
| 🐹 Go | `qwed-go` | 🟡 Coming Soon |
| 🦀 Rust | `qwed` | 🟡 Coming Soon |

git clone https://github.com/QWED-AI/qwed-verification.git
cd qwed-verification
pip install -r requirements.txt
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

| Resource | Description |
|----------|-------------|
| [📖 Full Documentation](https://docs.qwedai.com) | Complete API reference and guides |
| [🔧 API Reference](https://docs.qwedai.com/docs/api/overview) | Endpoints and schemas |
| [📊 Benchmarks](https://docs.qwedai.com/blog/unreadable-code-agi-benchmark) | LLM accuracy testing results |
| [🤝 Contributing Guide](./CONTRIBUTING.md) | How to contribute to QWED |
| [🏗️ Architecture](./docs/ARCHITECTURE.md) | System design and engine internals |
| [🔒 Security Policy](./SECURITY.md) | Reporting vulnerabilities |

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
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification)
```

**Preview:**  
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification)

This badge tells users that your LLM outputs are deterministically verified, not just "hallucination-prone guesses."

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
