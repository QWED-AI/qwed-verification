# QWED GitHub Action

**Neurosymbolic verification for your CI/CD pipeline**

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-QWED%20Verification-blue?logo=github)](https://github.com/marketplace/actions/qwed-neurosymbolic-verification)
[![Version](https://img.shields.io/github/v/release/QWED-AI/qwed-verification)](https://github.com/QWED-AI/qwed-verification/releases)

## What is QWED?

QWED combines **Neural Networks** (LLMs) with **Symbolic Reasoning** (SymPy, Z3) to provide deterministic verification of AI outputs.

**Use cases:**
- ✅ Verify mathematical calculations in PRs
- ✅ Check logical reasoning in documentation
- ✅ Detect unsafe code patterns
- ✅ Validate LLM outputs before deployment

## Quick Start

Add this to your `.github/workflows/verify.yml`:

```yaml
name: Verify with QWED

on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Verify Calculation
        uses: QWED-AI/qwed-verification@v2.2.0
        with:
          query: "What is the derivative of x^2?"
          provider: "openai"
          api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `query` | Question or statement to verify | ✅ Yes | - |
| `provider` | LLM provider (`openai`, `anthropic`, `gemini`) | No | `openai` |
| `api-key` | API key for LLM provider | No | - |
| `model` | Model name (e.g., `gpt-4o-mini`) | No | `gpt-4o-mini` |
| `mask-pii` | Enable PII masking (`true`/`false`) | No | `false` |
| `verification-type` | Type: `auto`, `math`, `logic`, `code` | No | `auto` |

## Outputs

| Output | Description |
|--------|-------------|
| `verified` | Verification result (`true`/`false`) |
| `value` | Verified value or result |
| `confidence` | Confidence score (0.0-1.0) |
| `evidence` | JSON evidence of verification |

## Examples

### Verify Math in PRs

```yaml
- name: Check Math
  uses: QWED-AI/qwed-verification@v2.2.0
  with:
    query: "What is 2^10?"
    provider: "openai"
    api-key: ${{ secrets.OPENAI_API_KEY }}
```

### Verify Logic

```yaml
- name: Check Logic
  uses: QWED-AI/qwed-verification@v2.2.0
  with:
    query: "Is (A AND NOT A) satisfiable?"
    provider: "anthropic"
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Check Code Security

```yaml
- name: Security Check
  uses: QWED-AI/qwed-verification@v2.2.0
  with:
    query: |
      Is this code safe?
      ```python
      eval(user_input)
      ```
    verification-type: "code"
```

### Enterprise: PII Masking

```yaml
- name: Secure Verification
  uses: QWED-AI/qwed-verification@v2.2.0
  with:
    query: "User email: john@example.com, calculate 2+2"
    mask-pii: "true"
    provider: "openai"
    api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Privacy & Security

- 🔒 **PII Masking**: Automatically mask sensitive data (emails, SSNs, credit cards)
- 🏠 **Local Option**: Use local LLMs (Ollama) for zero cloud exposure
- 🔐 **API Keys**: Use GitHub Secrets for secure credential management
- ✅ **Open Source**: Full transparency, no black boxes

## How It Works

```
Your Query
    ↓
LLM Response (GPT-4, Claude, etc.)
    ↓
Symbolic Verification (SymPy, Z3, AST)
    ↓
✅ Deterministic Proof or ❌ Verification Failure
```

**Example:**
- Query: "What is the derivative of x^2?"
- LLM says: "2x"
- SymPy computes: `diff(x**2, x) = 2*x`
- QWED: ✅ MATCH! Verified with 100% confidence

## Requirements

**API Keys** (choose one):
- OpenAI: `OPENAI_API_KEY`
- Anthropic: `ANTHROPIC_API_KEY`
- Google: `GOOGLE_API_KEY`

**Or use local LLMs** (Ollama) for free!

## Documentation

- **[Full Documentation](https://github.com/QWED-AI/qwed-verification/blob/main/README.md)**
- **[PII Masking Guide](https://github.com/QWED-AI/qwed-verification/blob/main/docs/PII_MASKING.md)**
- **[LLM Configuration](https://github.com/QWED-AI/qwed-verification/blob/main/docs/LLM_CONFIGURATION.md)**
- **[Python SDK](https://github.com/QWED-AI/qwed-verification/blob/main/docs/QWED_LOCAL.md)**

## Support

- **Issues**: [GitHub Issues](https://github.com/QWED-AI/qwed-verification/issues)
- **PyPI**: [qwed](https://pypi.org/project/qwed/)
- **Twitter**: [@rahuldass29](https://x.com/rahuldass29)

## License

Apache 2.0 - See [LICENSE](https://github.com/QWED-AI/qwed-verification/blob/main/LICENSE)

---

**Made with 💜 by [QWED-AI](https://github.com/QWED-AI)**
