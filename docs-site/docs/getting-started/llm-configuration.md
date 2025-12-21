---
sidebar_position: 4
---

# LLM Configuration

QWED works with any LLM provider. This guide shows you how to configure different LLM backends.

## Understanding QWED's Architecture

QWED uses LLMs as **untrusted translators**, not as answer generators:

```
┌──────────────────────────────────────────────────────────────────┐
│                    QWED VERIFICATION PIPELINE                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  User Query     LLM (Translator)     QWED (Verifier)    Result   │
│      │                │                    │               │     │
│      ▼                ▼                    ▼               ▼     │
│  "Is 2+2=5?"  →  "2+2=5"  →  [SymPy: 2+2=4]  →  ❌ CORRECTED: 4  │
│                                                                   │
│  Your LLM           ↑            Our Engines      Deterministic  │
│  (any provider)   Untrusted        (Trusted)       Guarantee     │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

> **Key Insight:** The LLM translates natural language to structured form. QWED then verifies the structured form using deterministic engines. The LLM can be wrong — QWED catches and corrects errors.

## Supported LLM Providers

| Provider | Env Variable | Models |
|----------|-------------|--------|
| **OpenAI** | `OPENAI_API_KEY` | gpt-4o, gpt-4-turbo, gpt-3.5-turbo |
| **Anthropic** | `ANTHROPIC_API_KEY` | claude-3-opus, claude-3-sonnet |
| **Google** | `GOOGLE_API_KEY` | gemini-pro, gemini-ultra |
| **Azure OpenAI** | `AZURE_OPENAI_*` | Any Azure-hosted model |
| **Local/Ollama** | `OLLAMA_BASE_URL` | llama2, mistral, codellama |
| **Custom** | `QWED_LLM_BASE_URL` | Any OpenAI-compatible API |

---

## Configuration Options

### Option 1: Use QWED's Built-in Translation (Recommended)

QWED can handle LLM translation internally:

```python
from qwed import QWEDClient

# QWED uses its own LLM for translation
client = QWEDClient(api_key="qwed_your_key")

result = client.verify("What is 15% of 200?")
# QWED internally: "15% of 200" → 0.15 * 200 → verify with SymPy → 30
```

### Option 2: Bring Your Own LLM

Use QWED purely as a verification layer:

```python
from qwed import QWEDClient
import openai

# Your LLM call
openai_client = openai.OpenAI(api_key="sk-...")
response = openai_client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "What is 847 × 23?"}]
)
llm_answer = response.choices[0].message.content

# QWED verification only (no LLM needed)
qwed = QWEDClient(api_key="qwed_your_key")
result = qwed.verify_math(
    expression="847 * 23",
    expected_result=llm_answer
)

if result.verified:
    print(f"✅ LLM was correct: {llm_answer}")
else:
    print(f"❌ LLM was wrong. Correct: {result.corrected}")
```

### Option 3: Self-Hosted with Custom LLM

For self-hosted deployments, configure your LLM:

```bash
# .env file for self-hosted QWED

# Choose your LLM provider
QWED_LLM_PROVIDER=openai    # openai, anthropic, google, azure, ollama, custom

# Provider-specific keys
OPENAI_API_KEY=sk-...
# OR
ANTHROPIC_API_KEY=sk-ant-...
# OR
GOOGLE_API_KEY=AIza...
# OR
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-4
# OR
OLLAMA_BASE_URL=http://localhost:11434

# Model selection (optional)
QWED_LLM_MODEL=gpt-4o               # Default model for translation
QWED_LLM_TEMPERATURE=0.0            # Deterministic translation
QWED_LLM_MAX_TOKENS=1000            # Max tokens for translation
```

---

## Provider-Specific Setup

### OpenAI

```bash
export QWED_LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-your-key-here
export QWED_LLM_MODEL=gpt-4o
```

### Anthropic (Claude)

```bash
export QWED_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-your-key-here
export QWED_LLM_MODEL=claude-3-sonnet-20240229
```

### Google (Gemini)

```bash
export QWED_LLM_PROVIDER=google
export GOOGLE_API_KEY=AIzaSy-your-key-here
export QWED_LLM_MODEL=gemini-pro
```

### Azure OpenAI

```bash
export QWED_LLM_PROVIDER=azure
export AZURE_OPENAI_API_KEY=your-azure-key
export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
export AZURE_OPENAI_DEPLOYMENT=gpt-4
export AZURE_OPENAI_API_VERSION=2024-02-15-preview
```

### Local LLMs (Ollama)

```bash
# Start Ollama
ollama serve

# Pull a model
ollama pull llama2

# Configure QWED
export QWED_LLM_PROVIDER=ollama
export OLLAMA_BASE_URL=http://localhost:11434
export QWED_LLM_MODEL=llama2
```

### Custom OpenAI-Compatible API

For any API that's OpenAI-compatible (vLLM, LiteLLM, etc.):

```bash
export QWED_LLM_PROVIDER=custom
export QWED_LLM_BASE_URL=http://your-server:8000/v1
export QWED_LLM_API_KEY=your-custom-key
export QWED_LLM_MODEL=your-model-name
```

---

## Programmatic Configuration

```python
from qwed import QWEDClient, LLMConfig

# Option 1: Use environment variables (recommended)
client = QWEDClient()

# Option 2: Explicit configuration
client = QWEDClient(
    api_key="qwed_your_key",
    llm_config=LLMConfig(
        provider="openai",
        api_key="sk-...",
        model="gpt-4o",
        temperature=0.0,
    )
)

# Option 3: No LLM (verification only)
client = QWEDClient(
    api_key="qwed_your_key",
    llm_enabled=False  # Only use deterministic verification
)
```

---

## Translation vs Verification

Understanding the two phases:

| Phase | What Happens | Who Does It | Required? |
|-------|--------------|-------------|-----------|
| **Translation** | Natural language → Structured form | LLM (any) | Optional |
| **Verification** | Structured form → Proof | QWED Engines | Required |

### When You Need an LLM

- `client.verify("Is the derivative of x² equal to 2x?")` — Needs LLM to parse
- `client.verify("Calculate compound interest on $1000 at 5%")` — Needs LLM

### When You Don't Need an LLM

- `client.verify_math("diff(x**2, x) == 2*x")` — Already structured
- `client.verify_logic("(AND (GT x 5) (LT x 10))")` — Already in DSL
- `client.verify_sql("SELECT * FROM users")` — Already structured
- `client.verify_code("import os; os.system('rm -rf /')")` — Code, not NL

---

## FAQ

### Do I need an LLM to use QWED?

**No.** If you're sending structured queries (math expressions, SQL, code, QWED-Logic DSL), you don't need an LLM. QWED engines work directly on structured input.

### Can I use my own LLM and just use QWED for verification?

**Yes.** This is the "Bring Your Own LLM" pattern. Call your LLM, then pass its output to QWED for verification.

### Which LLM is best for QWED translation?

For translation accuracy, we recommend:
1. GPT-4o (best)
2. Claude 3 Opus
3. Gemini Pro
4. GPT-3.5-turbo (good for simple queries)

### Is the LLM translation deterministic?

We set `temperature=0` for reproducibility, but LLMs are inherently probabilistic. That's why **QWED verification is essential** — it provides the determinism guarantee.

---

## Next Steps

- [Quick Start Tutorial](/docs/getting-started/quickstart)
- [QWED-Logic DSL Reference](/docs/api/dsl-reference)
- [Self-Hosting Guide](/docs/advanced/self-hosting)
