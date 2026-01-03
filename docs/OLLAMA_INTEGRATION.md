# QWED + Ollama Integration Guide
**Use QWED for FREE with Local LLMs!**

QWED supports **ANY** OpenAI-compatible API, including Ollama for running models locally.

---

## Why Ollama + QWED?

✅ **$0 Cost** - No API fees, just electricity  
✅ **100% Private** - Data never leaves your machine  
✅ **Full Control** - Choose any model (Llama 3, Mistral, Phi, etc.)  
✅ **Fast** - Local inference, no network latency  
✅ **Perfect for:** Students, hobbyists, privacy-focused developers

---

## Quick Start (5 Minutes)

### Step 1: Install Ollama

**macOS/Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows:**
Download from https://ollama.com/download

### Step 2: Pull a Model

```bash
# Recommended: Llama 3 (8B)
ollama pull llama3

# Or other models:
ollama pull mistral
ollama pull phi3
ollama pull codellama
```

### Step 3: Start Ollama Server

```bash
ollama serve
# Server runs on http://localhost:11434
```

### Step 4: Install QWED

```bash
pip install qwed
```

### Step 5: Use QWED with Ollama!

**Option A: Backend Server** (Recommended)
```bash
# terminal 1: Configure backend to use Ollama
cp .env.example .env

# Edit .env:
echo "ACTIVE_PROVIDER=openai" >> .env
echo "OPENAI_BASE_URL=http://localhost:11434/v1" >> .env
echo "OPENAI_API_KEY=ollama" >> .env
echo "OPENAI_MODEL=llama3" >> .env

# Start backend
python -m qwed_api
```

```python
# terminal 2: Use QWED SDK
from qwed import QWEDClient

client = QWEDClient(
    api_key="qwed_local",
    base_url="http://localhost:8000"
)

result = client.verify("What is 2+2?")
print(result.verified)  # True
print(result.value)  # 4
```

**Option B: QWEDLocal** (Coming in v2.1.0)
```python
from qwed import QWEDLocal

client = QWEDLocal(
    base_url="http://localhost:11434/v1",
    model="llama3",
    api_key="ollama"  # Dummy key
)

result = client.verify("Calculate factorial of 5")
print(result.verified)  # True
print(result.value)  # 120
```

---

## Supported Models

QWED works with any Ollama model! Tested with:

| Model | Size | Best For | Speed |
|-------|------|----------|-------|
| **llama3** | 8B | General use, best accuracy | ⚡⚡⚡ |
| **mistral** | 7B | Fast, good quality | ⚡⚡⚡⚡ |
| **phi3** | 3.8B | Low memory, decent accuracy | ⚡⚡⚡⚡⚡ |
| **codellama** | 7B | Code verification | ⚡⚡⚡ |
| **gemma** | 7B | Google's model | ⚡⚡⚡ |

---

## Complete Example

```python
from qwed import QWEDClient

client = QWEDClient(
    api_key="qwed_local",
    base_url="http://localhost:8000"  # Your QWED backend
)

# Math verification
result = client.verify_math(
    query="What is the derivative of x^2?",
    llm_output="2x"
)
print(f"✅ Verified: {result.verified}")
print(f"📊 Evidence: {result.evidence}")

# Logic verification
result = client.verify_logic(
    query="If A implies B, and B implies C, does A imply C?",
    llm_output="Yes"
)
print(f"✅ Valid: {result.verified}")

# Code security
result = client.verify_code(
    code='user_input = request.GET["q"]; eval(user_input)',
    language="python"
)
print(f"🚨 Blocked: {result.blocked}")
print(f"⚠️ Vulnerabilities: {result.vulnerabilities}")
```

---

## Cost Comparison

| Setup | Monthly Cost | Best For |
|-------|-------------|----------|
| **Ollama (Local)** | $0 💚 | Students, hobbyists, privacy |
| **OpenAI GPT-4o-mini** | ~$5-10 | Startups, quick prototypes |
| **Anthropic Claude** | ~$20-50 | Production, best accuracy |
| **OpenAI GPT-4** | ~$50-100 | Enterprises, critical systems |

**With Ollama:** 1 million verifications = $0 (just electricity!)

---

## Hardware Requirements

**Minimum (Phi3, small models):**
- 8GB RAM
- No GPU required (CPU only)
- Works on: M1 Mac, modern laptops

**Recommended (Llama 3, Mistral):**
- 16GB RAM
- GPU with 6GB+ VRAM (optional, speeds up inference)
- Works on: M1/M2 Mac, NVIDIA RTX 3060+

**Ideal (Large models):**
- 32GB+ RAM
- NVIDIA RTX 4090 / Apple M2 Ultra
- Can run: Llama 3 70B, CodeLlama 34B

---

## Troubleshooting

### Ollama not responding
```bash
# Check Ollama is running
ollama list

# Restart Ollama
ollama serve
```

### Connection refused
```bash
# Verify Ollama endpoint
curl http://localhost:11434/api/tags

# Should return list of models
```

### Slow inference
```bash
# Use smaller model
ollama pull phi3

# Or enable GPU acceleration (if available)
ollama run llama3 --gpu
```

---

## Alternative Local LLM Tools

QWED also works with:

- **LM Studio** - GUI for local models
- **LocalAI** - Drop-in OpenAI replacement
- **text-generation-webui** - Advanced UI
- **vLLM** - High-performance inference

All use OpenAI-compatible APIs → work with QWED!

---

## Privacy Benefits

**Data that NEVER leaves your machine:**
- ✅ Prompts & queries
- ✅ LLM responses
- ✅ Verification results
- ✅ User information

**Perfect for:**
- 🏥 Healthcare (HIPAA compliance)
- 🏦 Finance (sensitive data)
- 🏛️ Government (classified info)
- 🔬 Research (confidential experiments)

---

## Next Steps

**Expand your setup:**
- Try different models: `ollama pull <model>`
- Fine-tune for your domain
- Deploy to production (Docker + Ollama)

**Upgrade when needed:**
- Start free with Ollama
- Switch to cloud APIs for scale
- QWED works with both seamlessly!

---

## Community

**Questions?**
- 💬 Discussions: https://github.com/QWED-AI/qwed-verification/discussions
- 🐛 Issues: https://github.com/QWED-AI/qwed-verification/issues
- 📖 Docs: https://docs.qwedai.com

**Show your setup!**
- Tweet with #QWED #Ollama
- Share your use case
- Help others get started

---

**Remember:** QWED is model agnostic. Start free with Ollama, scale to cloud when ready! 🚀
