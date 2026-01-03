# QWED CLI Reference

**Beautiful command-line interface for QWED verification.**

## Installation

```bash
pip install qwed
```

The `qwed` CLI is automatically available after installation.

---

## Commands

### `qwed verify` - One-Shot Verification

Verify a query and exit.

```bash
qwed verify "What is 2+2?"
qwed verify "derivative of x^2" --provider openai
qwed verify "Is (p AND q) satisfiable?" --model llama3
```

**Options:**
- `--provider, -p` - LLM provider (`openai`, `anthropic`, `gemini`)
- `--model, -m` - Model name (e.g., `gpt-4o-mini`, `llama3`)
- `--base-url` - Custom API endpoint (for Ollama: `http://localhost:11434/v1`)
- `--api-key` - API key (or use `QWED_API_KEY` env var)
- `--no-cache` - Disable caching
- `--quiet, -q` - Minimal output (for scripts)

**Examples:**

```bash
# Ollama (auto-detected)
qwed verify "2+2"

# OpenAI
qwed verify "factorial of 5" --provider openai --api-key sk-...

# Custom endpoint
qwed verify "x^2 derivative" --base-url http://localhost:11434/v1 --model mistral

# Quiet mode
qwed verify "2+2" --quiet  # Just outputs: ✅ VERIFIED: 4
```

---

### `qwed interactive` - Interactive Mode

Start an interactive REPL session.

```bash
qwed interactive
qwed interactive --provider openai
qwed interactive --model llama3
```

**Usage:**

```bash
$ qwed interactive

🔬 QWED Interactive Mode
Type 'exit' or 'quit' to quit

> What is 2+2?
🔬 QWED Verification | Math Engine
📝 LLM Response: 4
✅ VERIFIED → 4

> stats
📊 Cache Statistics
Hits: 0
Misses: 1
Hit Rate: 0.0%

> exit
```

**Special Commands:**
- `stats` - Show cache statistics
- `exit`, `quit`, `q` - Exit interactive mode

---

### `qwed cache` - Cache Management

Manage verification result cache.

#### `qwed cache stats`

Show cache statistics.

```bash
$ qwed cache stats

📊 Cache Statistics
Hits: 156
Misses: 44
Hit Rate: 78.0%
Total Entries: 42/1000
Cache Size: 12.3 KB
```

#### `qwed cache clear`

Clear all cached results.

```bash
$ qwed cache clear
Are you sure you want to clear the cache? [y/N]: y
✅ Cache cleared!
```

---

## Environment Variables

### `QWED_API_KEY`

Set default API key (useful for scripts).

```bash
export QWED_API_KEY="sk-proj-..."
qwed verify "2+2"  # Uses env var API key
```

### `QWED_QUIET`

Disable colorful branding output.

```bash
export QWED_QUIET=1
qwed verify "2+2"  # Minimal output
```

---

## Configuration

### Provider Priority

QWED auto-detects providers in this order:

1. **Command-line flags** (`--provider`, `--base-url`)
2. **Environment variables** (`QWED_API_KEY`)
3. **Ollama default** (tries `http://localhost:11434/v1`)

### Default Models

| Provider | Default Model |
|----------|--------------|
| Ollama | `llama3` |
| OpenAI | `gpt-3.5-turbo` |
| Anthropic | `claude-3-haiku` |
| Gemini | `gemini-pro` |

---

## Output Formats

### Colorful Output (Default)

```
🔬 QWED Verification | Math Engine
📝 LLM Response: 4
✅ VERIFIED → 4

────────────────────────────────────────────────────────
✨ Verified by QWED | Model Agnostic AI Verification
💚 If QWED saved you time, give us a ⭐ on GitHub!
👉 https://github.com/QWED-AI/qwed-verification
────────────────────────────────────────────────────────
```

### Quiet Output (`--quiet`)

```
✅ VERIFIED: 4
```

### Error Output

```
❌ Error: Ollama not running. Either:
1. Start Ollama: ollama serve
2. Or specify provider explicitly
```

---

## Use Cases

### 1. Quick Verification

```bash
qwed verify "Is 17 a prime number?"
```

### 2. Scripting

```bash
#!/bin/bash
export QWED_QUIET=1
export QWED_API_KEY="sk-..."

result=$(qwed verify "2+2" --provider openai)
if [[ $result == *"VERIFIED"* ]]; then
    echo "Math checks out!"
fi
```

### 3. Local Development

```bash
# Start Ollama
ollama serve

# Verify without API costs
qwed interactive

> What is the derivative of x^3?
✅ VERIFIED → 3*x**2
```

### 4. Cache Performance Testing

```bash
# First run (cache miss)
time qwed verify "complex calculation"  # ~2 seconds

# Second run (cache hit)
time qwed verify "complex calculation"  # ~0.1 seconds!
```

---

## Troubleshooting

### "Ollama not running"

```bash
# Check Ollama status
curl http://localhost:11434/v1/models

# Start Ollama
ollama serve
```

### "API key required"

```bash
# Set env var
export QWED_API_KEY="sk-..."

# Or pass directly
qwed verify "query" --api-key sk-...
```

### "Module not found"

```bash
# Install missing LLM clients
pip install openai anthropic google-generativeai

# Install verification engines
pip install sympy z3-solver
```

---

## Advanced Features

### Caching Behavior

- **Default:** Enabled (24h TTL)
- **Disable:** `--no-cache` flag
- **Clear:** `qwed cache clear`
- **Stats:** `qwed cache stats`

### Multiple Providers

```bash
# Compare results across providers
qwed verify "2+2" --provider openai
qwed verify "2+2" --base-url http://localhost:11434/v1
qwed verify "2+2" --provider anthropic
```

---

## Related Docs

- **[QWEDLocal Guide](QWED_LOCAL.md)** - Python API
- **[Ollama Integration](OLLAMA_INTEGRATION.md)** - FREE local LLMs
- **[Full Documentation](https://docs.qwedai.com)** - Complete docs

---

**Made with 💜 by the QWED team**
