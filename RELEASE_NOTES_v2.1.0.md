# QWED v2.1.0 Release Notes

**Release Date:** January 3, 2026

## 🚀 Major New Feature: QWEDLocal - Client-Side Verification

**The biggest update in QWED history!** Run verification directly in your code without a backend server.

### What's New

#### ✨ QWEDLocal Class
- **No backend server needed** - Run verification directly in your application
- **Works with ANY LLM** - OpenAI, Anthropic, Gemini, Ollama, or any OpenAI-compatible API
- **$0 cost option** - Use free local models via Ollama
- **100% privacy** - Your data never touches QWED servers
- **Smart caching** - Automatic 50-80% cost savings on repeated queries

#### 🔬 Three Verification Engines
1. **Math Verification (SymPy)** - Symbolic math validation
2. **Logic Verification (Z3)** - Boolean logic SAT solving  
3. **Code Verification (AST)** - Python security analysis

#### 🎨 Beautiful CLI Tool
- `qwed verify` - One-shot verification
- `qwed interactive` - Interactive REPL mode
- `qwed cache stats/clear` - Cache management
- Colorful branded output with emojis
- Quiet mode for scripting

#### ⚡ Smart Caching Layer
- SQLite-based persistent cache
- SHA256 query hashing
- Automatic TTL expiration (24h default)
- Query normalization (case-insensitive, whitespace)
- Size limits (max 1000 entries)
- Cache hit/miss tracking

---

## 📦 Installation

```bash
pip install qwed
```

---

## 🎯 Quick Start

### Python API

```python
from qwed_sdk import QWEDLocal

# Option 1: FREE with Ollama
client = QWEDLocal(
    base_url="http://localhost:11434/v1",
    model="llama3"
)

# Option 2: OpenAI
client = QWEDLocal(
    provider="openai",
    api_key="sk-...",
    model="gpt-4o-mini"
)

# Verify!
result = client.verify_math("What is 2+2?")
print(result.verified)  # True
print(result.value)  # 4
```

### CLI

```bash
qwed verify "What is 2+2?"
qwed interactive
qwed cache stats
```

---

## 🔬 Verification Engines

### 1. Math Verification

```python
result = client.verify_math("derivative of x^2")
print(result.value)  # 2*x
```

**Technology:** SymPy symbolic math engine

### 2. Logic Verification (NEW!)

```python
result = client.verify_logic("Is (p AND NOT p) satisfiable?")
print(result.value)  # FALSE
```

**Technology:** Z3 SAT solver

### 3. Code Security (NEW!)

```python
result = client.verify_code("""
def safe_function():
    return 42
""")
print(result.value)  # "SAFE"
```

**Technology:** Python AST analysis

**Detects:**
- Dangerous functions (`eval`, `exec`, `compile`)
- System

 calls (`os`, `subprocess`)
- File operations
- Code smells

---

## ⚡ Smart Caching

**Automatic cost savings!**

```python
# First call - hits LLM
result = client.verify_math("2+2")  # ~1-2 seconds, costs $0.001

# Second call - from cache
result = client.verify_math("2+2")  # ~0.1 seconds, FREE!
```

**Cache Features:**
- ✅ Persistent storage (survives restarts)
- ✅ Query normalization (case + whitespace)
- ✅ TTL expiration (configurable)
- ✅ Hit rate tracking
- ✅ Manual clear via CLI or API

**Typical savings:** 50-80% cost reduction!

---

## 🎨 CLI Tool

### Commands

```bash
# Verify
qwed verify "What is 2+2?"

# Interactive mode
qwed interactive

# Cache stats
qwed cache stats
qwed cache clear

# Help
qwed --help
```

### Features

- ✅ Auto-detects Ollama (FREE default!)
- ✅ Colorful QWED-branded output
- ✅ Quiet mode for scripts
- ✅ Environment variable support
- ✅ Multiple provider support

---

## 💰 Cost Tiers

| Tier | Monthly Cost | LLM Options | Best For |
|------|-------------|-------------|----------|
| **Local** | **$0** | Ollama (Llama, Mistral, Phi) | Students, Privacy |
| **Budget** | **$5-10** | GPT-4o-mini, Gemini Flash | Startups |
| **Premium** | **$50-100** | GPT-4, Claude Opus | Enterprises |

**With caching: 50-80% additional savings!**

---

## 🔒 Privacy & Security

**Your data NEVER touches QWED servers!**

```
┌─────────────────────────────────┐
│ Your Machine                    │
│  ┌──────────┐                  │
│  │ QWEDLocal│ → LLM (Direct)   │
│  │          │ → Verifiers      │
│  └──────────┘   (Local)        │
│                                 │
│  ❌ NO data to QWED!           │
└─────────────────────────────────┘
```

**Perfect for:**
- Healthcare (HIPAA)
- Finance (PCI-DSS)
- Government (classified data)
- Privacy-focused apps

---

## 📖 Documentation

New comprehensive guides:

1. **[QWED_LOCAL.md](../docs/QWED_LOCAL.md)** - Complete Python API guide
2. **[CLI.md](../docs/CLI.md)** - CLI reference
3. **[OLLAMA_INTEGRATION.md](../docs/OLLAMA_INTEGRATION.md)** - FREE local LLMs

---

## 🎁 New Features

### GitHub Star Nudge

Shows friendly reminder after successful verifications:

```
────────────────────────────────────────────────────────
✨ Verified by QWED | Model Agnostic AI Verification
💚 If QWED saved you time, give us a ⭐ on GitHub!
👉 https://github.com/QWED-AI/qwed-verification
────────────────────────────────────────────────────────
```

**Smart timing:**
- Shows after 3rd successful verification
- Then every 10th verification
- Only when verification succeeds (user is happy!)

### QWED Brand Colors

Beautiful terminal output:
- 💜 **Magenta**: QWED branding
- 💚 **Green**: Success
- 🔴 **Red**: Errors
- 🔵 **Blue**: Values
- 💛 **Yellow**: Warnings
- 🔷 **Cyan**: Info

---

## 🔧 Technical Details

### New Dependencies

```bash
pip install click        # CLI framework
pip install colorama     # Colored output
pip install z3-solver    # Logic verification
```

### Architecture

```
qwed_sdk/
├── qwed_local.py    # NEW: Client-side verification
├── cache.py         # NEW: Smart caching layer
├── cli.py           # NEW: CLI tool
├── client.py        # Existing: Backend client
└── models.py        # Shared models
```

### Entry Point

```toml
[project.scripts]
qwed = "qwed_sdk.cli:cli"
```

---

## 🐛 Bug Fixes

- Fixed CLI entry point (was `main`, now `cli`)
- Fixed cache normalization for whitespace
- Fixed Z3 import error handling
- Fixed colorama fallback for no-color terminals

---

## ⚠️ Breaking Changes

**None!** This is a fully backwards-compatible release.

- Existing `QWEDClient` (backend) still works
- All existing APIs unchanged
- New `QWEDLocal` is additive

---

## 📊 What's Next (v2.2.0)

Planned features:
- 🎯 **Cost tracker** - Track $$ saved by caching
- 🤖 **Multi-model consensus** - Verify with 3 LLMs, vote
- ⚡ **Streaming output** - Live progress updates
- 🌍 **More languages** - JavaScript, Go, Rust code verification
- 📈 **Analytics dashboard** - Visualize cache hits, costs

---

## 🙏 Acknowledgments

Special thanks to:
- **Ollama team** - For making local LLMs easy
- **SymPy contributors** - Math verification backbone
- **Z3 team** - Logic verification engine
- **All our GitHub sponsors** - Supporting full-time development

---

## 📝 Migration Guide

No migration needed! Add QWEDLocal alongside existing backend:

```python
# Old (still works!)
from qwed_sdk import QWEDClient
client = QWEDClient(api_key="...")
result = client.verify("2+2")

# New (alternative)
from qwed_sdk import QWEDLocal
client = QWEDLocal(provider="openai", api_key="...")
result = client.verify("2+2")
```

---

## 🔗 Links

- **Documentation:** https://docs.qwedai.com
- **GitHub:** https://github.com/QWED-AI/qwed-verification
- **PyPI:** https://pypi.org/project/qwed/
- **Sponsor:** https://github.com/sponsors/rahuldass19

---

## ⭐ Support

If QWEDLocal saves you time or money:
1. Give us a star on GitHub! ⭐
2. Share with your team
3. Consider sponsoring development 💜

---

**Made with love by the QWED team. Happy verifying! 🚀**

---

## Version Info

- **Version:** 2.1.0
- **Released:** January 3, 2026
- **Python:** 3.10+
- **License:** Apache 2.0
