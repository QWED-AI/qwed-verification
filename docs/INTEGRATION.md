# 🎯 QWED Integration Guide

> **TL;DR:** Don't call your LLM yourself. Let QWED handle it. ✅

---

## ⚠️ Common Mistake

**Most users think:**

![Wrong Integration Pattern](assets/qwed_wrong_integration.png)

### ❌ DON'T DO THIS:

```python
# ❌ WRONG!
import openai
from qwed import QWEDClient

# Calling LLM yourself
response = openai.ChatCompletion.create(...)

# Then trying to verify
qwed.verify(response.content)  # TOO LATE!
```

**Why this fails:**
- 🚫 No control over LLM prompts
- 🚫 No DSL enforcement  
- 🚫 Vulnerable to prompt injection
- 🚫 Can't guarantee structured output

---

## ✅ Correct Approach

![Correct Integration Pattern](assets/qwed_correct_integration.png)

### ✅ DO THIS:

```python
# ✅ CORRECT!
from qwed import QWEDClient

qwed = QWEDClient(api_key="qwed_...")

# Just call QWED directly
result = qwed.verify("Is 2+2 equal to 4?")

print(result.verified)  # True ✅
```

**Why this works:**
- ✅ QWED controls LLM internally
- ✅ Structured prompts ensure DSL output
- ✅ Formal verification layer active
- ✅ 100% deterministic results

---

## 🔄 How QWED Really Works

![QWED Architecture Flow](assets/qwed_architecture_flow.png)

### Step-by-Step:

```
1️⃣ Your Code
    │
    ├─→ "Is 15% of 200 equal to 30?"
    │
    ▼
2️⃣ QWED API Gateway
    │
    ├─→ Sends to LLM (with special prompts)
    │   ├─→ LLM extracts: "15% × 200 = 30"
    │   └─→ Returns structured data
    │
    ├─→ Sends to Formal Verifiers
    │   ├─→ SymPy calculates: 0.15 × 200 = 30
    │   └─→ Verification: ✅ MATCH
    │
    ▼
3️⃣ Deterministic Result
    │
    └─→ {verified: true, evidence: {...}}
```

---

## 📖 Quick Start Examples

### 1️⃣ Math Verification

```python
from qwed import QWEDClient

client = QWEDClient(api_key="your_key")

# ✅ Natural language input
result = client.verify("Is 2+2 equal to 5?")

# What happens inside QWED:
# 📝 LLM extracts: "2+2=5"
# 🔬 SymPy verifies: 2+2 = 4 (not 5!)
# ❌ Returns: verified=False

print(result.verified)  # False
print(result.reason)    # "Expected 4, got 5"
print(result.evidence)  # {"calculated": 4, "claimed": 5}
```

**Visual Flow:**
```
User Query → QWED → [LLM: "2+2=5"] → [SymPy: 4≠5] → ❌ Failed
```

---

### 2️⃣ Code Security

```python
dangerous_code = """
def get_user(username):
    query = f"SELECT * FROM users WHERE name='{username}'"
    return db.execute(query)
"""

result = client.verify_code(dangerous_code, language="python")

# What happens inside QWED:
# 📝 LLM identifies: String interpolation in SQL
# 🔬 AST parser finds: User input in query
# 🚫 Security engine: SQL INJECTION RISK
# ❌ Returns: blocked=True

print(result.blocked)  # True 🚫
print(result.vulnerabilities)  # ["SQL Injection"]
print(result.severity)  # "HIGH"
```

**Visual Flow:**
```
Code → QWED → [LLM: Detects SQL] → [AST: f-string in query] → 🚫 BLOCKED
```

---

## 🎨 Visual Comparison

### Traditional LLM Call:

```
┌─────────────┐
│  Your App   │
└──────┬──────┘
       │ "Calculate 2+2"
       ▼
┌─────────────┐
│  GPT-4 API  │ 🎲 Random output
└──────┬──────┘
       │ "2 + 2 = 5"  ❌ WRONG!
       ▼
┌─────────────┐
│  Your App   │ 💥 Uses wrong answer
└─────────────┘
```

### QWED Call:

```
┌─────────────┐
│  Your App   │
└──────┬──────┘
       │ "Calculate 2+2"
       ▼
┌─────────────────────────────┐
│         QWED API             │
│  ┌──────┐       ┌─────────┐ │
│  │ LLM  │──────▶│ SymPy   │ │
│  └──────┘       └────┬────┘ │
│   "2+2=4"           │ Verify │
│                     ▼        │
│              ✅ VERIFIED     │
└──────────────────┬───────────┘
                   │ "4" ✅
                   ▼
           ┌─────────────┐
           │  Your App   │ ✅ Correct!
           └─────────────┘
```

---

## 🔐 Understanding the Security Model

### The Trust Boundary:

```
╔══════════════════════════════════════╗
║            UNTRUSTED ZONE            ║
║  ┌────────────────────────────────┐  ║
║  │   LLM (OpenAI/Anthropic/etc)   │  ║
║  │   • Can hallucinate            │  ║
║  │   • Non-deterministic          │  ║
║  │   • Prompt-injectable          │  ║
║  └────────────────────────────────┘  ║
╚════════════════╤═════════════════════╝
                 │ Structured Output (DSL)
                 ▼
╔══════════════════════════════════════╗
║           TRUSTED ZONE               ║
║  ┌────────────────────────────────┐  ║
║  │   Formal Verifiers             │  ║
║  │   • SymPy (Math)               │  ║
║  │   • Z3 (Logic)                 │  ║
║  │   • AST (Code)                 │  ║
║  │   • SQLGlot (SQL)              │  ║
║  └────────────────────────────────┘  ║
╚══════════════════════════════════════╝
```

**Key Point:** QWED ensures LLM output passes through the trust boundary via formal verification.

---

## 🎯 Do's and Don'ts

### ✅ DO:

```python
# ✅ Call QWED directly
result = qwed.verify("Calculate 15% of 200")

# ✅ Use natural language
result = qwed.verify("Is the square root of 16 equal to 4?")

# ✅ Let QWED handle LLM internally
result = qwed.verify_code(untrusted_code, language="python")

# ✅ Trust the verification results
if result.verified:
    use_output(result.value)
```

### ❌ DON'T:

```python
# ❌ Call LLM yourself first
llm_output = openai.chat(...) 
qwed.verify(llm_output)  # TOO LATE!

# ❌ Try to bypass QWED's LLM
result = qwed.verify_math("2+2", skip_llm=True)  # No such option

# ❌ Mix QWED calls with direct LLM calls
llm_result = gpt4.complete(...)
qwed_result = qwed.verify(...)  # Inconsistent!

# ❌ Assume LLM output is correct
value = llm.generate("Calculate...")
use_value_directly(value)  # DANGEROUS!
```

---

## 🎉 Quick Summary

### Remember These 3 Things:

1. **❌ Don't call LLM yourself**  
   Let QWED handle it internally

2. **✅ Call QWED directly**  
   Use natural language queries

3. **🔒 Trust the verification**  
   QWED uses formal methods, not guessing

### One-Line Integration:

```python
result = QWEDClient(api_key="...").verify("Your question here")
```

**That's it!** 🚀

---

*See [Full Integration Guide](https://docs.qwedai.com/integration) for framework integrations, debugging, and advanced usage.*
