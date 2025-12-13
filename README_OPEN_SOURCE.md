# QWED Open Source Ecosystem

[![PyPI](https://img.shields.io/pypi/v/qwed)](https://pypi.org/project/qwed/)
[![npm](https://img.shields.io/npm/v/@qwed/sdk)](https://www.npmjs.com/package/@qwed/sdk)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Accuracy](https://img.shields.io/badge/accuracy-99.2%25-brightgreen)](./benchmarks/)
[![Security](https://img.shields.io/badge/security-100%25-brightgreen)](./benchmarks/)

> The only open-source verification layer for production AI.

Welcome to **QWED** - The Enterprise Deterministic Verification Engine.

This repository contains the **Client SDKs** and **Benchmarks** to help you integrate and independently verify QWED's capabilities.

---

## 🤔 Why Open Source?

QWED's core verification engines are **proprietary** (our competitive moat).

But we're open-sourcing:
- ✅ **Client SDKs** - So developers can integrate easily
- ✅ **Benchmarks** - So you can verify our claims independently  
- ✅ **Examples** - So you can see real use cases

**Philosophy:** "Trust, but verify." We give you the tools to verify.

---

## 🚀 Getting Started

### 1. Get an API Key
Sign up at [qwed.tech](https://qwed.tech) to get your API key.

### 2. Choose Your SDK
- **Python:** `pip install qwed`
- **JavaScript/TypeScript:** `npm install @qwed/sdk`

### 3. Verify Your First Query
```python
from qwed import QwedClient

client = QwedClient(api_key="YOUR_KEY")
result = client.verify_natural_language("What is 10 + 10?")

print(result.final_answer)  # 20.0
print(result.status)        # "VERIFIED"
```

---

## 📦 SDKs

### Python SDK
#### Installation
```bash
pip install qwed
```

#### Advanced Usage
```python
# Verify code security
code_result = client.verify_code("print('Hello World')")

# Verify logic constraints
logic_result = client.verify_logic("x > 5 AND x < 10")

# Verify statistical claims
stats_result = client.verify_stats(csv_data, "Average sales increased by 15%")
```

### JavaScript SDK
#### Installation
```bash
npm install @qwed/sdk
```

#### Quick Start
```typescript
import { QwedClient } from '@qwed/sdk';

const client = new QwedClient("sk_live_...");

const result = await client.verifyNaturalLanguage("What is 15% of $200?");
console.log(result.finalAnswer); // 30.0
```

---

## � Example Use Cases

### Use Case 1: FinTech - Verify Loan Calculations
```python
from qwed import QwedClient

client = QwedClient(api_key="YOUR_KEY")

# User queries AI for loan payment
query = "What's the monthly payment for a $500k loan at 3.5% over 30 years?"

# QWED verifies the calculation
result = client.verify_natural_language(query)

if result.status == "VERIFIED":
    print(f"Payment: ${result.final_answer}/month")
    print(f"Proof: {result.verification}")
else:
    print("ERROR: LLM hallucinated")
```

### Use Case 2: HealthTech - Verify Drug Dosages
```python
query = "Calculate pediatric dosage: patient weighs 25kg, adult dose 500mg"
result = client.verify_natural_language(query)

# QWED uses symbolic math to ensure correctness
if result.status == "VERIFIED":
    approve_dosage(result.final_answer)
else:
    flag_for_human_review()
```

### Use Case 3: Code Security - Block Exploits
```typescript
const code = "os.remove('important.txt')";
const result = await client.verifyCode(code);

if (result.status === "UNSAFE") {
    console.log("Blocked dangerous code:", result.issues);
} else {
    executeCode(code);
}
```

---

## 📊 Benchmark Results

We tested QWED against raw LLM outputs (GPT-4, Claude) on 1000+ queries.

| Test Category | Raw LLM Accuracy | QWED Accuracy | Improvement |
|---------------|------------------|---------------|-------------|
| **Math** | 83% | 99.2% | +16.2% |
| **Security** | 0% (all exploits missed) | 100% (all caught) | +100% |
| **Logic** | 67% | 98.5% | +31.5% |
| **Overall** | 75% | 99.2% | +24.2% |

### How We Test
- 1000+ queries across 8 domains (Math, Logic, Security, Stats, Facts, SQL, Reasoning, Image)
- Edge cases included (division by zero, ambiguous queries, code injection)
- Reproducible (run `python benchmarks/api_runner.py` yourself)

### View Full Results
- [Benchmark Data (JSON)](./benchmarks/results/)
- [Test Methodology](./benchmarks/METHODOLOGY.md)

---

## 🤝 Contributing

We welcome contributions to improve the SDKs and benchmarks!

### Areas We Need Help
- [ ] Additional language SDKs (Go, Ruby, Java)
- [ ] More benchmark test cases
- [ ] Documentation improvements
- [ ] Example applications

### How to Contribute
1. Fork this repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Code of Conduct
Be kind. We're all learning.

---

## 📜 License

**SDKs:** MIT License (free to use, modify, distribute)

**QWED Core Engines:** Proprietary (contact founders@qwed.tech for licensing)

**Benchmarks:** CC0 (public domain - use freely)

---

Built with ❤️ in Mumbai by [Rahul Dass](https://twitter.com/rahuldass29)

Questions? → founders@qwed.tech
