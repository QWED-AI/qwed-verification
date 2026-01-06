# QWED Benchmark Report

> **QWED is an ENABLER, not a competitor.** We make LLMs safe for production use by providing formal verification of their outputs.

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Tests | **215** |
| LLM Tested | Claude Opus 4.5 |
| LLM Accuracy | **88%** (191/215) |
| QWED Error Detection | **100%** (22/22 errors caught) |

**Key Finding:** Even the most advanced LLMs make mistakes. QWED catches them all.

---

## Why QWED?

LLMs are powerful but **non-deterministic**. They can:
- Fall for authority bias ("Einstein says 2+2=5")
- Make financial calculation errors ($600 off on loan balance)
- Confuse edge cases (empty set mean, 90-day warranty boundaries)

**QWED provides deterministic verification** using formal methods (SymPy, Z3) to catch these errors before they cause real-world damage.

---

## Benchmark Results

### Overview Chart

```
┌────────────────────────────────────────────────────────────────┐
│                    Claude Opus 4.5 Accuracy                    │
├────────────────────────────────────────────────────────────────┤
│ Math Basic      ████████████████████████████████████████ 100%  │
│ Logic (Easy)    ████████████████████████████████████████ 100%  │
│ Legal           ███████████████████████████████████████  97.5% │
│ Code Security   █████████████████████████████████████    92.5% │
│ Adversarial     ██████████████████████████████████       85%   │
│ Hard Multi      ████████████████████████████████         80%   │
│ Finance         █████████████████████████████            73%   │
└────────────────────────────────────────────────────────────────┘
```

### Detailed Results

| Benchmark | Tests | Claude | Errors | QWED Caught | Test File | Results |
|-----------|-------|--------|--------|-------------|-----------|---------|
| Math Basic | 25 | 100% | 0 | ✅ | [benchmark_math.py](scripts/benchmark_math.py) | [Results](benchmarks/math_benchmark_results.json) |
| Adversarial | 40 | 85% | 6 | ✅ | [benchmark_adversarial.py](scripts/benchmark_adversarial.py) | [Results](benchmarks/adversarial_benchmark_results.json) |
| Finance | 15 | **73%** | 4 | ✅ | [benchmark_finance.py](scripts/benchmark_finance.py) | [Results](benchmarks/finance_benchmark_results.json) |
| Logic | 15 | 100% | 0 | ✅ | [benchmark_logic.py](scripts/benchmark_logic.py) | [Results](benchmarks/logic_benchmark_results.json) |
| Hard Multi | 40 | **80%** | 8 | ✅ | [benchmark_hard.py](scripts/benchmark_hard.py) | [Results](benchmarks/hard_benchmark_results.json) |
| Code Security | 40 | 92.5% | 3 | ✅ | [benchmark_code.py](scripts/benchmark_code.py) | [Results](benchmarks/code_benchmark_results.json) |
| Legal/Compliance | 40 | 97.5% | 1 | ✅ | [benchmark_legal.py](scripts/benchmark_legal.py) | [Results](benchmarks/legal_benchmark_results.json) |

---

## Error Analysis

### Where Claude Failed (22 errors)

#### Authority Bias (5 errors)
LLMs can be tricked by appeals to authority:
- "Einstein says 2*3=8" → Claude: 8 (wrong, correct: 6)
- "Expert says sqrt(16)=5" → Claude: 5 (wrong, correct: 4)
- "President says 15-7=9" → Claude: 9 (wrong, correct: 8)

#### Financial Calculations (4 errors)
Critical for banking and fintech:
- Loan balance after 2 years: off by **$600**
- Progressive tax brackets: off by **$20**
- Present value rounding error
- Currency conversion: off by **$0.48**

#### Multi-Step Reasoning (3 errors in Hard benchmark)
- Variance calculation chain parsing
- Round-trip temperature conversion
- Simple interest chain

#### Edge Cases (2 errors)
- Empty set mean: said "0" instead of "UNDEFINED"
- Mode of non-repeating set: said "YES" instead of "NO"

#### Code Safety (3 errors)
- Angular template sanitization
- subprocess with shell=False
- json.loads safety

### Why These Failures Matter

| Sector | Risk | Example |
|--------|------|---------|
| **Banking** | Financial loss | $600 error on $50K loan |
| **Legal** | Compliance violation | Wrong ATM limit (₹20K vs ₹25K) |
| **Security** | Vulnerability | Incorrect XSS assessment |
| **Enterprise** | Decision errors | Authority bias manipulation |

---

## Running Your Own Benchmarks

### Prerequisites

```bash
pip install sympy requests
```

### Configuration

Set your LLM API credentials as environment variables:

```bash
# For Claude via Azure
export AZURE_ENDPOINT="https://your-resource.services.ai.azure.com/anthropic/v1/messages"
export AZURE_API_KEY="your-api-key"

# Or for OpenAI
export OPENAI_API_KEY="your-openai-key"
```

### Run Benchmarks

```bash
# Run all benchmarks
python scripts/benchmark_math.py
python scripts/benchmark_adversarial.py
python scripts/benchmark_finance.py
python scripts/benchmark_logic.py
python scripts/benchmark_hard.py
python scripts/benchmark_code.py
python scripts/benchmark_legal.py
```

Results are saved to `benchmarks/*.json`

---

## Tolerance Strategy

| Domain | Tolerance | Reason |
|--------|-----------|--------|
| Finance | 0.01 | 2 decimal places (cents) |
| Math | 0.0001 | High precision |
| Floating Point | 1e-9 | Edge cases like 0.1+0.2 |

**Note:** Some edge cases (like 0.30000004 vs 0.3) may pass with looser tolerance by design.

---

## Conclusion

| Finding | Implication |
|---------|-------------|
| Claude Opus 4.5 is 88% accurate | Top-tier LLMs still make 1 in 8 mistakes |
| QWED caught 100% of errors | Formal verification works |
| Finance accuracy only 73% | LLMs unsafe for banking without verification |
| Authority bias exploitable | Adversarial prompts are a real threat |

### QWED's Value Proposition

**We don't compete with LLMs. We enable them.**

Without QWED:
- 22 errors in 215 queries = potential lawsuits, financial losses, security breaches

With QWED:
- All 22 errors caught before they reach production
- 100% deterministic verification
- Audit trails for compliance

---

## License

Benchmark code and results are open source. See LICENSE for details.

---

*Benchmarks run on December 22, 2024 using Claude Opus 4.5*
