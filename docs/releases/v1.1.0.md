# QWED v1.1.0 - TypeScript SDK + Technical Deep Dive

Released: January 1, 2026

## 🚀 Major Updates

### 1. TypeScript SDK Published to npm ✅

```bash
npm install @qwed-ai/sdk
```

**Available now on npmjs.com!**
- Full TypeScript typing support
- Works with Node.js and browser (ESM/CJS)
- Same API as Python SDK
- 216 downloads on Zenodo whitepaper (high interest!)

**Example:**
```typescript
import { QWEDClient } from '@qwed-ai/sdk';

const client = new QWEDClient({ apiKey: 'your_key' });
const result = await client.verifyMath('2+2', '4');
console.log(result.verified); // true
```

**NPM Package:** [@qwed-ai/sdk](https://www.npmjs.com/package/@qwed-ai/sdk)

---

### 2. Comprehensive Technical Documentation (566 Lines Added)

**New Whitepaper Sections:**

#### ✅ Section 3.4: Output Format Enforcement (197 lines)
- Function calling mechanism (OpenAI Tools/Anthropic Tool Use)
- Pydantic schema validation
- Pre-verification schema checks
- **Result:** Zero ambiguity in LLM outputs

#### ✅ Section 4.2.1: DSL-Based Logic Security (170 lines)
- **CRITICAL:** Complete DSL documentation (was missing!)
- Whitelist-based S-expression parsing
- No `eval()`, `exec()`, or `__import__()` - guaranteed
- 40+ whitelisted operators
- Secure compilation to Z3

#### ✅ Section 4.3.1: Language Detection (91 lines)
- Explicit language declaration (Python, JS, Go, SQL, etc.)
- Language-specific AST parsers
- No misidentification possible

#### ✅ Section 4.4.1: SQL AST-Based Obfuscation Detection (90 lines)
- AST parsing (not regex!)
- Catches obfuscated injections: `WHERE /**/1/**/=/**/1`
- Tautology detection

#### ✅ Section 3.3.1: Handling Ambiguous Outputs
- Function calling prevents multiple values
- Schema rejects `List[float]` when expecting `float`

#### ✅ Section 6.4: Case Study Methodology Note
- Clarifies $12,889 bug is illustrative
- References actual benchmark data

**Whitepaper DOI:** [10.5281/zenodo.18110785](https://doi.org/10.5281/zenodo.18110785)

---

### 3. PDF-Friendly Documentation

- Replaced all Mermaid diagrams with ASCII art
- Works in GitHub, PDF exports, and offline docs
- 5 diagrams updated across all repos

---

## 📦 What's Included

### SDKs Available

| Language | Package | Install | Status |
|----------|---------|---------|--------|
| **Python** | `qwed` | `pip install qwed` | ✅ Live on PyPI |
| **TypeScript** | `@qwed-ai/sdk` | `npm install @qwed-ai/sdk` | ✅ **NEW: Live on npm!** |
| **Go** | In repo | See `sdk-go/README.md` | 🔶 Source available |
| **Rust** | In repo | See `sdk-rust/README.md` | 🔶 Source available |

---

## 🔧 Integrations

- ✅ LangChain (439 lines, production-ready)
- ✅ CrewAI (455 lines, production-ready)
- ✅ LlamaIndex (full integration)

---

## 📊 Benchmarks

**Against Claude Opus 4.5:**
- Financial calculations: 73% LLM accuracy → 100% QWED detection
- Mathematical reasoning: 81% → 100%
- Adversarial prompts: 85% → 100%
- Code security: 78% → 100%

**215 test cases, 100% error detection rate**

---

## 🐛 Bug Fixes

- Fixed Mermaid diagram rendering on GitHub (chunk 2291 error)
- Updated DOI references across all documentation
- Corrected Zenodo version field formatting

---

## 📖 Documentation

- **Whitepaper:** [v1.1.0 on Zenodo](https://doi.org/10.5281/zenodo.18110785) (222 downloads!)
- **API Docs:** [docs.qwedai.com](https://docs.qwedai.com)
- **Examples:** See `examples/` directory
- **Benchmarks:** See `benchmarks/` directory

---

## 🔗 Links

- **TypeScript SDK:** https://www.npmjs.com/package/@qwed-ai/sdk
- **Python SDK:** https://pypi.org/project/qwed/
- **Whitepaper:** https://doi.org/10.5281/zenodo.18110785
- **Documentation:** https://docs.qwedai.com
- **JOSS Paper:** https://joss.theoj.org/papers/385abbd3a6733fc907f1780eb5b6c927

---

## 🙏 Contributors

- [@rahuldass19](https://github.com/rahuldass19)

---

## 📜 License

Apache 2.0

---

## 🎯 What's Next?

- JOSS peer review submission
- Go SDK official release (pkg.go.dev)
- Rust SDK on crates.io
- Additional language support
- More verification engines

---

**Full Changelog:** https://github.com/QWED-AI/qwed-verification/compare/v2.0.0...v1.1.0
