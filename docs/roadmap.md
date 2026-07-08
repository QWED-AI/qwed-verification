# QWED Roadmap — Historical Archive

> ⚠️ **This document is a historical archive.** The QWED roadmap has moved to [docs.qwedai.com](https://docs.qwedai.com). The information below is preserved for reference only and may not reflect the current (v5.2.0+) ecosystem.

**Vision:** The First Open Source Neurosymbolic AI Guardrail

---

## What is Neurosymbolic AI?

QWED combines:
- **Neural Networks** (LLMs like GPT-4, Claude, Llama) for natural language understanding
- **Symbolic Reasoning** (SymPy, Z3, AST) for deterministic verification

This hybrid approach gives you the best of both worlds: LLMs translate problems into formal logic, and symbolic engines provide mathematical proof.

---

## Completed ✅

### v2.1.0 - "QWEDLocal" (January 2026)
- Client-side verification (no backend needed)
- Math verification (SymPy)
- Logic verification (Z3)
- Code security (AST)
- Smart caching (50-80% cost savings)
- Beautiful CLI tool
- Works with ANY LLM (Ollama, OpenAI, Anthropic, Gemini)

---

## Next Up 🚀

### v2.2.0 - "The Privacy Release" (Late January 2026)

**Theme:** Enterprise-Ready Security

#### Features:
- **PII Masking** 🔒
  - Detect and mask sensitive data before sending to LLMs
  - Credit cards, SSNs, emails, phone numbers
  - Uses Microsoft Presidio
  - `mask_pii=True` parameter

- **Enhanced Confidence Scores** 📊
  - Granular scoring (not just 0% or 100%)
  - Visual confidence bars in CLI
  - Reasoning explanations

- **Neurosymbolic Branding** 🧠
  - Updated positioning as neurosymbolic guardrail
  - Technical documentation

**Why These Features?**
- PII masking unlocks enterprise/healthcare/banking customers
- Enhanced confidence provides nuanced feedback
- Neurosymbolic positioning differentiates from competitors

---

### v2.3.0 - "The Intelligence Release" (Mid February 2026)

**Theme:** Developer Experience

#### Features:
- **Cost Tracker** 💸
  - Track API spending per query
  - Show cache savings
  - Budget alerts
  - Weekly/monthly reports

- **Streaming Verification** ⚡
  - Live progress updates
  - Better UX for slow queries
  - Generator-based API

**Why These Features?**
- Cost tracking helps developers optimize spend
- Streaming improves perceived performance

---

## Future Considerations 💭

### Potential v2.4.0+ Features:
- Multi-model consensus (3 LLMs vote, majority wins)
- More programming languages (JavaScript, Go, Rust)
- RAG verification (validate RAG pipeline outputs)
- Enhanced code verification (more languages)

**Note:** Features will be prioritized based on user feedback and adoption.

---

## What We Won't Build ❌

### Fact Verification (Dropped)
**Why:** QWED's strength is **deterministic** verification (Math, Logic, Code = 100% or 0%). Adding **probabilistic** fact-checking (Wikipedia, news = 60-90% accuracy) would dilute our core value proposition and risk damaging user trust in our deterministic engines.

**Alternative:** Recommend users use specialized fact-checking tools for this use case.

---

## How to Contribute

We welcome contributions! Here's how you can help:

1. **Try QWEDLocal** - Use it, find bugs, suggest improvements
2. **Documentation** - Help improve guides and examples
3. **Code** - Pick an issue labeled `good first issue` or `help wanted`
4. **Feedback** - Tell us what features YOU need

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

---

## Timeline

| Version | Theme | Target Date |
|---------|-------|-------------|
| v2.1.0 | QWEDLocal ✅ | January 2026 |
| v2.2.0 | Privacy | Late January 2026 |
| v2.3.0 | Intelligence | Mid February 2026 |
| v2.4.0+ | TBD | Spring 2026 |

*Dates are estimates and may change based on development progress.*

---

## Questions?

- **GitHub Discussions:** Ask questions, propose features
- **Issues:** Report bugs, request features
- **Twitter:** [@rahuldass29](https://twitter.com/rahuldass29) for updates

---

**Built with 💜 for a deterministic future.**
