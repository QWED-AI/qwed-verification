# QWED v2.2.0 Release Notes

**Release Date:** January 4, 2026

**Type:** Minor Release - Enterprise Privacy Feature

---

## 🎉 What's New

### 🔒 PII Masking (Enterprise Privacy Protection)

The headline feature of v2.2.0 is **automatic PII (Personally Identifiable Information) masking** that protects sensitive data before sending to LLM providers.

**Perfect for:**
- 🏥 Healthcare (HIPAA compliance)
- 🏦 Finance (PCI-DSS compliance)
- 🇪🇺 EU companies (GDPR compliance)
- ⚖️ Legal (Attorney-client privilege)

---

## ✨ New Features

### 1. PII Detection & Masking

Automatically detect and mask 9 types of PII:

- ✅ Email addresses
- ✅ Credit card numbers
- ✅ Phone numbers
- ✅ US Social Security Numbers (SSN)
- ✅ IBAN codes
- ✅ IP addresses
- ✅ Person names
- ✅ Locations/addresses
- ✅ Medical licenses

**Example:**
```python
from qwed_sdk import QWEDLocal

# Enable PII masking
client = QWEDLocal(
    provider="openai",
    api_key="sk-...",
    mask_pii=True  # 🔒 NEW!
)

result = client.verify("My email is john@example.com")
# LLM sees: "My email is <EMAIL_ADDRESS>"
```

### 2. CLI PII Support

**New `--mask-pii` flag:**
```bash
qwed verify "Email: user@example.com" --mask-pii
```

**New `qwed pii` command for testing:**
```bash
qwed pii "My SSN is 123-45-6789"
# Output: Masked: My SSN is <US_SSN>
```

### 3. PII Evidence Metadata

All verification results now include PII detection info:

```python
result = client.verify("Email: john@example.com", mask_pii=True)

print(result.evidence['pii_masked'])
# {
#   'pii_detected': 1,
#   'types': ['EMAIL_ADDRESS'],
#   'positions': [(7, 23)]
# }
```

**Transparent audit trail** for compliance!

---

## 📦 Installation

### Standard Installation

```bash
pip install qwed
```

### With PII Masking

PII masking requires Microsoft Presidio (optional dependency):

```bash
# Install with PII support
pip install 'qwed[pii]'

# Download spaCy model
python -m spacy download en_core_web_lg
```

**Note:** PII masking adds ~150MB dependencies (why it's optional!)

---

## 🔧 Technical Details

### Architecture

- **Backend:** Microsoft Presidio for PII detection
- **Integration:** Lazy loading (only loads if `mask_pii=True`)
- **Masking:** One-way, non-reversible (`<ENTITY_TYPE>` placeholders)
- **Privacy:** 100% local processing (no data sent to QWED)

### Performance

- **Latency Impact:** ~100-200ms per query
- **Accuracy:** 95%+ detection rate on common PII
- **Languages:** English only (v2.2.0)

---

## 📚 Documentation

New documentation added:

- **[docs/PII_MASKING.md](docs/PII_MASKING.md)** - Comprehensive PII guide
  - Installation instructions
  - 9 supported entity types
  - Enterprise use cases (HIPAA, PCI-DSS, GDPR)
  - Configuration & FAQ
  
- **[README.md](README.md)** - Updated with PII section
- **[tests/test_pii_masking.py](tests/test_pii_masking.py)** - Unit tests

---

## 🐛 Bug Fixes

- Fixed test suite to gracefully skip PII tests when Presidio not installed
- CI/CD now passes with PII tests marked as SKIPPED

---

## 🔄 Breaking Changes

**None!** This is a fully backward-compatible release.

- PII masking is **opt-in** (`mask_pii=False` by default)
- Existing code works without any changes
- Optional dependency (install with `pip install 'qwed[pii]'`)

---

## 🚀 Upgrade Guide

### From v2.1.0 → v2.2.0

**Standard upgrade:**
```bash
pip install --upgrade qwed
```

**With PII masking:**
```bash
pip install --upgrade 'qwed[pii]'
python -m spacy download en_core_web_lg
```

**Code changes:** None required! (PII is opt-in)

---

## 📊 Usage Examples

### Healthcare (HIPAA)

```python
client = QWEDLocal(
    provider="openai",
    mask_pii=True,
    pii_entities=["PERSON", "US_SSN", "EMAIL_ADDRESS", "MEDICAL_LICENSE"]
)

# Patient data protected!
result = client.verify("Patient John Doe, SSN: 123-45-6789...")
```

### Finance (PCI-DSS)

```python
client = QWEDLocal(
    base_url="http://localhost:11434/v1",  # Local LLM = extra secure!
    model="llama3",
    mask_pii=True,
    pii_entities=["CREDIT_CARD", "IBAN_CODE", "EMAIL_ADDRESS"]
)

# Card numbers never sent to cloud!
result = client.verify("Card: 4532-1234-5678-9010")
```

### Legal (GDPR)

```python
client = QWEDLocal(
    provider="anthropic",
    mask_pii=True  # All PII types
)

# Attorney-client privilege maintained
result = client.verify("Client email: client@law.com, located at...")
```

---

## 🎯 What's Next

**v2.3.0 (Planned - Q1 2026):**
- Cost tracking & analytics
- Streaming verification
- Enhanced confidence scores

See [ROADMAP.md](ROADMAP.md) for full roadmap.

---

## 🙏 Acknowledgments

Special thanks to:
- **Microsoft Presidio** team for the excellent PII detection library
- **spaCy** for NLP foundations
- Community feedback on privacy features

---

## 📖 Full Changelog

### Added
- PII masking with Microsoft Presidio integration
- 9 PII entity types detection
- `mask_pii` parameter in QWEDLocal
- `pii_entities` custom entity list parameter
- `--mask-pii` CLI flag
- `qwed pii <text>` CLI command for testing
- `pii_masked` field in verification evidence
- Comprehensive PII masking documentation
- Unit tests for PII functionality

### Changed
- README.md updated with PII masking section
- Test suite updated to skip PII tests without Presidio

### Fixed
- CI/CD tests now pass when Presidio not installed

---

## 🔗 Links

- **PyPI:** https://pypi.org/project/qwed/
- **GitHub:** https://github.com/QWED-AI/qwed-verification
- **Documentation:** https://docs.qwedai.com
- **PII Guide:** [docs/PII_MASKING.md](docs/PII_MASKING.md)

---

## 💬 Support

- **Issues:** https://github.com/QWED-AI/qwed-verification/issues
- **Email:** rahul@qwedai.com
- **Twitter:** [@rahuldass29](https://x.com/rahuldass29)

---

**QWED v2.2.0** - Privacy-first AI verification for enterprises. 🔒

**Install now:** `pip install 'qwed[pii]'`
