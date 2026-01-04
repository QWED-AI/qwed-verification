# PII Masking - Enterprise Privacy Protection

**Protect sensitive data automatically before sending to LLMs.**

> [!IMPORTANT]
> PII masking is an **enterprise privacy feature** that detects and masks Personally Identifiable Information (PII) before your data is sent to LLM providers. This is critical for HIPAA, GDPR, and PCI-DSS compliance.

---

## 📋 Table of Contents

- [What is PII Masking?](#what-is-pii-masking)
- [Why It Matters](#why-it-matters)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Supported PII Types](#supported-pii-types)
- [Usage Examples](#usage-examples)
- [Enterprise Use Cases](#enterprise-use-cases)
- [How It Works](#how-it-works)
- [Configuration](#configuration)
- [Limitations](#limitations)
- [FAQ](#faq)

---

## What is PII Masking?

PII (Personally Identifiable Information) masking automatically detects and replaces sensitive data with placeholders before sending queries to LLM providers.

**Example:**
```
Input:  "My email is john@example.com and card is 4532-1234-5678-9010"
Masked: "My email is <EMAIL_ADDRESS> and card is <CREDIT_CARD>"
```

The LLM **never sees** your sensitive data!

---

## Why It Matters

### The Problem

When you send queries to cloud LLM providers (OpenAI, Anthropic, etc.), your data passes through their servers:

```
You → OpenAI API → OpenAI Servers → Training Data (potentially)
```

**Risks:**
- 💳 **Credit card numbers** exposed
- 📧 **Email addresses** harvested
- 🔢 **SSNs** leaked
- 📞 **Phone numbers** stored
- 🏥 **Medical data** (HIPAA violation)

### The Solution

QWED masks PII **before** sending to LLMs:

```
You → QWED (masks PII) → OpenAI API (sees <EMAIL>) → Safe!
```

**Benefits:**
- ✅ **HIPAA Compliant** (Healthcare)
- ✅ **GDPR Compliant** (EU Privacy)
- ✅ **PCI-DSS Compliant** (Finance)
- ✅ **Zero Trust** architecture

---

## Installation

### Step 1: Install PII Extra

PII masking requires Microsoft Presidio (optional dependency):

```bash
pip install 'qwed[pii]'
```

### Step 2: Download spaCy Model

Presidio uses spaCy for NLP:

```bash
python -m spacy download en_core_web_lg
```

**Total install size:** ~150MB (why it's optional!)

### Verify Installation

```bash
qwed pii "test@example.com"
```

If installed correctly:
```
Original: test@example.com
Masked:   <EMAIL_ADDRESS>
Detected: 1 entities
  - EMAIL_ADDRESS: 1
```

---

## Quick Start

### Python API

```python
from qwed_sdk import QWEDLocal

# Enable PII masking
client = QWEDLocal(
    provider="openai",
    api_key="sk-...",
    mask_pii=True  # Enable masking
)

# Your sensitive data is protected!
result = client.verify("My email is john@example.com")

# Check what was masked
print(result.evidence['pii_masked'])
# {
#   'pii_detected': 1,
#   'types': ['EMAIL_ADDRESS'],
#   'positions': [(12, 28)]
# }
```

### CLI

```bash
# Verify with PII masking
qwed verify "Email: user@example.com, Card: 4532-1234-5678-9010" --mask-pii

# Test PII detection
qwed pii "My SSN is 123-45-6789"
```

---

## Supported PII Types

QWED detects **9 types** of PII using Microsoft Presidio:

| Entity Type | Examples | Use Case |
|-------------|----------|----------|
| `EMAIL_ADDRESS` | john@example.com | Identity |
| `CREDIT_CARD` | 4532-1234-5678-9010 | Finance (PCI-DSS) |
| `PHONE_NUMBER` | 555-123-4567, +1-555-1234 | Contact info |
| `US_SSN` | 123-45-6789 | Identity (US) |
| `IBAN_CODE` | DE89370400440532013000 | Banking (EU) |
| `IP_ADDRESS` | 192.168.1.1 | Network security |
| `PERSON` | John Doe, Jane Smith | Names |
| `LOCATION` | New York, 123 Main St | Addresses |
| `MEDICAL_LICENSE` | DEA-1234567 | Healthcare (HIPAA) |

### Detection Examples

```bash
# Email
qwed pii "Contact: admin@company.com"
# Masked: Contact: <EMAIL_ADDRESS>

# Credit Card
qwed pii "Card: 4532-1234-5678-9010"
# Masked: Card: <CREDIT_CARD>

# Multiple types
qwed pii "John Doe (john@example.com) lives at 123 Main St"
# Masked: <PERSON> (<EMAIL_ADDRESS>) lives at <LOCATION>
```

---

## Usage Examples

### Example 1: Healthcare (HIPAA)

**Scenario:** AI-powered medical assistant

```python
from qwed_sdk import QWEDLocal

# HIPAA-compliant client
client = QWEDLocal(
    provider="openai",
    api_key="sk-...",
    mask_pii=True  # Required for HIPAA!
)

# Query with patient data
query = """
Patient: John Doe
SSN: 123-45-6789
Email: john@example.com
Diagnosis: Calculate drug dosage for 70kg patient
"""

result = client.verify(query)

# LLM only sees:
# Patient: <PERSON>
# SSN: <US_SSN>
# Email: <EMAIL_ADDRESS>
# Diagnosis: Calculate drug dosage for 70kg patient
```

**Benefits:**
- ✅ PHI (Protected Health Information) never sent to cloud
- ✅ HIPAA compliance maintained
- ✅ Transparent audit trail in evidence

### Example 2: Finance (PCI-DSS)

**Scenario:** Fraud detection system

```python
client = QWEDLocal(
    base_url="http://localhost:11434/v1",  # Local LLM (extra security!)
    model="llama3",
    mask_pii=True
)

# Transaction with card number
query = "Verify transaction: Card 4532-1234-5678-9010 charged $500"

result = client.verify(query)

# Card number masked before processing
# Evidence shows what was protected
print(result.evidence['pii_masked'])
```

**Benefits:**
- ✅ PCI-DSS Level 1 compliance
- ✅ Card numbers never in LLM logs
- ✅ Works with local LLMs (zero cloud exposure)

### Example 3: Legal (Attorney-Client Privilege)

**Scenario:** Contract analysis

```python
client = QWEDLocal(
    provider="anthropic",
    api_key="sk-ant-...",
    mask_pii=True,
    pii_entities=["EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER"]  # Custom list
)

contract = """
Party A: John Smith (john@smithlaw.com)
Party B: Jane Doe (jane@doetech.com)
Phone: 555-1234
"""

result = client.verify(f"Analyze contract: {contract}")

# All personal data masked
```

---

## How It Works

### Architecture

```
┌─────────────────┐
│  User Query     │
│ "Email: john@   │
│  example.com"   │
└────────┬────────┘
         │
         ▼
┌────────────────────┐
│ PIIDetector        │
│ (Microsoft         │
│  Presidio)         │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ Masked Query       │
│ "Email: <EMAIL_    │
│  ADDRESS>"         │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ LLM API            │
│ (OpenAI/Anthropic) │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ Verification       │
│ Result + PII Info  │
└────────────────────┘
```

### Detection Process

1. **Analyze:** Presidio scans text for PII patterns
2. **Detect:** Identifies entity types and positions
3. **Mask:** Replaces with `<ENTITY_TYPE>` placeholders
4. **Send:** Masked text goes to LLM
5. **Evidence:** PII metadata saved for audit

### One-Way Masking

QWED uses **non-reversible** masking:
- ✅ Simple and secure
- ✅ No mapping tables to leak
- ✅ "Proving without revealing"

**Design Decision:** Values are permanently masked. We don't try to "unmask" results.

---

## Configuration

### Custom Entity Types

Only detect specific PII types:

```python
client = QWEDLocal(
    provider="openai",
    api_key="sk-...",
    mask_pii=True,
    pii_entities=["EMAIL_ADDRESS", "CREDIT_CARD"]  # Only these
)
```

### Disable for Specific Queries

```python
# Client with masking enabled
client = QWEDLocal(mask_pii=True, ...)

# But turn off for non-sensitive query
result = client.verify("What is 2+2?")  # No PII to mask anyway
```

### Environment-Based

```python
import os

# Enable PII in production only
mask_pii = os.getenv("ENV") == "production"

client = QWEDLocal(
    provider="openai",
    mask_pii=mask_pii
)
```

---

## Limitations

### 1. Detection Accuracy

- **False Positives:** May mask non-PII (e.g., "john" as name)
- **False Negatives:** May miss obfuscated PII
- **Language:** English only (v2.2.0)

### 2. Performance

- **Latency:** Adds ~100-200ms per query
- **Memory:** Requires ~150MB for spaCy model

### 3. Context Loss

Masked data loses semantic meaning:

```
Before: "Email John at john@example.com"
After:  "Email <PERSON> at <EMAIL_ADDRESS>"
```

LLM might not understand the relationship.

**Mitigation:** Use descriptive masking if needed (future feature).

---

## FAQ

### Q: Does PII masking work with Ollama?

**A:** Yes! In fact, it's **perfect** for Ollama:

```python
client = QWEDLocal(
    base_url="http://localhost:11434/v1",
    model="llama3",
    mask_pii=True  # Extra paranoid mode!
)
```

Your data **never leaves your machine**:
- ✅ LLM runs locally
- ✅ PII masked locally
- ✅ Zero cloud exposure

### Q: What if Presidio isn't installed?

**A:** Graceful error with install instructions:

```
❌ PII masking requires additional packages.

📦 Install with:
   pip install 'qwed[pii]'

📥 Then download model:
   python -m spacy download en_core_web_lg
```

### Q: Can I see what was masked?

**A:** Yes! Check the evidence:

```python
result = client.verify("Email: john@example.com", mask_pii=True)

print(result.evidence['pii_masked'])
# {
#   'pii_detected': 1,
#   'types': ['EMAIL_ADDRESS'],
#   'positions': [(7, 23)]
# }
```

### Q: Does it work with caching?

**A:** Yes! Cached results also include PII info.

### Q: What's the performance impact?

**A:** Typically 100-200ms added latency. Negligible compared to LLM API call (~1-3s).

### Q: Is it secure?

**A:** Yes:
- ✅ Runs **locally** (not a cloud service)
- ✅ Microsoft Presidio (enterprise-grade)
- ✅ No data sent to QWED servers
- ✅ One-way masking (no reverse mapping)

---

## Enterprise Use Cases

### Healthcare: HIPAA Compliance

```python
# Protected Health Information (PHI) masking
client = QWEDLocal(
    provider="openai",
    mask_pii=True,
    pii_entities=[
        "PERSON",           # Patient names
        "US_SSN",          # Social Security
        "EMAIL_ADDRESS",    # Contact info
        "PHONE_NUMBER",     # Phone numbers
        "MEDICAL_LICENSE",  # Provider IDs
        "LOCATION"          # Addresses
    ]
)
```

### Finance: PCI-DSS Compliance

```python
# Payment Card Industry compliance
client = QWEDLocal(
    provider="anthropic",
    mask_pii=True,
    pii_entities=[
        "CREDIT_CARD",  # Card numbers
        "IBAN_CODE",    # Bank accounts
        "EMAIL_ADDRESS", # Customer emails
        "PHONE_NUMBER"   # Customer phones
    ]
)
```

### Legal: Data Privacy Laws

```python
# GDPR / CCPA compliance
client = QWEDLocal(
    base_url="http://localhost:11434/v1",  # Local = zero data transfer
    mask_pii=True,
    pii_entities=[
        "PERSON",        # Client names
        "EMAIL_ADDRESS", # Contact data
        "LOCATION",      # Addresses
        "IP_ADDRESS"     # Network data
    ]
)
```

---

## Next Steps

1. **Install:** `pip install 'qwed[pii]'`
2. **Test:** `qwed pii "your sensitive text"`
3. **Integrate:** Add `mask_pii=True` to your code
4. **Audit:** Check `evidence['pii_masked']` for compliance

**Questions?** See [QWED_LOCAL.md](QWED_LOCAL.md) for more examples.

---

**© 2025 QWED. Privacy-first AI verification.**
