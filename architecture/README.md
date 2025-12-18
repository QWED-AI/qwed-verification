# QWED Technical Architecture Library

Welcome to the technical foundation of QWED. This directory contains the authoritative specifications for the QWED protocol, mapped directly to the codebase implementation.

---

## 🗺️ Technical Core Mapping

| Visionary Concept | Technical Implementation | Core Files |
| :--- | :--- | :--- |
| **The Symbolic Firewall** | `ControlPlane` Orchestrator | `src/qwed_new/core/control_plane.py` |
| **Untrusted Translation** | `TranslationLayer` | `src/qwed_new/core/translator.py` |
| **Deterministic Engines** | `VerificationEngine` (Unified) | `src/qwed_new/core/verifier.py` |
| **Logic Formalism** | `DSLLogicVerifier` (Z3) | `src/qwed_new/core/dsl_logic_verifier.py` |
| **Financial Precision** | `Money` Class (Decimal) | `src/qwed_new/core/money.py` |
| **SQL Armor** | `SQLVerifier` | `src/qwed_new/core/sql_verifier.py` |
| **Enterprise Audit** | `Observability` & `Logs` | `src/qwed_new/core/observability.py` |
| **Multi-Tenancy** | `TenantContext` Middleware | `src/qwed_new/core/tenant_context.py` |

---

## 📂 Documentation Deep-Dives

- **[CODEBASE_STRUCTURE.md](CODEBASE_STRUCTURE.md)**: The "Phonebook" of QWED. Every file, class, and method documented.
- **[SECURITY_IMPLEMENTATION_REPORT.md](SECURITY_IMPLEMENTATION_REPORT.md)**: Our defense-in-depth strategy, OWASP compliance, and threat models.

---

## 📊 Quick System Stats

- **Language:** Python 3.11+
- **Infrastructure:** Docker + PostgreSQL
- **Verification Engines:** 8 Integrated Engines
- **Security:** 7-Layer Defense System
- **Compliance:** OWASP LLM 2025 Ready

---

## 🚀 Deployment Snapshot

- **Production Target:** Ubuntu 22.04 LTS
- **Service Type:** Systemd + Uvicorn
- **Containerization:** Docker Compose for Database & Cache

---

## 🔗 Global Navigation

- [Back to System Vision](../docs/ARCHITECTURE.md)
- [API Reference](../docs/API.md)
- [Deployment Guide](../docs/DEPLOYMENT.md)

---

**Last Updated:** 2025-12-18  
**Maintained by:** QWED Engineering Team
