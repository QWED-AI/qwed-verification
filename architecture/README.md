# QWED Architecture Documentation

This folder contains comprehensive architecture and design documentation for the QWED platform.

## 📁 Contents

- **[CODEBASE_STRUCTURE.md](CODEBASE_STRUCTURE.md)** - Complete backend codebase structure and architecture guide
  - System overview and philosophy
  - High-level architecture diagrams
  - Detailed directory structure
  - Core modules documentation
  - All 8 verification engines
  - Authentication & multi-tenancy system
  - API endpoints reference
  - Database schema
  - Provider system
  - Security & observability features
  - Agent system (Phase 2)
  - Data flow diagrams

- **[SECURITY_IMPLEMENTATION_REPORT.md](SECURITY_IMPLEMENTATION_REPORT.md)** - Enterprise security framework documentation
  - OWASP LLM Top 10 2025 compliance
  - Week 1: Core security (7-layer defense, sandboxing, output sanitization)
  - Week 2: Enterprise features (audit logging, RBAC, threat detection)
  - Production deployment details
  - Bug fixes and validation

## 🎯 Purpose

This documentation serves as the **single source of truth** for understanding the QWED backend architecture, 
making it easier for:

- **New developers** to onboard quickly
- **Contributors** to understand the system design
- **DevOps teams** to plan deployment strategies
- **Security auditors** to review the architecture
- **Product managers** to understand capabilities

## 📊 Quick Stats

- **Total Backend Files:** 65+
- **Lines of Code:** ~14,000+
- **Verification Engines:** 8
- **API Endpoints:** 20+
- **Database Tables:** 11 (enhanced with security fields)
- **Supported Domains:** Mathematics, Logic, Statistics, Fact Checking, Code Security, SQL, Images, Reasoning
- **Security Modules:** 8 (OWASP LLM 2025 compliant)
- **Production Status:** ✅ **LIVE** on Azure VM

## 🚀 Production Deployment

- **Environment:** Azure VM (Ubuntu, Python 3.10)
- **Endpoint:** http://13.71.22.94:8000
- **API Docs:** http://13.71.22.94:8000/docs
- **Status:** Operational with full security features
- **Verified:** All 7 security layers active, cryptographic audit logging enabled

## 🔗 Related Documentation

See also:
- [../docs/API.md](../docs/API.md) - API endpoint specifications
- [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) - High-level architecture overview
- [../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) - Deployment instructions
- [../docs/RATE_LIMITING.md](../docs/RATE_LIMITING.md) - Rate limiting details

---

**Last Updated:** 2025-11-29  
**Maintained by:** QWED Development Team
