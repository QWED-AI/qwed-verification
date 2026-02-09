# Governance Model

## Overview
This project follows a **Benevolent Dictator for Life (BDFL)** governance model. The project founder, **Rahul Dass** (`@rahul-dass`), has the final say in all decisions but operates in consultation with the community.

## Roles & Responsibilities

### Benevolent Dictator for Life (BDFL)
- **Who:** Rahul Dass
- **Responsibilities:**
    - Strategic direction and roadmap
    - Final decision on controversial PRs
    - Conflict resolution
    - Release management and signing
    - Security vulnerability response

### Maintainers
- **Responsibilities:**
    - Triage issues and PRs
    - Merge non-controversial PRs
    - Maintain documentation
    - Enforce Code of Conduct

### Contributors
- **Responsibilities:**
    - Submit PRs and issues
    - Adhere to `CONTRIBUTING.md`
    - Adhere to `CODE_OF_CONDUCT.md`

## Decision Making Process
Decisions are made through consensus when possible. GitHub Issues and Discussions are the primary venues for proposals. If consensus cannot be reached, the BDFL makes the final decision.

## Bus Factor Mitigation / Continuity
In the event that the BDFL is incapacitated or unavailable for more than 4 weeks:
- Administrative access to the repository, package registries (PyPI), and domain names is shared with a designated trusted backup maintainer (currently designated internally).
- This backup maintainer is authorized to appoint new maintainers or transfer leadership to ensure project continuity.

## Security & Access Control
All maintainers with write access to the repository or package registries (PyPI, Docker Hub) are **required** to have Two-Factor Authentication (2FA) enabled on their accounts. We strongly encourage the use of hardware keys (e.g., YubiKey) or TOTP apps (e.g., Google Authenticator) over SMS-based 2FA where possible.

## Code of Conduct
This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
