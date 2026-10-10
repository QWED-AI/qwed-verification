# Governance Model

## Overview
This project follows a **Benevolent Dictator for Life (BDFL)** governance model. The project founder, **Rahul Dass** ([@rahuldass19](https://github.com/rahuldass19)), has the final say in all decisions but operates in consultation with the community.

QWED currently has a single maintainer.

## Roles & Responsibilities

### Benevolent Dictator for Life (BDFL)
- **Who:** Rahul Dass
- **Responsibilities:**
    - Strategic direction and roadmap
    - Final decision on controversial PRs
    - Conflict resolution
    - Release management (PyPI packages are published through PyPI Trusted Publishing, with build provenance attestations)
    - Security vulnerability response

### Maintainers
There are currently no maintainers besides the BDFL. The role is defined so that contributors with a sustained record of good contributions can be invited; maintainers will be listed here when the role is filled.

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

## Continuity
A single-maintainer project is a continuity risk. No backup maintainer with administrative access has been appointed yet; when one is, they will be named here, along with what they can do if the BDFL is unavailable for more than four weeks.

## Security & Access Control
Everyone with write access to the repository or package registries (PyPI, Docker Hub) must use two-factor authentication. GitHub 2FA is enforced at the QWED-AI organization level. Hardware keys or authenticator apps are preferred over SMS.

## Code of Conduct
This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
