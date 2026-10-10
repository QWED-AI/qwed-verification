# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 7.2.x (latest release) | :white_check_mark: |
| < 7.2   | :x: |

Security fixes are released for the latest version only.

## Reporting a Vulnerability

We take the security of QWED very seriously. If you discover a security vulnerability, please report it to us immediately.

### How to Report

Please do **not** report security vulnerabilities through public GitHub issues, pull requests, or discussions.

Instead, please report them privately via email to:  
**rahul@qwedai.com**

You can also report privately through [GitHub Security Advisories](https://github.com/QWED-AI/qwed-verification/security/advisories/new).

Please include as much information as possible to help us reproduce and fix the issue, including:
- Steps to reproduce the issue
- Affected version(s)
- Relevant code, configuration, logs, or screenshots
- Proof-of-concept or exploit details, if available
- The potential impact on confidentiality, integrity, or availability

### Response Timeline

We are committed to addressing security issues promptly.

- We aim to acknowledge your report within **3 business days**. QWED has a single maintainer, so a response may occasionally take longer.
- We will triage and validate the report as quickly as possible
- We will keep you informed of progress during investigation and remediation
- We will coordinate disclosure timing with you when appropriate

### Coordinated Disclosure

Please give us a reasonable amount of time to investigate and remediate the issue before making any public disclosure.

We ask that you:
- Avoid publicly disclosing the issue until a fix or mitigation is available
- Make a good-faith effort to avoid privacy violations, data destruction, or service disruption
- Avoid accessing, modifying, or exfiltrating data beyond what is necessary to demonstrate the issue

### Reporter Credit

We value the security community and will publicly credit vulnerability reporters who responsibly disclose issues and do not request anonymity. Credit may be given in release notes, advisories, or repository security history.

### Acknowledgments

We thank the following people, credited in the published advisories, for responsibly disclosed findings:

- **EQSTLab** ([@EQSTLab](https://github.com/EQSTLab)), reporter, and **2REBCat** ([@2REBCat](https://github.com/2REBCat)), analyst: SymPy expression injection, [GHSA-q27q-98j4-9pfv](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-q27q-98j4-9pfv) / CVE-2026-55585, fixed in 5.1.2.
- **manus-pi** ([@manus-pi](https://github.com/manus-pi)) and **manus-use** ([@manus-use](https://github.com/manus-use)), reporters: unsanitized `sympify()` in the math verifier, [GHSA-xmm6-8r3x-j567](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-xmm6-8r3x-j567), fixed in 7.2.1.

Thanks also to **andesyteoss** ([@andesyteoss](https://github.com/andesyteoss)) for contributing the expression-parsing fix in [#200](https://github.com/QWED-AI/qwed-verification/pull/200).

The full list of published advisories, with affected and fixed versions, is on the [Security tab](https://github.com/QWED-AI/qwed-verification/security/advisories).

## Security Issue vs. Bug

To help us triage issues effectively, please distinguish between security issues and bugs:

- **Security issue:** A vulnerability that compromises the confidentiality, integrity, or availability of the system, such as code execution, injection, auth bypass, privilege escalation, sensitive data exposure, sandbox escape, or fail-open security behavior. Please report these privately as described above.
- **Bug:** A functional defect or unexpected behavior that does not have security implications, such as a UI issue, incorrect calculation, documentation problem, or non-exploitable crash. Please report these via the [GitHub Issue Tracker](https://github.com/QWED-AI/qwed-verification/issues).

Thank you for helping keep QWED secure.
