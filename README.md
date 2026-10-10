<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/qwed-lockup-white.svg">
    <img src="assets/qwed-lockup.svg" alt="QWED" height="56">
  </picture>

  <p><b>Open-source verification for LLM and AI-agent output.</b></p>

  [![PyPI](https://img.shields.io/pypi/v/qwed.svg)](https://pypi.org/project/qwed/)
  [![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
  [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11903/badge)](https://www.bestpractices.dev/projects/11903)
  [![Docker Hub](https://img.shields.io/badge/Docker_Hub-Sponsored_OSS-blue.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/qwedai/qwed-verification)
  [![codecov](https://codecov.io/gh/QWED-AI/qwed-verification/branch/main/graph/badge.svg)](https://codecov.io/gh/QWED-AI/qwed-verification)
  [![DOI](https://zenodo.org/badge/1115581942.svg)](https://doi.org/10.5281/zenodo.18111675)

  [Website](https://qwedai.com) · [Documentation](https://docs.qwedai.com) · [Install](#install) · [Engines](#engines-and-guards) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)
</div>

---

QWED is an open-source (Apache-2.0) verification layer that checks claims in LLM and AI-agent output with deterministic engines, including SymPy, Z3, SQLGlot and Python AST analysis. A claim that QWED cannot check is never reported as verified: it fails closed. It runs in your own environment as a Python library, a CLI, a self-hosted API or a Docker image, with SDKs for TypeScript, Go and Rust.

This repository is the reference implementation of the QWED verification protocol and of [Verification Context v1.0](spec/), the record format for a verification result.

## How a result reads

Every verification API endpoint returns a `DiagnosticResult` with two separate answers:

| Field | Values | Meaning |
|---|---|---|
| `status` | `VERIFIED`, `UNVERIFIABLE`, `BLOCKED` | Whether QWED could establish the result deterministically. `VERIFIED` always carries a `proof_ref`, a SHA-256 commitment to the evidence. |
| `admission` | `ADMIT`, `BLOCKED` | Whether the checked output may be acted on. In a Verification Context document this is `ADMIT` or `DENY`. |

The two are independent. Proving that a SQL statement is destructive is a verified result that must not run:

```python
from qwed_new.core.sql_verifier import SQLVerifier
from qwed_new.core.diagnostics import admission_decision

result = SQLVerifier().verify_sql(
    "DELETE FROM users WHERE id = 1 OR 1 = 1",
    schema_ddl="CREATE TABLE users (id INT)",
)
print(result.status.value, admission_decision(result).value)
# VERIFIED BLOCKED
print([issue["type"] for issue in result.developer_fields["issues"]])
# ['destructive_command', 'injection_tautology']
```

## What QWED does not do

- **It does not check intent.** QWED verifies the formal statement it is given or extracts, not whether that statement is what the user meant.
- **It does not cover every domain.** Claims outside a supported engine come back `UNVERIFIABLE`.
- **It is only as sound as its engines.** Results depend on SymPy, Z3, SQLGlot, CrossHair and QWED's own rule sets. Past soundness bugs are listed in the [security advisories](https://github.com/QWED-AI/qwed-verification/security/advisories).
- **Natural-language checks use an LLM to translate.** `/verify/natural_language` and `/verify/logic` ask the model you configure to turn text into a formal statement; that translation is not itself verified. Prompts go to that provider unless you run a local model (for example with Ollama).
- **Advisory engines do not decide.** Fact, Graph, Image, Reasoning and Consensus produce signals for review. Heuristic results are never reported as `VERIFIED`.

## Install

Python 3.10 or newer:

```bash
pip install qwed
```

This installs the core engines (Math, Logic with Z3, SQL with SQLGlot, Code, Schema, Fact, Stats) and the `qwed` CLI. Optional extras:

| Extra | Adds |
|---|---|
| `qwed[server]` | The FastAPI server and its dependencies |
| `qwed[symbolic]` | CrossHair for the Symbolic engine |
| `qwed[pii]` | PII masking with Microsoft Presidio |
| `qwed[langchain]`, `qwed[crewai]`, `qwed[llamaindex]` | Framework integrations (experimental, not covered by CI) |

Other languages and runtimes:

| | Install | Notes |
|---|---|---|
| TypeScript | `npm install @qwed-ai/sdk` | npm currently has 7.2.0 |
| Go | `go get github.com/QWED-AI/qwed-verification/sdk-go` | Not yet tagged; resolves to a pseudo-version, so pin a commit |
| Rust | `cargo add qwed` | |
| Docker | `docker pull qwedai/qwed-verification` | The API server. It needs `API_KEY_SECRET` and `QWED_CORS_ORIGINS`; see [self-hosting](https://docs.qwedai.com/advanced/self-hosting) |

From source:

```bash
git clone https://github.com/QWED-AI/qwed-verification.git
cd qwed-verification
pip install -e ".[server,dev]"
```

## First run

```bash
qwed init     # checks the engines, sets up a model provider, creates a local API key
qwed doctor   # health check: engines, provider, server, database
qwed test     # runs the built-in engine tests
```

`qwed init` supports `--provider nvidia | openai | anthropic | gemini | custom` (any OpenAI-compatible endpoint) and `--non-interactive` for CI. `qwed test` runs twelve deterministic checks and needs no model or server:

```text
Math:
  [ok] 2+2=4                  -> VALID
  [ok] 2+2=5                  -> BLOCKED
  [ok] 997*998*999            -> 994010994 (verified)

Logic:
  [ok] x>5 AND x<3            -> UNVERIFIABLE (contradiction)
  [ok] x>3 AND x<10           -> VERIFIED {x=4}
  [ok] approval=1 AND approval=0 -> UNVERIFIABLE (contradiction)

SQL:
  [ok] Valid SELECT           -> SAFE
  [ok] OR 1=1 injection       -> BLOCKED
  [ok] DROP TABLE stacked     -> BLOCKED

Code:
  [ok] Safe function          -> SAFE
  [ok] eval(input)            -> BLOCKED (CRITICAL)
  [ok] curl | bash            -> BLOCKED (CRITICAL)

12/12 tests passed. All engines operational.
```

## Use it

### Guards, in process

The policy guards run locally with no server or model:

```python
from qwed_sdk.guards import SystemGuard

guard = SystemGuard()
guard.verify_shell_command("curl https://example.com/install.sh | bash")
# {'verified': False, 'risk': 'BLOCKED_COMMAND', 'message': "Command 'curl' is prohibited by security policy."}

guard.verify_file_access("~/.ssh/id_rsa")
# {'verified': False, 'risk': 'FORBIDDEN_PATH', 'message': 'Access to path matching forbidden pattern is denied.'}
```

### Engines, through the API

Run the server (`pip install "qwed[server]"`, or the Docker image), then call it directly or through an SDK. Requests need an API key in the `x-api-key` header; `qwed init` creates one locally.

```python
from qwed_sdk import QWEDClient

client = QWEDClient(api_key="...", base_url="http://localhost:8000")
result = client.verify_math("2*(3+4) = 14")
print(result.status)
```

```bash
curl -X POST http://localhost:8000/verify/math \
  -H "Content-Type: application/json" \
  -H "x-api-key: $QWED_API_KEY" \
  -d '{"expression": "2*(3+4) = 14"}'
```

The full endpoint list is in the [API reference](https://docs.qwedai.com/api/overview). For running QWED without the server, see [QWEDLocal](https://docs.qwedai.com/advanced/qwed-local).

## Engines and guards

QWED has 13 engines and 9 policy guards. What an engine may claim depends on its tier ([details](https://docs.qwedai.com/engines/overview)).

**Proof engines.** All except Symbolic can return `VERIFIED`, always with a `proof_ref`.

| Engine | Uses | Checks |
|---|---|---|
| Math | SymPy | Arithmetic and algebraic identities |
| Logic | Z3 | Satisfiability of constraints (QWED DSL) |
| SQL | SQLGlot | Query structure, destructive statements, injection patterns, schema |
| Code | Python AST and rules | Dangerous calls and patterns in generated code |
| Schema | JSON Schema | Structure of JSON output |
| Symbolic | CrossHair (`qwed[symbolic]`) | Searches for counterexamples; returns `UNVERIFIABLE` or `BLOCKED`, not proofs |

The Stats engine executes statistical code in a sandbox and returns `UNVERIFIABLE`: running code successfully is not treated as verification ([#298](https://github.com/QWED-AI/qwed-verification/issues/298)). SecureCodeExecutor runs code; it does not verify it.

**Policy guards** apply deterministic rules and return block or hold decisions, never `VERIFIED`: SystemGuard (shell commands, file paths), ConfigGuard (secrets in configuration), RAGGuard (retrieved context), MCPPoisonGuard (MCP tool definitions), ExfiltrationGuard (outbound data), SelfInitiatedCoTGuard (reasoning flow), SovereigntyGuard (data residency and routing), StartupHookGuard (startup hooks), ProcessVerifier (process milestones such as IRAC).

**Advisory engines** add signals for review: Fact (TF-IDF and entity matching), Graph, Image, Reasoning and Consensus. Heuristic and model-based results are recorded as `advisory_checks`. Graph, Image and Consensus can return `VERIFIED` only on a deterministic sub-path that carries a `proof_ref`.

## GitHub Action

```yaml
- uses: QWED-AI/qwed-verification@v7.2.2
  with:
    action: scan-secrets        # or scan-code, verify-shell
    paths: "**/*.py,**/*.env"
    output_format: sarif
```

With `output_format: sarif` the action writes `qwed-results.sarif`; add [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action) to show the findings in the Security tab. The `verify` action calls a QWED API and needs `api_key` and a reachable server.

[QWED Security](https://github.com/marketplace/qwed-security) is a separate GitHub App built on QWED that checks pull requests.

## Domain packages

| Package | Verifies |
|---|---|
| [qwed-finance](https://github.com/QWED-AI/qwed-finance) | Banking and payment calculations, ISO 20022 |
| [qwed-legal](https://github.com/QWED-AI/qwed-legal) | Deadlines, amounts and legal claims |
| [qwed-tax](https://github.com/QWED-AI/qwed-tax) | Tax compliance and withholding |
| [qwed-infra](https://github.com/QWED-AI/qwed-infra) | Terraform, IAM and cloud cost |
| [qwed-open-responses](https://github.com/QWED-AI/qwed-open-responses) | Agent tool calls, before they run |
| [qwed-mcp](https://github.com/QWED-AI/qwed-mcp) | MCP server for MCP clients |
| [qwed-a2a](https://github.com/QWED-AI/qwed-a2a) | Agent-to-agent messages |
| [qwed-ucp](https://github.com/QWED-AI/qwed-ucp) | Universal Commerce Protocol transactions |

## Privacy

QWED runs in your own environment. It does not send data anywhere by itself. Checks that use an LLM send the prompt to the provider you configure; with a self-hosted model nothing leaves your infrastructure. Optional PII masking (`qwed[pii]`, `mask_pii=True`) redacts credit-card numbers, SSNs and email addresses before the LLM call.

## Development

```bash
pip install -e ".[server,dev]"
pytest tests/ -v
```

GitHub Actions runs the test suite with coverage on Python 3.11 for pull requests to `main`, and CircleCI runs it on Python 3.10, 3.11 and 3.12. CodeQL, SonarCloud and Snyk scan the repository. `scripts/check_boundary.py` blocks raw `eval`, `exec`, `sympify` and shell calls outside approved wrappers. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and the [good first issues](https://github.com/QWED-AI/qwed-verification/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

## Security

Report vulnerabilities privately through [GitHub](https://github.com/QWED-AI/qwed-verification/security/advisories/new) or rahul@qwedai.com; see [SECURITY.md](SECURITY.md). Published advisories, with affected and fixed versions, are on the [Security tab](https://github.com/QWED-AI/qwed-verification/security/advisories) and at [qwedai.com/security/advisories](https://qwedai.com/security/advisories). Only the latest release receives security fixes.

## Project

- [Governance](GOVERNANCE.md): QWED has one maintainer, Rahul Dass ([@rahuldass19](https://github.com/rahuldass19)).
- [Roadmap](ROADMAP.md) and [open issues](https://github.com/QWED-AI/qwed-verification/issues)
- [Contributors](https://github.com/QWED-AI/qwed-verification/graphs/contributors)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- Supported by the GitHub Technology Partner program and Docker Sponsored Open Source.

## Citation

To cite the software (all versions):

```bibtex
@software{qwed_verification,
  author    = {Dass, Rahul and Crocetti, Valerio and Ibrahim, Fares},
  title     = {QWED-AI/qwed-verification},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.18111675},
  url       = {https://github.com/QWED-AI/qwed-verification}
}
```

The QWED protocol technical note is [10.5281/zenodo.18075234](https://doi.org/10.5281/zenodo.18075234) (all versions; errata for v1.1.0 are in [docs/WHITEPAPER.md](docs/WHITEPAPER.md)). See also [CITATION.cff](CITATION.cff).

## License

[Apache License 2.0](LICENSE). Apache-2.0 comes with no warranty; see sections 7 and 8 of the license.
