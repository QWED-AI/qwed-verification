# SDK contract fixtures

Responses captured from the QWED server (FastAPI `TestClient`) for the
requests the SDKs send. The Rust (`sdk-rust/tests/contract.rs`), Go
(`sdk-go/contract_test.go`) and TypeScript (`sdk-ts/tests/contract.test.ts`)
contract tests parse them, and `tests/test_issue_468_rust_sdk_contract.py`
fails if the server's answers to the deterministic requests drift from them.

| File | Request | `status` · `admission` |
|------|---------|------------------------|
| `math_verified.json` | `/verify/math` `2 + 2 = 4` | `VERIFIED · ADMIT` |
| `math_false.json` | `/verify/math` `2 + 2 = 5` | `VERIFIED · BLOCKED` |
| `math_ambiguous.json` | `/verify/math` `1/2(3+1)` | `BLOCKED · BLOCKED` |
| `code_safe.json` | `/verify/code` `x = 1 + 1` | `VERIFIED · ADMIT` |
| `code_unsafe.json` | `/verify/code`, Python code with a shell call | `VERIFIED · BLOCKED` |
| `sql.json` | `/verify/sql` `SELECT id FROM users` | `VERIFIED · ADMIT` |
| `natural_language.json` | `/verify/natural_language`, no provider | `UNVERIFIABLE · BLOCKED` |
| `logic.json` | `/verify/logic`, no provider | `BLOCKED`, no admission |
| `fact.json` | `/verify/fact` | `UNVERIFIABLE`, no admission |
| `batch.json` | `/verify/batch`, two math items | job `completed`; items `VERIFIED` and `UNVERIFIABLE`, no admission |

The natural-language, logic and fact answers depend on the configured LLM
provider, so the Python test checks only their envelope rules.
