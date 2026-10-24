# @qwed-ai/sdk

> TypeScript/JavaScript SDK for QWED Verification Protocol

[![npm version](https://img.shields.io/npm/v/@qwed-ai/sdk.svg)](https://www.npmjs.com/package/@qwed-ai/sdk)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)

## Installation

```bash
npm install @qwed-ai/sdk
# or
yarn add @qwed-ai/sdk
# or
pnpm add @qwed-ai/sdk
```

## Quick Start

```typescript
import { QWEDClient, isAdmitted } from '@qwed-ai/sdk';

const client = new QWEDClient({
  apiKey: 'qwed_your_api_key',
  baseUrl: 'http://localhost:8000', // optional
});

const result = await client.verifyMath('2 + 2 = 4');
console.log(result.status);       // 'VERIFIED'
console.log(result.admission);    // 'ADMIT'
console.log(isAdmitted(result));  // true
```

## Reading a result

Every verification returns the server's DiagnosticResult envelope:

| Field | Meaning |
|-------|---------|
| `status` | `VERIFIED`, `UNVERIFIABLE` or `BLOCKED` (`UNKNOWN` for a missing value or one this SDK does not know) |
| `rawStatus` | The server's status text exactly as sent, such as `SAT` where `status` is `UNKNOWN`; never used for admission |
| `admission` | `ADMIT` or `BLOCKED` where the endpoint decides (`UNKNOWN` for a value this SDK does not know); absent where it does not, as on `/verify/logic`, `/verify/fact` and batch logic and fact items |
| `proof_ref` | Set only when `status` is `VERIFIED` |
| `attestation` | The server's signed token on a `VERIFIED` answer (see [Attestations](#attestations)) |
| `agent_message`, `developer_fields`, `is_authoritative`, `constraint_id` | Explanation and detail |
| any other key | The endpoint's own fields, such as `is_valid`, `issues` or `error`. Numbers come from `JSON.parse`, so an integer above 2^53 or a long decimal is rounded |

**Gate on `isAdmitted(result)`, not on `status`.** `VERIFIED` means the engine reached a deterministic answer, not that the claim holds: `2 + 2 = 5` is `VERIFIED · BLOCKED` (proven false), and unsafe code is `VERIFIED · BLOCKED` (proven unsafe). `isAdmitted()` is true only for `ADMIT` together with `VERIFIED` and a `proof_ref`; a missing or unknown admission is never admitted.

`verified` and `isVerified()` are deprecated. The parser always sets `verified` to `isAdmitted(result)`, whatever the body says, and `isVerified()` returns `isAdmitted()`. Endpoints that make no admission decision (`/verify/logic`, `/verify/fact`, `/verify/rag`, `/verify/process`, and batch logic and fact items) are therefore never admitted. `/verify/rag` and `/verify/process` do send a top-level `verified`, which is their guard's own result; the parser replaces it, and the guard's value stays in `developer_fields.verified`. If you fetch responses yourself, pass the parsed JSON to `parseVerificationResponse()` or `parseBatchResponse()`.

## Verification Methods

### Natural Language

```typescript
const result = await client.verify('Is 15% of 200 equal to 30?');
```

### Math Expressions

```typescript
const result = await client.verifyMath('x**2 + 2*x + 1 = (x+1)**2');
console.log(isAdmitted(result)); // true for a true identity
console.log(result.is_valid);
```

### Logic (QWED-DSL)

```typescript
const result = await client.verifyLogic('(AND (GT x 5) (LT y 10))');
// /verify/logic makes no admission decision: admission is undefined and
// isAdmitted() is false, whatever the status.
console.log(result.status, result.admission);
```

### Code Security

```typescript
const result = await client.verifyCode(`
  import os
  os.system('rm -rf /')
`, { language: 'python' });

console.log(result.status, result.admission); // 'VERIFIED', 'BLOCKED'
console.log(isAdmitted(result));              // false
console.log(result.issues);                   // what was found
```

### Fact Verification

```typescript
const result = await client.verifyFact(
  'Paris is the capital of France',
  'France is a country in Europe. Its capital city is Paris.'
);
// A heuristic match is not a proof: UNVERIFIABLE, with no admission.
console.log(result.status);                // 'UNVERIFIABLE'
console.log(result.deterministic_verdict); // 'SUPPORTED'
```

### SQL Validation

```typescript
const result = await client.verifySQL(
  'SELECT * FROM users WHERE id = 1',
  'CREATE TABLE users (id INT PRIMARY KEY, name TEXT)',
  { dialect: 'postgresql' }
);
```

## Batch Verification

```typescript
const batch = await client.verifyBatch([
  { query: '2+2=4', type: VerificationType.Math },
  { query: '3*3=9', type: VerificationType.Math },
  { query: '(AND (GT x 5))', type: VerificationType.Logic },
]);

console.log(batch.job_id, batch.status); // job state, such as 'completed' or 'partial'
console.log(batch.completed_items, batch.failed_items, batch.total_items);
for (const item of batch.items) {
  // item.status is the item's state (`completed`, `failed`);
  // item.result is its verification answer.
  console.log(item.query, item.result?.status, isAdmitted(item.result));
}
```

## Attestations

Every `VERIFIED` answer carries `attestation`: an ES256 JWT the server signed
after checking the verdict (no request option is needed). Verifying it shows
the answer came from that server and was not changed:

```typescript
const result = await client.verifyMath('2 + 2 = 4');
if (result.attestation) {
  // Fetches the server's keys from /.well-known/jwks.json (cached for five
  // minutes) and checks the signature, issuer, expiry, a VERIFIED status,
  // and that the token is this answer's (its proof_hash is result.proof_ref).
  const claims = await client.verifyAttestation(result, '2 + 2 = 4');
  console.log(claims.exp); // when the token expires
}
```

To verify offline, or against keys you pinned, call
`verifyAttestation(token, jwks, { proofRef, query })` with the JWKS you
hold. A failure throws `AttestationError`. A token says the server reached
the verdict; whether to act on it is still `isAdmitted(result)`.
`parseAttestation` only decodes a token, without checking it.

## Agent Verification

```typescript
// Register an agent
const agent = await client.registerAgent({
  agent: {
    name: 'CustomerBot',
    type: 'supervised',
    principal_id: 'org_123',
  },
  permissions: {
    allowed_engines: [VerificationType.SQL, VerificationType.Math],
    allowed_tools: ['database_read'],
  },
  budget: {
    max_daily_cost_usd: 50,
  },
});

// Verify agent action
const decision = await client.verifyAgentAction({
  agent_id: agent.agent_id,
  agent_token: agent.agent_token,
  action: {
    type: 'execute_sql',
    query: 'SELECT * FROM customers',
  },
});

if (decision.decision === 'APPROVED') {
  // Safe to execute
}
```

## Error Handling

```typescript
import { QWEDClient, QWEDError, QWEDAuthError, QWEDRateLimitError } from '@qwed-ai/sdk';

try {
  const result = await client.verify('test');
} catch (error) {
  if (error instanceof QWEDAuthError) {
    console.error('Invalid API key');
  } else if (error instanceof QWEDRateLimitError) {
    console.error(`Rate limited. Retry after ${error.retryAfter}s`);
  } else if (error instanceof QWEDError) {
    console.error(`Error ${error.code}: ${error.message}`);
  }
}
```

## Types

All types are exported and fully documented:

```typescript
import {
  VerificationType,
  VerificationStatus,
  Admission,
  VerificationResponse,
  BatchResponse,
  BatchItemResult,
  AgentVerificationResponse,
  // ... and more
} from '@qwed-ai/sdk';
```

## Configuration

```typescript
const client = new QWEDClient({
  apiKey: 'qwed_...',          // Required
  baseUrl: 'http://localhost:8000', // Optional, your local QWED server (the default)
  timeout: 30000,              // Optional, default: 30000ms
  headers: {                   // Optional custom headers
    'X-Custom-Header': 'value',
  },
});
```

## Building from source

Working on the SDK itself needs Node 24. The dev toolchain declares
`eslint` 10 (`^20.19.0 || ^22.13.0 || >=24`) and `vitest` 5
(`^22.12.0 || ^24.0.0 || >=26.0.0`, peer `@types/node ^22 || >=24`):
Node 24 satisfies both, and matches CI (`sdk-tests.yml`) and
`@types/node ^24`. Node 21, Node 23, and Node 25 are outside the
vitest range, so they are not supported for development.

That is a build-tooling floor, not a runtime one. The published package keeps
`engines.node: ">=18.0.0"`, because the APIs this client uses (`fetch`,
`AbortController`, `atob`) are present in Node 18.0.0 and consumers install
nothing from `devDependencies`. Raising `engines.node` to match the lint
toolchain would reject real Node 18 users for a constraint that cannot affect
them.

```bash
npm ci
npm run typecheck   # tsc --noEmit for src/, then src/ and tests/ together
npm run lint        # eslint src tests
npx vitest run      # contract and client tests
npm run build       # tsup -> dist/ (cjs + esm + .d.ts)
```

The contract tests in `tests/contract.test.ts` parse responses captured from
the server, stored in `sdk-fixtures/` at the repository root. The Go and Rust
SDKs parse the same files, and `tests/test_issue_468_rust_sdk_contract.py`
fails if the server's answers drift from them.

## License

Apache 2.0

