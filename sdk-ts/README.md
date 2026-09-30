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
import { QWEDClient } from '@qwed-ai/sdk';

const client = new QWEDClient({
  apiKey: 'qwed_your_api_key',
  baseUrl: 'http://localhost:8000', // optional
});

// Verify a math query
const result = await client.verify('What is 2+2?');
console.log(result.verified); // true
console.log(result.status);   // 'VERIFIED'
```

## Verification Methods

### Natural Language

```typescript
const result = await client.verify('Is 15% of 200 equal to 30?');
```

### Math Expressions

```typescript
const result = await client.verifyMath('x**2 + 2*x + 1 = (x+1)**2');
console.log(result.result?.is_valid); // true
```

### Logic (QWED-DSL)

```typescript
const result = await client.verifyLogic('(AND (GT x 5) (LT y 10))');
console.log(result.result?.satisfiability); // 'SAT'
console.log(result.result?.model);          // { x: 6, y: 9 }
```

### Code Security

```typescript
const result = await client.verifyCode(`
  import os
  os.system('rm -rf /')
`, { language: 'python' });

console.log(result.verified); // false
console.log(result.result?.vulnerabilities);
```

### Fact Verification

```typescript
const result = await client.verifyFact(
  'Paris is the capital of France',
  'France is a country in Europe. Its capital city is Paris.'
);
console.log(result.result?.verdict); // 'SUPPORTED'
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
const result = await client.verifyBatch([
  { query: '2+2=4', type: VerificationType.Math },
  { query: '3*3=9', type: VerificationType.Math },
  { query: '(AND (GT x 5))', type: VerificationType.Logic },
]);

console.log(result.summary.success_rate); // 100
console.log(result.items);                // individual results
```

## Attestations

Request cryptographic proof of verification:

```typescript
const result = await client.verify('2+2=4', {
  includeAttestation: true,
});

if (result.attestation) {
  const parsed = parseAttestation(result.attestation);
  console.log(parsed?.payload.qwed.result.status); // 'VERIFIED'
}
```

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
  VerificationResponse,
  BatchResponse,
  AgentVerificationResponse,
  // ... and more
} from '@qwed-ai/sdk';
```

## Configuration

```typescript
const client = new QWEDClient({
  apiKey: 'qwed_...',          // Required
  baseUrl: 'https://api.qwed.ai', // Optional, default: localhost:8000
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
npm run typecheck   # tsc --noEmit, covers every file under src/
npm run lint        # eslint src
npm run build       # tsup -> dist/ (cjs + esm + .d.ts)
```

## License

Apache 2.0

