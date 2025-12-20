---
sidebar_position: 1
---

# SDKs Overview

QWED provides official SDKs for 4 languages.

## Available SDKs

| Language | Package | Status |
|----------|---------|--------|
| [Python](/docs/sdks/python) | `qwed-new` | ✅ Stable |
| [TypeScript](/docs/sdks/typescript) | `@qwed-ai/sdk` | ✅ Stable |
| [Go](/docs/sdks/go) | `github.com/qwed-ai/qwed-go` | ✅ Stable |
| [Rust](/docs/sdks/rust) | `qwed` | ✅ Stable |

## Feature Comparison

| Feature | Python | TypeScript | Go | Rust |
|---------|--------|------------|---------|------|
| Sync Client | ✅ | ✅ | ✅ | ✅ |
| Async Client | ✅ | ✅ | ✅ | ✅ |
| Batch Operations | ✅ | ✅ | ✅ | ✅ |
| Agent API | ✅ | ✅ | ❌ | ❌ |
| Attestations | ✅ | ✅ | ✅ | ✅ |
| CLI | ✅ | ❌ | ❌ | ❌ |

## Quick Install

```bash
# Python
pip install qwed-new

# TypeScript
npm install @qwed-ai/sdk

# Go
go get github.com/qwed-ai/qwed-go

# Rust
cargo add qwed
```

## Minimal Example

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
<TabItem value="python" label="Python">

```python
from qwed_sdk import QWEDClient

client = QWEDClient(api_key="qwed_...")
result = client.verify("2+2=4")
print(result.verified)  # True
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import { QWEDClient } from '@qwed-ai/sdk';

const client = new QWEDClient({ apiKey: 'qwed_...' });
const result = await client.verify('2+2=4');
console.log(result.verified);  // true
```

</TabItem>
<TabItem value="go" label="Go">

```go
client := qwed.NewClient("qwed_...")
result, _ := client.Verify(ctx, "2+2=4")
fmt.Println(result.Verified)  // true
```

</TabItem>
<TabItem value="rust" label="Rust">

```rust
let client = QWEDClient::new("qwed_...");
let result = client.verify("2+2=4").await?;
println!("{}", result.verified);  // true
```

</TabItem>
</Tabs>
