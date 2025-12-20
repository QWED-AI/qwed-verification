---
sidebar_position: 1
---

# Installation

Get QWED up and running in minutes.

## Python SDK

```bash
pip install qwed-new
```

### Requirements
- Python 3.10+
- Optional: Redis (for caching)

## TypeScript SDK

```bash
npm install @qwed-ai/sdk
# or
yarn add @qwed-ai/sdk
# or
pnpm add @qwed-ai/sdk
```

## Go SDK

```bash
go get github.com/qwed-ai/qwed-go
```

## Rust SDK

```toml
# Cargo.toml
[dependencies]
qwed = "1.0"
```

---

## Full Stack (Self-Hosted)

For running the complete QWED stack locally:

```bash
# Clone the repository
git clone https://github.com/QWED-AI/qwed-verification.git
cd qwed-verification

# Start infrastructure (Redis, Prometheus, Grafana, Jaeger)
docker-compose up -d

# Install dependencies
pip install -e .

# Run the API
python -m uvicorn qwed_new.api.main:app --reload
```

### Infrastructure URLs

| Service | URL |
|---------|-----|
| API | http://localhost:8000 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Jaeger | http://localhost:16686 |

---

## qwed-core (Minimal)

For embedding verification in your application without external dependencies:

```bash
pip install qwed-core
```

Or run as Docker:

```bash
docker run -p 8080:8080 qwed/qwed-core
```

## Next Steps

- [Quick Start Guide](/docs/getting-started/quickstart)
- [Core Concepts](/docs/getting-started/concepts)
