# QWED Verification Examples

This directory contains working examples of how to use the QWED SDK for various verification tasks.

## Setup

First, install the SDK:
```bash
pip install qwed
```

Ensure the QWED server is running (e.g., via `docker-compose up` or `uvicorn qwed_new.api.main:app`).

## Examples

| File | Description |
|------|-------------|
| [math_example.py](math_example.py) | Mathematical verification (symbolic & natural language) |
| [logic_example.py](logic_example.py) | Logic puzzles and constraint solving (Z3) |
| [code_security_example.py](code_security_example.py) | Detecting vulnerabilities in code |
| [sql_safety_example.py](sql_safety_example.py) | Verifying SQL queries against schema |
| [fact_verification_example.py](fact_verification_example.py) | Checking factual claims against context |
| [stats_example.py](stats_example.py) | Verifying statistical claims on CSV data |
| [consensus_example.py](consensus_example.py) | Multi-engine consensus, advisory only (never `VERIFIED`) |
| [image_verification_example.py](image_verification_example.py) | Image analysis and claim verification |
| [batch_verification_example.py](batch_verification_example.py) | Processing multiple requests efficiently |

## Running Examples

Each script is standalone. You may need to set your API key if you have authentication enabled.

```bash
python math_example.py
```

