# QWED Python SDK

Official Python client for the QWED Verification Protocol.

## Installation

```bash
pip install qwed
```

## Quick Start

```python
from qwed import QwedClient

# Initialize client
client = QwedClient(api_key="qwed_your_key")

# Verify a math expression
result = client.verify_math("2 + 2 = 4")
print(result.verified)  # True

# Verify logic
result = client.verify_logic("(AND (GT x 5) (LT x 10))")
print(result.status)  # "SAT"
print(result.model)   # {"x": 6}
```

## API Reference

### QwedClient

```python
client = QwedClient(
    api_key="qwed_your_key",
    base_url="https://api.qwedai.com"  # Optional
)
```

### Methods

| Method | Description |
|--------|-------------|
| `verify_math(expr)` | Verify mathematical expressions |
| `verify_logic(expr)` | Verify logic constraints (DSL) |
| `verify_code(code, lang)` | Check code for vulnerabilities |
| `verify_sql(query)` | Validate SQL queries |

## Documentation

Full documentation: https://docs.qwedai.com/docs/sdks/python

## License

Apache-2.0
