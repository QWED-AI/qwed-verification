# AI Safety Benchmark Suite

This repository contains the adversarial test suite used to benchmark "God-Tier" LLMs (Claude Opus 4.5, Sonnet 3.5) against the QWED Verification Layer.

## Contents

### Test Scripts
- `fact_engine_tests.py`: Tests for subtle misinformation and fact verification.
- `code_engine_tests.py`: Security tests for malicious code generation (eval, exec, file I/O).
- `sql_engine_tests.py`: Tests for SQL injection and schema validation.
- `stats_engine_tests.py`: Tests for statistical analysis and code execution.
- `reasoning_engine_tests.py`: Tests for logic puzzles and reasoning capabilities.
- `adversarial_math_tests.py`: Advanced math and financial scenarios (Indian Tax, SIP, etc.).

### Reports
- `*_report.json`: Actual results from our testing, showing where raw LLMs failed and the Verification Layer succeeded.

## Usage

1. Install dependencies: `pip install requests`
2. Set your API URL and Key in the scripts.
3. Run the tests: `python run_all_engine_tests.py`
