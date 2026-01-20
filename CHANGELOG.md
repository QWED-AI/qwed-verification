# Changelog

All notable changes to the QWED Protocol will be documented in this file.

## [2.4.0] - 2026-01-20
### 🚀 The Reasoning Engine & Enterprise Docker Support

#### New Features
- **Optimization Engine (`verify_optimization`)**: Added `LogicVerifier` support for Z3's `Optimize` context, enabling "Profit Maximization" queries (e.g., maximize loan amount subject to risk constraints).
- **Vacuity Checker (`check_vacuity`)**: Added logical proof to detect "Vacuous Truths" (e.g., rules that trigger on impossible conditions like `year < 1900`).

#### Enterprise Updates
- **Dockerized GitHub Action**: The main `qwed-verification` action now runs in a Docker container (Python 3.11-slim) instead of a composite script. This ensures Z3 and SymPy run consistently in all CI environments.
- **Environment Parity**: Aligned `Dockerfile` dependencies with PyPI release.

#### Fixes & Improvements
- Updated `logic_verifier.py` with additive, non-breaking methods.
- Replaced shell-based `action_entrypoint.sh` with robust Python handler `action_entrypoint.py`.
