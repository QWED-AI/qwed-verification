# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-12-20

### Added
- Math Engine: Calculus, Matrix operations, Finance (NPV/IRR), Statistics
- Logic Engine: ForAll/Exists quantifiers, BitVectors, Array theory
- Code Engine: JavaScript, Java, Go language support (was Python only)
- SQL Engine: Complexity limits, Cost estimation, Enhanced injection detection
- Fact Engine: TF-IDF semantic similarity, Entity matching, Citation extraction
- Image Engine: Deterministic metadata verification, VLM consensus fallback
- Reasoning Engine: Multi-provider support (Anthropic, Azure, OpenAI), Result caching
- Consensus Engine: Async parallel execution, Circuit breaker pattern
- Stats Engine: Wasm sandbox, Docker fallback, AST validation

### Changed
- All engines now follow "deterministic-first" philosophy
- Improved claim classification in Image verifier

### Fixed
- Image verifier size claim regex patterns
- SQL test assertions for dict-based response format

### Security
- No changes listed.

## [1.0.0] - 2024-11-15

### Added
- Initial release with 8 verification engines
- Python SDK
- FastAPI REST API
- Multi-tenancy with API key authentication
- Rate limiting

