# QWED Complete Testing Protocol - Implementation Checklist

## Phase 1: Core Test Infrastructure (Days 1-3)
- [ ] Day 1: Build test runner framework (`run_complete_audit.py`)
  - [ ] Base test class with API client
  - [ ] Retry logic and error handling
  - [ ] Priority-based execution (CRITICAL/HIGH/MEDIUM)
- [ ] Day 2: Implement report generation
  - [ ] JSON reporter (machine-readable)
  - [ ] Markdown reporter (human-readable)
  - [ ] HTML dashboard (basic)
- [ ] Day 3: Setup config and fixtures
  - [ ] Create `config.yaml` for centralized settings
  - [ ] Setup pytest fixtures in `conftest.py`
  - [ ] Test data cleanup utilities

## Phase 2: Test Validated Engines (Days 4-6)
- [ ] Day 4: Code Engine Test Suite
  - [ ] Context-aware detection tests
  - [ ] AST edge cases
  - [ ] Crypto misuse tests
  - [ ] **Target: 90%+ pass rate**
- [ ] Day 5: Math Engine Test Suite
  - [ ] Expression ambiguity tests
  - [ ] Symbolic simplification tests
  - [ ] Domain restriction tests
  - [ ] Document gaps found
- [ ] Day 6: Logic Engine Test Suite
  - [ ] Schema validation tests
  - [ ] Z3 edge cases
  - [ ] Quantifier handling tests
  - [ ] Fix schema bugs discovered

## Phase 3: Test New Engines (Days 7-11)
- [ ] Day 7: Stats Engine Test Suite
  - [ ] Docker isolation validation
  - [ ] Pandas/NumPy security (DataFrame.eval)
  - [ ] Statistical correctness tests
  - [ ] Memory leak detection
- [ ] Day 8: SQL Engine Test Suite
  - [ ] SQL injection tests (UNION, blind, time-based)
  - [ ] Schema validation edge cases
  - [ ] NoSQL injection patterns
  - [ ] Query complexity limits
- [ ] Day 9: Fact Engine Test Suite
  - [ ] Knowledge cutoff detection (2023+)
  - [ ] Hallucination classification
  - [ ] Contradictory claims detection
  - [ ] Source citation validation
- [ ] Days 10-11: Image Engine Test Suite
  - [ ] OCR accuracy on adversarial images
  - [ ] Claim-image alignment tests
  - [ ] Image manipulation detection
  - [ ] Steganography detection

## Phase 4: Integration & Stress (Days 12-14)
- [ ] Day 12: Cross-Engine Integration Tests
  - [ ] Code + Math hybrid scenarios
  - [ ] Logic + Code hybrid scenarios
  - [ ] Multi-engine validation flows
- [ ] Day 13: Stress Tests
  - [ ] 10,000 line file handling
  - [ ] 100 concurrent request tests
  - [ ] Complex nested structure tests
  - [ ] Timeout handling validation
- [ ] Day 14: Malformed Input Tests
  - [ ] Empty string handling
  - [ ] Binary data rejection
  - [ ] Unicode edge cases
  - [ ] Null byte and mixed line ending tests

## Phase 5: Analysis & Hardening (Days 15-20)
- [ ] Days 15-17: Fix Critical Failures
  - [ ] Address all CRITICAL test failures
  - [ ] Fix top 10 issues
  - [ ] Re-run affected test suites
  - [ ] Verify no regressions
- [ ] Days 18-19: Fix High Priority Failures
  - [ ] Address HIGH priority issues
  - [ ] Focus on engines with <80% pass rate
  - [ ] Document design decisions
- [ ] Day 20: Final Audit & Documentation
  - [ ] Run complete test suite
  - [ ] Generate comprehensive report
  - [ ] Document per-engine pass rates
  - [ ] Create roadmap for remaining gaps

## Success Metrics (By Day 20)
- [ ] Code Engine: 95%+ pass rate
- [ ] Math Engine: 85%+ pass rate
- [ ] Logic Engine: 85%+ pass rate
- [ ] Stats Engine: 80%+ pass rate
- [ ] SQL Engine: 90%+ pass rate
- [ ] Fact Engine: 75%+ pass rate
- [ ] Image Engine: 70%+ pass rate
- [ ] 100% CRITICAL tests passing
- [ ] 90%+ HIGH priority tests passing
- [ ] No crashes on malformed input
- [ ] <30 second timeout for all operations
- [ ] Handles 100 concurrent requests
