# Benchmarks

This folder holds two kinds of data. Please read what each one measures before quoting it.

## Model answer accuracy (December 2025)

`*_benchmark_results.json`, produced by `scripts/benchmark_*.py` on 2025-12-22.

These record how often **Claude Opus 4.5** (as recorded in five of the seven files) answered 215 hand-written questions the same way as a hand-written reference answer:

| Suite | Correct |
|---|---|
| math | 25/25 |
| logic | 15/15 |
| finance | 11/15 |
| adversarial | 34/40 |
| hard | 32/40 |
| code | 37/40 |
| legal | 39/40 |
| **total** | **193/215** |

**What these numbers do not measure.** QWED's engines were not run on the model's answers. In the scripts, an error counts as "caught" whenever the model's answer differs from the reference answer: the same branch that increments `wrong` also increments `qwed_caught` (`scripts/benchmark_adversarial.py` lines 228-229, `scripts/benchmark_finance.py` lines 266-267). The `qwed_caught` fields therefore restate the model's error count; they are not a QWED detection rate. Earlier versions of the README and whitepaper described them as "100% error detection", which was wrong.

A benchmark that runs QWED's engines on model output, and reports the verdict distribution (`VERIFIED` / `UNVERIFIABLE` / `BLOCKED`) including false `VERIFIED` results, has not been published yet.

Note: the scripts evaluate model-generated expressions without a sandbox; see [#418](https://github.com/QWED-AI/qwed-verification/issues/418) before running them.

## Engine performance and limits

- `PERFORMANCE_REPORT.md` and `performance_results_*.json`: engine-only latency measured with `performance_profiler.py` (January 2026). They exclude LLM calls.
- `CROSSHAIR_LIMITS.md` and `crosshair_limits_benchmark.py`: where CrossHair's symbolic execution stops being useful.
- `UNREADABLE_CODE_BENCHMARK.md` and `unreadable_code_*`: obfuscated-code detection experiments.
