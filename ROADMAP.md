# QWED Roadmap

What is being worked on, grouped by priority rather than by date. Every item links to the issue where progress is tracked; the issues are the source of truth.

## Now: verification correctness and security hardening

- [Verification correctness and engine hardening](https://github.com/QWED-AI/qwed-verification/issues/433) (tracker)
- [External audit remediation](https://github.com/QWED-AI/qwed-verification/issues/342) (tracker) and [source-only audit, run 2](https://github.com/QWED-AI/qwed-verification/issues/394) (tracker)
- [Fail-closed boundaries across execution, graph, reasoning and logic engines](https://github.com/QWED-AI/qwed-verification/issues/167) (tracker)
- Attestations on every authoritative `VERIFIED` result: [#319](https://github.com/QWED-AI/qwed-verification/issues/319), [#320](https://github.com/QWED-AI/qwed-verification/issues/320)
- SDK paths that still return two-state results: [#326](https://github.com/QWED-AI/qwed-verification/issues/326), [#327](https://github.com/QWED-AI/qwed-verification/issues/327)

## Next: engines

- Deterministic statistical claims for the Stats engine: [#298](https://github.com/QWED-AI/qwed-verification/issues/298), [#299](https://github.com/QWED-AI/qwed-verification/issues/299)
- CrossHair inside the secure sandbox: [#431](https://github.com/QWED-AI/qwed-verification/issues/431)
- DSL operators with no Z3 implementation (IFF, FORALL, EXISTS): [#428](https://github.com/QWED-AI/qwed-verification/issues/428)
- Bounded model checking for loops: [#16](https://github.com/QWED-AI/qwed-verification/issues/16)

## Later: protocol

- Verification Context v1.1: attempt identity and retry provenance ([#381](https://github.com/QWED-AI/qwed-verification/issues/381), tracker [#385](https://github.com/QWED-AI/qwed-verification/issues/385))
- Execution-outcome feedback for agents: [#382](https://github.com/QWED-AI/qwed-verification/issues/382)

## Done

Release history is in [CHANGELOG.md](CHANGELOG.md) and on [GitHub Releases](https://github.com/QWED-AI/qwed-verification/releases). Recent milestones:

- `DiagnosticResult` on every engine API endpoint (v7.0.0)
- Verification Context v1.0 (v7.1.0)
- Security and soundness fixes (v7.2.0 to v7.2.2)
- OpenSSF Best Practices: Gold
- SDKs for TypeScript, Go and Rust

## Get involved

- Suggest features or report bugs in [Issues](https://github.com/QWED-AI/qwed-verification/issues)
- Discuss ideas in [Discussions](https://github.com/QWED-AI/qwed-verification/discussions)
