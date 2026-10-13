# Soundness eval

Claims with a known answer, run through QWED's proof engines. It measures the
one failure a verifier must not have: **accepting a claim that does not hold**.

```bash
pip install -e .
python -m evals.run          # summary
python -m evals.run --json   # also writes eval-results.json
```

No model, network or database is involved: the runner calls the engines
through the library API (`VerificationEngine`, `LogicVerifier`, `SQLVerifier`,
`CodeVerifier`, `SchemaVerifier`), the same classes the SDK, CLI and API use.

## What each result means

Every case says whether its claim **holds** (`true` or `false`). The engine's
answer is **accepted** when it returns `VERIFIED` and does not mark the result
invalid (`developer_fields.is_valid` is not `false`). For SQL, code and schema
checks that is the same as `admission_decision(...)` returning `ADMIT`.
`UNVERIFIABLE` and `BLOCKED` never accept.

| Claim | Accepted | Not accepted |
|---|---|---|
| holds | proved | not proved (fail-closed, safe but incomplete) |
| does not hold | **false accept** (a soundness failure) | caught |

`false_accept` must be zero. `tests/test_evals.py` runs every case in CI and
fails the build otherwise. An engine that raises is an `error`, never `caught`,
and fails the build too. "Not proved" is allowed: QWED fails closed, so a
true claim it cannot prove is held, not passed. The report shows how many.

## The report

`python -m evals.run --json` writes `eval-results.json` with:

- `qwed_version`, `commit`, `python`, `generated_at` and the `command` that made it
- `totals` and `by_engine`: cases, how many hold, proved, not proved, caught, false accepts, errors
- `statuses`: how many `VERIFIED`, `UNVERIFIABLE` and `BLOCKED` results came back
- `cases`: every claim with its status and outcome

`.github/workflows/eval.yml` runs it on every release and attaches
`eval-results.json` to the GitHub release.

## Adding a case

Add an object to the file for its engine in `cases/`:

```json
{
  "id": "math-012",
  "check": "math.verify_math",
  "claim": "2 ** 64 is 18446744073709551615",
  "input": {"expression": "2**64", "claimed": 18446744073709551615},
  "holds": false,
  "source": "GHSA-j622-qffp-rc27"
}
```

- `check` is one of the engine calls in `run.py` (`_engines`).
- `holds` is the true answer, worked out independently of QWED.
- `source` names the advisory or issue a case comes from, when there is one.
- Changing the `holds` of an existing case needs its reason in the pull
  request: flipping an answer is the one way to hide a false accept.

Every advisory that showed a false `VERIFIED` in these engines has its
reproduction here, so the bug stays fixed. When a false accept is found,
report it privately first (see SECURITY.md), then add its case with the fix.

## What this does not measure

- The translation from natural language to a formal statement, which uses a
  model and is not verified.
- Advisory engines (Fact, Graph, Image, Reasoning, Consensus) and Stats,
  which never return `VERIFIED` for heuristic results.
- Domain packages (qwed-finance, qwed-legal, qwed-tax and others), which
  will get their own cases.
- How often a model is right. See `benchmarks/README.md` for that data and its
  limits.
