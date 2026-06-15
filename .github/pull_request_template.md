## QWED Enforcement Checklist

- [ ] Verification before execution — no path bypasses verification
- [ ] Fail closed — all failure paths block, not degrade
- [ ] Approved paths only — no bare `eval` / `exec` / `parse_expr`
- [ ] No silent degradation — no suppressed errors or bypass-oriented retries
- [ ] No trust in LLM output — claims verified by deterministic computation
- [ ] Vulnerability family thinking — similar bypass patterns considered
- [ ] Existing issues not regressed — severity of unfixed issues unchanged

## Summary

Describe the intent of the change and the verification boundary it touches.

## Validation

List the checks, tests, or scans used to validate this PR.

## Notes

If this change affects enforcement behavior, explain why it is still compliant
with [QWED_RULES.md](../QWED_RULES.md).
