# ADR-003: Truth vs Admission

**Status:** Accepted
**Decided:** via adversarial architecture review (category-level)

## Context

A naive design conflates two very different claims:

- **Truth** — "the claim was checked and this is the proven outcome."
- **Admission** — "this artifact is safe/permitted to run or ship."

Conflating them produces dangerous outcomes: treating `VERIFIED` as "safe to
execute" admits unsafe code, and treating "unsafe" as "not verified" hides the fact
that the danger was *proven*.

## Decision

> **`VERIFIED` is a *truth* guarantee, not an *admission* guarantee.**
>
> **Admission is a separate decision.**

- `VERIFIED` means *"the object was checked and this is the proven result."* It says
  nothing about whether the artifact should be run or shipped.
- **Admission** is computed separately from the verdict plus policy. It is the
  safe-to-run / safe-to-ship decision.

## VERIFIED-as-unsafe

A proven-unsafe artifact is **`VERIFIED`** (we *proved* it is unsafe) with
**admission DENIED**. This is the critical case that a conflated model gets wrong:

- Truth: `VERIFIED` — the analysis is complete and proven; `is_valid = false`.
- Admission: `DENIED` — do not execute/ship.

Consumers that admit on `status == "VERIFIED"` alone would admit unsafe code; they
must gate on `admission == "ADMIT"`. `is_valid` contributes to the admission
decision but is **not** an alternative authorization gate — a valid statement can
still be denied by policy, so execution and shipping gate exclusively on admission.

## Mapping

| Verdict | Truth | Admission (typical) |
|---------|-------|---------------------|
| `VERIFIED`, valid | proven safe | ADMIT |
| `VERIFIED`, unsafe | proven unsafe | **DENY** |
| `UNVERIFIABLE` | not proven | DENY (fail-closed) |
| `BLOCKED` | verification failed | DENY (fail-closed) |

## Rejected alternatives

- **`VERIFIED` ⇒ safe to run.** Admits proven-unsafe code.
- **"unsafe" ⇒ `BLOCKED` / not verified.** Hides that the danger was proven; loses
  the truth guarantee.

## Consequences

- Truth and admission are independently legible.
- Proven-unsafe code is both *known* (VERIFIED) and *stopped* (admission DENIED).
- Fail-closed: `UNVERIFIABLE` and `BLOCKED` never admit.
