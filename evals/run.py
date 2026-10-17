"""Soundness evaluation: run QWED's proof engines on claims with a known answer.

    python -m evals.run           # print a summary
    python -m evals.run --json    # also write eval-results.json here

Every case in ``evals/cases/*.json`` is a claim with a known answer
(``holds``: true or false) and the engine call that checks it. The runner
calls the engine directly, through the library API, with no model, network or
database, and records what came back. The number that matters is
``false_accepts``: claims that do not hold but that QWED accepted. It must be
zero; ``tests/test_evals.py`` fails the build otherwise. An engine that raises
counts as an error, never as caught, and also fails the run.

"Accepted" means the engine said the claim holds: a ``VERIFIED`` result that
is not marked invalid (``developer_fields.is_valid`` is not ``False``). For
SQL, code and schema checks that is the same as ``admission_decision`` returning
``ADMIT``. Fail-closed results (``UNVERIFIABLE``, ``BLOCKED``) never accept.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "cases"
SCHEMA = "qwed-eval/1"
REPORT = "eval-results.json"

# What a result means for the claim, by (holds, accepted).
OUTCOMES = {
    (True, True): "proved",
    (True, False): "not_proved",
    (False, False): "caught",
    (False, True): "false_accept",
}


def _diagnostic(result: Any) -> Tuple[str, bool, Dict[str, Any]]:
    """Status, accepted and developer fields from a DiagnosticResult."""
    status = result.status.value
    fields = dict(result.developer_fields or {})
    accepted = status == "VERIFIED" and fields.get("is_valid", True) is not False
    return status, accepted, fields


def _legacy(result: Dict[str, Any], engine: str) -> Tuple[str, bool, Dict[str, Any]]:
    """Status and accepted from a legacy engine dict (math engine)."""
    from qwed_new.core.diagnostics import DiagnosticResult

    if result.get("status") == "VERIFIED":
        return "VERIFIED", bool(result.get("is_correct", result.get("is_equivalent", True))), result
    # A counter-proof is a decided verdict: VERIFIED, never accepted (#437).
    if result.get("status") == "DISPROVEN":
        return "VERIFIED", False, result
    status = DiagnosticResult.from_legacy_dict(result, engine=engine).status.value
    return status, False, result


def _engines() -> Dict[str, Callable[[Dict[str, Any]], Tuple[str, bool, Dict[str, Any]]]]:
    from qwed_new.core.code_verifier import CodeVerifier
    from qwed_new.core.logic_verifier import LogicVerifier
    from qwed_new.core.schema_verifier import SchemaVerifier
    from qwed_new.core.sql_verifier import SQLVerifier
    from qwed_new.core.verifier import VerificationEngine

    math, logic, sql, code, schema = VerificationEngine(), LogicVerifier(), SQLVerifier(), CodeVerifier(), SchemaVerifier()
    return {
        "math.verify_math": lambda i: _legacy(math.verify_math(i["expression"], i["claimed"]), "math"),
        "math.verify_identity": lambda i: _legacy(math.verify_identity(i["lhs"], i["rhs"]), "math"),
        "logic.prove_theorem": lambda i: _diagnostic(logic.prove_theorem(i["variables"], i["premises"], i["conclusion"])),
        "logic.check_equivalence": lambda i: _diagnostic(logic.check_equivalence(i["variables"], i["formula1"], i["formula2"])),
        "sql.verify_sql": lambda i: _diagnostic(sql.verify_sql(i["query"], i.get("schema_ddl"), i.get("dialect", "postgres"))),
        "code.verify_code": lambda i: _diagnostic(code.verify_code(i["code"], i.get("language", "python"))),
        "schema.verify": lambda i: _diagnostic(schema.verify(i["data"], i["schema"])),
    }


def load_cases() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for path in sorted(CASES.glob("*.json")):
        for case in json.loads(path.read_text(encoding="utf-8")):
            case.setdefault("file", path.name)
            cases.append(case)
    ids = [c["id"] for c in cases]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate case ids: {duplicates}")
    return cases


def run(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    engines = _engines()
    rows = []
    for case in cases:
        check = case["check"]
        if check not in engines:
            raise ValueError(f"{case['id']}: unknown check {check!r}")
        try:
            status, accepted, fields = engines[check](case["input"])
            error = None
        except Exception as exc:  # an engine that raises has not accepted anything
            status, accepted, fields, error = "ERROR", False, {}, f"{type(exc).__name__}: {exc}"
        holds = bool(case["holds"])
        # An engine that raised has checked nothing: report it, never count it as caught.
        outcome = "error" if error else OUTCOMES[(holds, accepted)]
        rows.append({
            "id": case["id"],
            "engine": check.split(".")[0],
            "check": check,
            "claim": case["claim"],
            "holds": holds,
            "status": status,
            "accepted": accepted,
            "outcome": outcome,
            "source": case.get("source"),
            "error": error,
        })
    return {"cases": rows, **summarise(rows)}


def summarise(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    def tally(subset: List[Dict[str, Any]]) -> Dict[str, int]:
        out = {"cases": len(subset), "holds": sum(r["holds"] for r in subset)}
        out["does_not_hold"] = out["cases"] - out["holds"]
        for name in ("proved", "not_proved", "caught", "false_accept", "error"):
            out[name] = sum(r["outcome"] == name for r in subset)
        return out

    engines = sorted({r["engine"] for r in rows})
    statuses: Dict[str, int] = {}
    for r in rows:
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    return {
        "totals": tally(rows),
        "by_engine": {e: tally([r for r in rows if r["engine"] == e]) for e in engines},
        "statuses": dict(sorted(statuses.items())),
    }


def _git_dirs(top: Path) -> List[Path]:
    """The git directory of a checkout, then its common directory if it has one.

    In a worktree or a submodule, .git is a file ("gitdir: <path>"); a
    worktree's git directory names the shared one in its "commondir" file.
    """
    git = top / ".git"
    if git.is_file():
        pointer = git.read_text(encoding="utf-8").strip()
        if pointer.startswith("gitdir: "):
            git = (top / pointer[len("gitdir: "):]).resolve()
    dirs = [git]
    common = git / "commondir"
    if common.is_file():
        dirs.append((git / common.read_text(encoding="utf-8").strip()).resolve())
    return dirs


def _commit() -> str | None:
    """The commit under test: GITHUB_SHA in CI, else read from git's files without starting a process."""
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        dirs = _git_dirs(ROOT.parent)
        head = (dirs[0] / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head
        ref = head[len("ref: "):]
        for d in dirs:
            if (d / ref).is_file():
                return (d / ref).read_text(encoding="utf-8").strip()
            packed = d / "packed-refs"
            if packed.is_file():
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line.endswith(" " + ref):
                        return line.split(" ", 1)[0]
    except OSError:
        # Best effort: outside a readable git checkout the report has no commit.
        return None
    return None


def report(result: Dict[str, Any]) -> Dict[str, Any]:
    try:
        version = metadata.version("qwed")
    except metadata.PackageNotFoundError:
        version = None
    return {
        "schema": SCHEMA,
        "qwed_version": version,
        "commit": _commit(),
        "python": platform.python_version(),
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "command": "python -m evals.run --json",
        **result,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help=f"also write the full report to ./{REPORT}")
    args = parser.parse_args(argv)

    data = report(run(load_cases()))
    if args.json:
        Path(REPORT).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    t = data["totals"]
    print(f"{t['cases']} claims: {t['holds']} hold, {t['does_not_hold']} do not.")
    print(f"  proved {t['proved']}, not proved {t['not_proved']}, caught {t['caught']}, false accepts {t['false_accept']}, errors {t['error']}")
    for engine, e in data["by_engine"].items():
        print(f"  {engine:<7} {e['cases']:>3} claims  proved {e['proved']}/{e['holds']}  caught {e['caught']}/{e['does_not_hold']}  false accepts {e['false_accept']}")
    for row in data["cases"]:
        if row["outcome"] == "false_accept":
            print(f"FALSE ACCEPT {row['id']}: {row['claim']}", file=sys.stderr)
        elif row["outcome"] == "error":
            print(f"ERROR {row['id']}: {row['error']}", file=sys.stderr)
    return 1 if t["false_accept"] or t["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
