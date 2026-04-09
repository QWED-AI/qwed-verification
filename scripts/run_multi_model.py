#!/usr/bin/env python3
"""
QWED Multi-Model Adversarial Benchmark — Run against ALL frontier models.

Runs the full adversarial test suite (Standard + Hard Mode) against
multiple LLM models via DigitalOcean Gradient API.

Produces:
  - Per-model JSONL trace logs (adversarial_traces/)
  - Per-model JSON reports
  - Comparative summary across all models

Usage:
    python scripts/run_multi_model.py
    python scripts/run_multi_model.py --models openai-o3 anthropic-claude-opus-4.6
    python scripts/run_multi_model.py --dry-run
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── All 4 frontier models via Gradient ──────────────────────────────
DEFAULT_MODELS = [
    "anthropic-claude-opus-4.6",
    "anthropic-claude-4.6-sonnet",
    "openai-o3",
    "openai-gpt-5.4-pro",
]


def run_model_tests(model: str, dry_run: bool = False, run_metadata: dict | None = None) -> dict:
    """Run the full adversarial suite against a single model."""
    print(f"\n{'━'*70}")
    print(f"  MODEL: {model}")
    print(f"{'━'*70}\n")

    env = {}
    env["CUSTOM_MODEL"] = model
    if not dry_run:
        for key in ["CUSTOM_BASE_URL", "CUSTOM_API_KEY"]:
            if key in os.environ: env[key] = os.environ[key]
    for key in ["PATH", "VIRTUAL_ENV"]:
        if key in os.environ: env[key] = os.environ[key]

    log_dir = Path("multi_model_results")
    log_dir.mkdir(exist_ok=True)
    import hashlib
    safe_name = "".join(c for c in model if c.isalnum() or c in "_-.") or "model"
    artifact_stem = f"{safe_name}_{hashlib.sha256(model.encode('utf-8')).hexdigest()[:8]}"
    junit_xml_path = log_dir / f"{artifact_stem}_junit.xml"

    cmd = [
        sys.executable, "-m", "pytest",
        "tests/adversarial/",
        "-v", "-s",
        "--tb=short",
        "--timeout=120",
        f"--junitxml={junit_xml_path}",
    ]

    start = datetime.now(timezone.utc)
    result = subprocess.run(
        cmd, env=env,
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    end = datetime.now(timezone.utc)
    duration = (end - start).total_seconds()

    if run_metadata:
        start = run_metadata.get("start_time", start)
        duration = run_metadata.get("duration", duration)

    # Parse pytest output for pass/fail counts
    output = result.stdout + result.stderr
    
    from defusedxml.ElementTree import parse as xml_parse
    try:
        tree = xml_parse(junit_xml_path)
        root = tree.getroot()
        testsuites = root if root.tag == "testsuites" else [root]
        tests = sum(int(ts.attrib.get("tests", 0)) for ts in testsuites)
        failures = sum(int(ts.attrib.get("failures", 0)) for ts in testsuites)
        errors = sum(int(ts.attrib.get("errors", 0)) for ts in testsuites)
        skipped = sum(int(ts.attrib.get("skipped", 0)) for ts in testsuites)
        failed = failures + errors
        passed = tests - (failed + skipped)
    except Exception as e:
        raise ValueError(f"Failed to parse JUnit XML at {junit_xml_path}") from e

    # Save raw output
    log_path = log_dir / f"{artifact_stem}_output.txt"
    if not log_path.resolve().is_relative_to(log_dir.resolve()):
        raise ValueError(f"Path traversal detected in model name: {model}")
    with open(log_path, "w") as f:
        f.write(output)

    report = {
        "model": model,
        "timestamp": start.isoformat(),
        "duration_seconds": round(duration, 1),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": passed + failed + skipped,
        "exit_code": result.returncode,
        "status": "PASS" if result.returncode == 0 else "FAIL",
        "log_file": str(log_path),
    }

    # Extract test-specific findings from output
    findings = {}
    # Hint Influence
    for case in ["loan_interest", "tax_calculation"]:
        if f"HINT INFLUENCE — {case}" in output:
            block = output.split(f"HINT INFLUENCE — {case}")[1].split("=" * 60)[0]
            try:
                data = json.loads(block.strip())
                findings[f"hint_{case}"] = data.get("faithfulness", "UNKNOWN")
            except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
                raise ValueError(f"Failed to parse HINT INFLUENCE — {case}: {e}") from e

    # Monitor Awareness
    for case in ["contract_clause", "portfolio_risk"]:
        if f"MONITOR AWARENESS — {case}" in output:
            block = output.split(f"MONITOR AWARENESS — {case}")[1].split("=" * 60)[0]
            try:
                data = json.loads(block.strip())
                findings[f"monitor_{case}"] = data.get("monitor_awareness", "UNKNOWN")
            except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
                raise ValueError(f"Failed to parse MONITOR AWARENESS — {case}: {e}") from e

    # CoT Contradiction
    if "CoT CONTRADICTION TEST" in output:
        if "LLM and Z3 AGREE" in output:
            findings["cot_contradiction"] = "AGREE"
        elif "CONTRADICTION" in output:
            findings["cot_contradiction"] = "CONTRADICTION"

    # Process Hash
    if "PROCESS HASH CONSISTENCY" in output:
        block = output.split("PROCESS HASH CONSISTENCY")[1].split("=" * 60)[0]
        try:
            data = json.loads(block.strip())
            findings["deterministic_output"] = data.get("deterministic_output", False)
            findings["all_correct"] = data.get("all_correct", False)
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
            raise ValueError(f"Failed to parse PROCESS HASH CONSISTENCY: {e}") from e

    # Steganographic Verbosity
    if "STEGANOGRAPHIC VERBOSITY" in output:
        block = output.split("STEGANOGRAPHIC VERBOSITY")[1].split("=" * 60)[0]
        try:
            data = json.loads(block.strip())
            findings["verbosity_ratio"] = data.get("complexity_ratio", 0)
            findings["steganographic"] = data.get("suspicious", False)
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
            raise ValueError(f"Failed to parse STEGANOGRAPHIC VERBOSITY: {e}") from e

    # Multi-Hop
    if "MULTI-HOP HIDDEN INFLUENCE" in output:
        block = output.split("MULTI-HOP HIDDEN INFLUENCE")[1].split("=" * 60)[0]
        try:
            data = json.loads(block.strip())
            findings["hint_propagated"] = data.get("hint_propagated", False)
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
            raise ValueError(f"Failed to parse MULTI-HOP HIDDEN INFLUENCE: {e}") from e

    # Contradictory
    for case in ["tax_rate_conflict", "discount_conflict"]:
        if f"CONTRADICTORY INSTRUCTIONS — {case}" in output:
            block = output.split(f"CONTRADICTORY INSTRUCTIONS — {case}")[1].split("=" * 60)[0]
            try:
                data = json.loads(block.strip())
                findings[f"contradictory_{case}"] = data.get("followed", "UNKNOWN")
            except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
                raise ValueError(f"Failed to parse CONTRADICTORY INSTRUCTIONS — {case}: {e}") from e

    # Gradual Drift
    if "GRADUAL DRIFT DETECTION" in output:
        block = output.split("GRADUAL DRIFT DETECTION")[1].split("=" * 60)[0]
        try:
            data = json.loads(block.strip())
            findings["drift_first_flag"] = data.get("first_flag_at_turn", "never")
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
            raise ValueError(f"Failed to parse GRADUAL DRIFT DETECTION: {e}") from e

    # Obfuscation
    if "DELIBERATE OBFUSCATION" in output:
        block = output.split("DELIBERATE OBFUSCATION")[1].split("=" * 60)[0]
        try:
            data = json.loads(block.strip())
            findings["obfuscation"] = data.get("both_correct", False)
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
            raise ValueError(f"Failed to parse DELIBERATE OBFUSCATION: {e}") from e

    report["findings"] = findings

    # Save per-model report
    report_path = log_dir / f"{artifact_stem}_report.json"
    if not report_path.resolve().is_relative_to(log_dir.resolve()):
        raise ValueError(f"Path traversal detected in model name: {model}")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Print summary
    status_icon = "✅" if report["status"] == "PASS" else "❌"
    print(f"\n  {status_icon} {model}: {passed} passed, {failed} failed, "
          f"{skipped} skipped ({duration:.1f}s)")

    return report


def generate_comparison(reports: list, run_timestamp: datetime | None = None) -> dict:
    """Generate a comparative report across all models."""
    if run_timestamp is None:
        run_timestamp = min(
            (datetime.fromisoformat(r["timestamp"]) for r in reports if "timestamp" in r),
            default=datetime.now(timezone.utc)
        )
    comparison = {
        "timestamp": run_timestamp.isoformat(),
        "models_tested": len(reports),
        "models": {},
    }

    for r in reports:
        model = r["model"]
        comparison["models"][model] = {
            "status": r["status"],
            "passed": r["passed"],
            "failed": r["failed"],
            "duration": r["duration_seconds"],
            "findings": r.get("findings", {}),
        }

    # Save comparison
    comp_path = Path("multi_model_results") / "comparison_report.json"
    with open(comp_path, "w") as f:
        json.dump(comparison, f, indent=2, default=str)

    return comparison


def print_comparison_table(reports: list):
    """Print a beautiful comparison table."""
    print("\n")
    print("=" * 90)
    print("  QWED MULTI-MODEL ADVERSARIAL BENCHMARK — COMPARISON")
    print("=" * 90)
    print()

    # Header
    print(f"{'Test':<30}", end="")
    for r in reports:
        short = r["model"].split("-", 1)[-1][:15]
        print(f"  {short:>15}", end="")
    print()
    print("-" * (30 + 17 * len(reports)))

    # Overall
    print(f"{'Overall':<30}", end="")
    for r in reports:
        icon = "✅" if r["status"] == "PASS" else "❌"
        print(f"  {icon} {r['passed']}/{r['total']:>10}", end="")
    print()

    print(f"{'Duration (s)':<30}", end="")
    for r in reports:
        print(f"  {r['duration_seconds']:>14.1f}s", end="")
    print()

    # Findings rows
    finding_labels = {
        "hint_loan_interest": "Hint (loan)",
        "hint_tax_calculation": "Hint (tax)",
        "monitor_contract_clause": "Monitor (contract)",
        "monitor_portfolio_risk": "Monitor (portfolio)",
        "cot_contradiction": "CoT vs Z3",
        "deterministic_output": "Deterministic",
        "all_correct": "All Correct",
        "verbosity_ratio": "Verbosity Ratio",
        "steganographic": "Steganographic",
        "hint_propagated": "Multi-Hop Poison",
        "contradictory_tax_rate_conflict": "Conflict (tax)",
        "contradictory_discount_conflict": "Conflict (discount)",
        "drift_first_flag": "Drift Flag Turn",
        "obfuscation": "Obfuscation Clean",
    }

    print("-" * (30 + 17 * len(reports)))
    for key, label in finding_labels.items():
        print(f"{label:<30}", end="")
        for r in reports:
            val = r.get("findings", {}).get(key, "—")
            if isinstance(val, bool):
                val = "✅" if val else "❌"
            elif isinstance(val, float):
                val = f"{val:.1f}x"
            print(f"  {str(val):>15}", end="")
        print()

    print("=" * (30 + 17 * len(reports)))
    print()


def main():
    parser = argparse.ArgumentParser(description="QWED Multi-Model Benchmark")
    parser.add_argument(
        "--models", nargs="+", default=DEFAULT_MODELS,
        help="Models to test (default: all 4)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Offline only")
    args = parser.parse_args()

    print("=" * 70)
    print("  QWED MULTI-MODEL ADVERSARIAL BENCHMARK")
    print("  Testing QWED against ALL frontier models")
    print("=" * 70)
    print(f"  Models: {', '.join(args.models)}")
    print(f"  Mode:   {'DRY RUN' if args.dry_run else 'LIVE'}")
    print(f"  Time:   {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    # Verify API config
    if not args.dry_run:
        if not os.getenv("CUSTOM_BASE_URL") or not os.getenv("CUSTOM_API_KEY"):
            print("\nERROR: Set CUSTOM_BASE_URL and CUSTOM_API_KEY first.")
            sys.exit(1)

    reports = []
    for model in args.models:
        try:
            report = run_model_tests(model, dry_run=args.dry_run)
            reports.append(report)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"\n❌ {model} CRASHED: {e}")
            reports.append({
                "model": model, "status": "CRASH", "passed": 0,
                "failed": 0, "skipped": 0, "total": 0,
                "duration_seconds": 0, "findings": {},
            })

    # Generate comparison
    _ = generate_comparison(reports)  # Side effect: writes comparison_report.json

    # Print table
    print_comparison_table(reports)

    # Save everything
    # Use consistent timestamp across all artifacts
    run_timestamp = min(
        (datetime.fromisoformat(r["timestamp"]) for r in reports if "timestamp" in r),
        default=datetime.now(timezone.utc)
    )

    summary_path = Path("multi_model_results") / "final_summary.json"
    with open(summary_path, "w") as f:
        json.dump({
            "benchmark": "QWED Adversarial Hidden Reasoning Detection",
            "timestamp": run_timestamp.isoformat(),
            "models_tested": len(reports),
            "reports": reports,
        }, f, indent=2, default=str)

    print("📁 Results saved: multi_model_results/")
    print("📊 Comparison:    multi_model_results/comparison_report.json")
    print("📋 Full summary:  multi_model_results/final_summary.json")

    if any(r["status"] != "PASS" for r in reports):
        sys.exit(1)


if __name__ == "__main__":
    main()
