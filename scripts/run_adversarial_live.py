#!/usr/bin/env python3
"""
QWED Adversarial Test Runner — Live LLM Hidden Reasoning Detection.

Runs the full adversarial test suite against a live LLM API (Gradient/DigitalOcean).
Produces a structured JSON report.

Usage:
    # Set environment variables first:
    export CUSTOM_BASE_URL="https://inference.do-ai.run/v1"
    export CUSTOM_API_KEY="your-key"
    export CUSTOM_MODEL="anthropic-claude-opus-4.6"

    # Run:
    python scripts/run_adversarial_live.py
    python scripts/run_adversarial_live.py --model openai-o3
    python scripts/run_adversarial_live.py --dry-run
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description="QWED Adversarial Test Runner")
    parser.add_argument(
        "--model",
        default=os.getenv("CUSTOM_MODEL", "anthropic-claude-opus-4.6"),
        help="Model to test (default: env CUSTOM_MODEL or claude-opus-4.6)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run offline tests only (no API calls)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON report path (default: adversarial_report_<timestamp>.json)",
    )
    args = parser.parse_args()

    # Set model
    os.environ["CUSTOM_MODEL"] = args.model

    print("=" * 70)
    print("  QWED ADVERSARIAL TEST SUITE — HIDDEN REASONING DETECTION")
    print("=" * 70)
    print(f"  Model:     {args.model}")
    print(f"  Mode:      {'DRY RUN (offline only)' if args.dry_run else 'LIVE (API calls)'}")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)
    print()

    # Build pytest command
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/adversarial/test_hidden_reasoning.py",
        "-v",
        "--tb=short",
        "-s",  # Show print output        
    ]

    if args.dry_run:
        # Only run offline tests (skip live tests that need API)
        # Temporarily unset API vars to trigger skipif
        env = os.environ.copy()
        env.pop("CUSTOM_BASE_URL", None)
        env.pop("CUSTOM_API_KEY", None)
    else:
        env = os.environ.copy()
        # Verify API config
        if not env.get("CUSTOM_BASE_URL") or not env.get("CUSTOM_API_KEY"):
            print("ERROR: CUSTOM_BASE_URL and CUSTOM_API_KEY must be set for live mode.")
            print("Use --dry-run for offline testing.")
            sys.exit(1)

    # Run tests
    result = subprocess.run(cmd, env=env, cwd=os.path.dirname(os.path.dirname(__file__)))

    # Generate report
    report = {
        "suite": "QWED Adversarial Hidden Reasoning Detection",
        "model": args.model,
        "mode": "dry_run" if args.dry_run else "live",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "exit_code": result.returncode,
        "status": "PASS" if result.returncode == 0 else "FAIL",
    }

    # Snyk Fix: Sanitize user input to prevent Path Traversal
    output_filename = os.path.basename(args.output) if args.output else f"adversarial_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    output_path = os.path.abspath(output_filename) # Ensure it stays in current dir if basename applied
    
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved: {output_path}")
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
