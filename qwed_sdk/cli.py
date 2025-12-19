"""
QWED CLI - Command-line interface for QWED Verification Platform.

Usage:
    qwed verify "What is 2+2?"
    qwed verify-math "x**2 + 2*x + 1 = (x+1)**2"
    qwed verify-logic "(AND (GT x 5) (LT y 10))"
    qwed batch input.json -o output.json
    qwed health
"""

import argparse
import json
import sys
import os
from typing import Optional

# Try to import the SDK
try:
    from qwed_sdk import QWEDClient, VerificationResult, BatchResult
except ImportError:
    # Fallback for development
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from qwed_sdk import QWEDClient, VerificationResult, BatchResult


def get_client() -> QWEDClient:
    """Get a configured QWED client from environment."""
    api_key = os.getenv("QWED_API_KEY", "")
    base_url = os.getenv("QWED_API_URL", "http://localhost:8000")
    
    if not api_key:
        print("Error: QWED_API_KEY environment variable not set", file=sys.stderr)
        print("Set it with: export QWED_API_KEY='qwed_...'", file=sys.stderr)
        sys.exit(1)
    
    return QWEDClient(api_key=api_key, base_url=base_url)


def cmd_health(args):
    """Check API health."""
    with get_client() as client:
        result = client.health()
        print(json.dumps(result, indent=2))


def cmd_verify(args):
    """Verify a natural language query."""
    with get_client() as client:
        result = client.verify(args.query, provider=args.provider)
        _print_result(result, args.json)


def cmd_verify_math(args):
    """Verify a mathematical expression."""
    with get_client() as client:
        result = client.verify_math(args.expression)
        _print_result(result, args.json)


def cmd_verify_logic(args):
    """Verify a logic expression."""
    with get_client() as client:
        result = client.verify_logic(args.query)
        _print_result(result, args.json)


def cmd_verify_code(args):
    """Verify code for security issues."""
    code = args.code
    
    # Read from file if provided
    if args.file:
        with open(args.file, "r") as f:
            code = f.read()
    
    with get_client() as client:
        result = client.verify_code(code, language=args.language)
        _print_result(result, args.json)


def cmd_batch(args):
    """Process a batch of verifications from a JSON file."""
    # Read input file
    with open(args.input, "r") as f:
        items = json.load(f)
    
    if not isinstance(items, list):
        print("Error: Input file must contain a JSON array of items", file=sys.stderr)
        sys.exit(1)
    
    with get_client() as client:
        result = client.verify_batch(items)
        
        output = {
            "job_id": result.job_id,
            "status": result.status,
            "total_items": result.total_items,
            "completed_items": result.completed_items,
            "failed_items": result.failed_items,
            "success_rate": f"{result.success_rate:.1f}%",
            "items": [
                {
                    "id": item.id,
                    "query": item.query,
                    "status": item.status,
                    "result": item.result,
                    "error": item.error
                }
                for item in result.items
            ]
        }
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2)
            print(f"Results written to {args.output}")
        else:
            print(json.dumps(output, indent=2))


def _print_result(result: VerificationResult, as_json: bool = False):
    """Print verification result."""
    if as_json:
        print(json.dumps(result.result, indent=2))
    else:
        status_emoji = "✅" if result.is_verified else "❌"
        print(f"{status_emoji} Status: {result.status}")
        
        if result.error:
            print(f"   Error: {result.error}")
        
        if result.provider_used:
            print(f"   Provider: {result.provider_used}")
        
        if result.latency_ms > 0:
            print(f"   Latency: {result.latency_ms:.0f}ms")
        
        # Print key result fields
        if result.result:
            for key in ["is_valid", "simplified", "verdict", "is_safe"]:
                if key in result.result:
                    print(f"   {key}: {result.result[key]}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="qwed",
        description="QWED Verification Platform CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # health command
    health_parser = subparsers.add_parser("health", help="Check API health")
    health_parser.set_defaults(func=cmd_health)
    
    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify natural language query")
    verify_parser.add_argument("query", help="Query to verify")
    verify_parser.add_argument("--provider", "-p", help="LLM provider preference")
    verify_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    verify_parser.set_defaults(func=cmd_verify)
    
    # verify-math command
    math_parser = subparsers.add_parser("verify-math", help="Verify mathematical expression")
    math_parser.add_argument("expression", help="Math expression to verify")
    math_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    math_parser.set_defaults(func=cmd_verify_math)
    
    # verify-logic command
    logic_parser = subparsers.add_parser("verify-logic", help="Verify logic expression")
    logic_parser.add_argument("query", help="Logic query to verify")
    logic_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    logic_parser.set_defaults(func=cmd_verify_logic)
    
    # verify-code command
    code_parser = subparsers.add_parser("verify-code", help="Verify code for security")
    code_parser.add_argument("code", nargs="?", help="Code to verify")
    code_parser.add_argument("--file", "-f", help="Read code from file")
    code_parser.add_argument("--language", "-l", default="python", help="Programming language")
    code_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    code_parser.set_defaults(func=cmd_verify_code)
    
    # batch command
    batch_parser = subparsers.add_parser("batch", help="Process batch from JSON file")
    batch_parser.add_argument("input", help="Input JSON file with items")
    batch_parser.add_argument("--output", "-o", help="Output JSON file for results")
    batch_parser.set_defaults(func=cmd_batch)
    
    # Parse and execute
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        args.func(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
