"""
QWED Action Entrypoint v3.0

Supports:
- verify: Single LLM output verification (math, logic, code, sql, shell)
- scan-secrets: Scan files for leaked API keys/tokens
- scan-code: Batch scan Python files for dangerous patterns
- verify-shell: Lint shell scripts for RCE patterns
"""
import os
import sys
import json
import hashlib
from pathlib import Path

try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None

# QWED SDK imports - only guards (no heavy dependencies)
sys.path.insert(0, "/app")
from qwed_sdk.guards.system_guard import SystemGuard
from qwed_sdk.guards.config_guard import ConfigGuard
from qwed_new.guards.process_guard import ProcessVerifier
from qwed_new.core.verification_context import _canonical_json


def get_env(name: str, default: str = "") -> str:
    """Get environment variable with fallback."""
    return os.environ.get(f"INPUT_{name.upper()}", default)


def set_output(name: str, value: str):
    """Set GitHub Action output."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        # Validate path to prevent path traversal (defense-in-depth)
        output_path = os.path.realpath(output_file)
        cwd = os.path.realpath(os.getcwd())
        # Canonical containment check using commonpath
        allowed_roots = ["/home/runner", "/github", cwd]
        try:
            if not any(os.path.commonpath([root, output_path]) == root for root in allowed_roots):
                print(f"⚠️  Suspicious GITHUB_OUTPUT path: {output_file}")
                return
        except ValueError:
            # commonpath raises ValueError if paths are on different drives (Windows)
            print(f"⚠️  Invalid GITHUB_OUTPUT path: {output_file}")
            return
        # deepcode ignore PT: Path validated with commonpath containment check
        with open(output_path, "a") as f:
            f.write(f"{name}={value}\n")
    print(f"::set-output name={name}::{value}")  # Legacy fallback


CODE_PATTERNS = "**/*.py"
SHELL_PATTERNS = "**/*.sh"
CONFIG_FILE_PATTERNS = "**/*.env,**/*.json,**/*.yaml,**/*.yml,**/*.toml,**/*.ini"

# A bare "." (the Action's old default) means "the workspace", so it takes
# the mode's own patterns rather than being passed to glob, which rejects it.
_WORKSPACE_PATTERNS = ("", ".", "./")


def _split_patterns(patterns: str) -> list[str]:
    return [p.strip() for p in patterns.split(",") if p.strip()]


def expand_paths(
    patterns: str, default: str = "", suffixes: tuple[str, ...] = ()
) -> tuple[list[Path], list[str]]:
    """Expand comma-separated glob patterns to files inside the workspace.

    An empty input, or a pattern of ".", uses ``default``. Only regular files
    are kept, and only those ending in one of ``suffixes`` when it is given.
    The suffix filter runs before duplicates are dropped, so a link with
    another name never stands in for a file the mode would scan. Returns the
    files and one error per pattern that could not be expanded or that
    reaches a file outside the workspace, so the caller can refuse to admit
    the scan.
    """
    expanded = []
    for pattern in _split_patterns(patterns) or [""]:
        if pattern in _WORKSPACE_PATTERNS:
            expanded.extend(_split_patterns(default))
        else:
            expanded.append(pattern)

    root = Path.cwd().resolve()
    files, errors, seen = [], [], set()
    for pattern in dict.fromkeys(expanded):
        try:
            matches = list(Path(".").glob(pattern))
        except (ValueError, IndexError, NotImplementedError) as exc:
            errors.append(f"invalid pattern {pattern!r}: {exc or type(exc).__name__}")
            continue
        outside = []
        for match in matches:
            if not match.is_file() or (suffixes and not match.name.endswith(suffixes)):
                continue
            resolved = match.resolve()
            if not resolved.is_relative_to(root):
                outside.append(str(match))
                continue
            if resolved not in seen:
                seen.add(resolved)
                files.append(match)
        if outside:
            shown = ", ".join(outside[:5]) + (f" and {len(outside) - 5} more" if len(outside) > 5 else "")
            errors.append(f"pattern {pattern!r} matches files outside the workspace: {shown}")
    return files, errors


def _finish_scan(scan_type: str, findings: list, files_scanned: int, errors: list[str]):
    """Set the outputs for a file scan and exit non-zero if it is not admitted.

    A scan is admitted only if it covered at least one file, every pattern
    expanded cleanly, every matched file was scanned and nothing was found.
    An empty or partial scan proves nothing.
    """
    reason = None
    if errors:
        reason = "; ".join(errors[:5])
        if len(errors) > 5:
            reason += f"; and {len(errors) - 5} more"
    elif files_scanned == 0:
        reason = "no files matched the paths input, so nothing was scanned"

    verified = reason is None and not findings
    if reason:
        print(f"\n❌ Not admitted: {reason}.")

    set_output("verified", "true" if verified else "false")
    set_output("findings_count", str(len(findings)))
    set_output("files_scanned", str(files_scanned))
    set_output("badge_url", generate_badge_url(verified))

    evidence = {"findings_count": len(findings), "files_scanned": files_scanned}
    if reason:
        evidence["reason"] = reason
    verdict = "VERIFIED" if verified else "UNVERIFIABLE"
    admission = "ADMIT" if verified else "DENY"
    _set_vc_outputs(verdict, admission, evidence, scan_type, reason=reason)

    if not verified and get_env("FAIL_ON_FINDINGS", "true") == "true":
        sys.exit(1)


# ============== VERIFY MODE (Legacy) ==============
def action_verify():
    """Single verification mode (legacy v2.x behavior)."""
    api_key = get_env("API_KEY")
    query = get_env("QUERY")
    llm_output = get_env("LLM_OUTPUT")
    engine = get_env("ENGINE", "math")
    
    if engine == "math" and not query:
        print("❌ Error: 'query' is required for math verify mode.")
        sys.exit(1)
    elif engine == "logic" and not query:
        print("❌ Error: 'query' is required for logic verify mode.")
        sys.exit(1)
    elif engine == "code" and not llm_output:
        print("❌ Error: 'llm_output' is required for code verify mode.")
        sys.exit(1)
    
    print(f"🚀 QWED Verification (Engine: {engine})")
    
    try:
        # Lazy import to avoid httpx dependency for scan modes
        from qwed_sdk.client import QWEDClient
        client = QWEDClient(api_key=api_key)
        
        if engine == "math":
            result = client.verify_math(expression=query)
        elif engine == "logic":
            result = client.verify_logic(query)
        elif engine == "code":
            result = client.verify_code(code=llm_output)
        else:
            print(f"❌ Unsupported engine: {engine}")
            sys.exit(1)
        
        # Admitted only as the server decided (GHSA-jppc-7r58-7pjh): its
        # admission where the route makes one, otherwise VERIFIED with
        # is_valid true. The SDK's is_verified follows that rule; a BLOCKED or
        # UNVERIFIABLE result is never admitted, whatever is_valid it carries.
        admitted = result.is_verified
        verdict = result.status if result.status in ("VERIFIED", "UNVERIFIABLE", "BLOCKED") else "UNVERIFIABLE"
        print(f"🔍 Verdict: {verdict} · {'ADMIT' if admitted else 'DENY'}")
        explanation = result.result.get("explanation", "") if result.result else ""
        print(f"📝 Explanation: {explanation}")
        
        set_output("verified", str(admitted).lower())
        set_output("explanation", explanation)
        set_output("badge_url", generate_badge_url(admitted))
        
        admission = "ADMIT" if admitted else "DENY"
        _set_vc_outputs(verdict, admission, {"explanation": explanation}, engine)
        
        if not admitted and get_env("FAIL_ON_FINDINGS", "true") == "true":
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Verification Error: {e}")
        sys.exit(1)


# ============== SCAN-SECRETS MODE ==============
def action_scan_secrets():
    """Scan files for leaked secrets."""
    paths = get_env("PATHS")
    output_format = get_env("OUTPUT_FORMAT", "text")

    print("🔐 QWED Secret Scanner v3.0")
    print(f"   Scanning: {paths or CONFIG_FILE_PATTERNS}")

    guard = ConfigGuard()
    files, errors = expand_paths(paths, CONFIG_FILE_PATTERNS)

    findings = []
    files_scanned = 0

    for filepath in files:
        try:
            content = filepath.read_text(errors="ignore")
            files_scanned += 1

            # Scan as string (for non-JSON files)
            result = guard.scan_string(content)
            
            if not result["verified"]:
                for secret in result.get("secrets_found", []):
                    findings.append({
                        "file": str(filepath),
                        "type": secret["type"],
                        # "message": secret["message"] # REMOVED: Tainted source
                        "message": "Potential secret detected (see SARIF for details)"
                    })
        except Exception as e:
            print(f"   ⚠️  Could not scan {filepath}: {e}")
            errors.append(f"could not scan {filepath}")
    
    # Output results
    # Output results manually to prevent tainting output_results with secret data
    if output_format == "sarif":
        sarif = generate_sarif(findings, "secrets")
        sarif_path = "qwed-results.sarif"
        with open(sarif_path, "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"📊 SARIF output written to: {sarif_path}")
        set_output("sarif_file", sarif_path)
    
    elif output_format == "json":
        # SECURE JSON OUTPUT: Only counts, no details to console
        print(json.dumps({
            "scan_type": "secrets",
            "count": len(findings),
            "message": "Details omitted for security. Check SARIF report."
        }, indent=2))
        
    else:
        # SECURE TEXT OUTPUT: Only counts, no details to console
        if findings:
            print(f"\n❌ Found {len(findings)} secret(s).")
            print("   ⚠️  Details omitted from logs to prevent leakage.")
            print("   📄 Check the 'Security' tab or 'qwed-results.sarif' artifact.")
        elif files_scanned:
            print(f"\n✅ No secrets found in {files_scanned} file(s).\n")

    _finish_scan("secrets", findings, files_scanned, errors)


# ============== SCAN-CODE MODE ==============
def action_scan_code():
    """Batch scan Python files for dangerous patterns."""
    import ast
    
    paths = get_env("PATHS")
    output_format = get_env("OUTPUT_FORMAT", "text")

    print("🛡️  QWED Code Scanner v3.0")
    print(f"   Scanning: {paths or CODE_PATTERNS}")

    files, errors = expand_paths(paths, CODE_PATTERNS, (".py",))
    findings = []
    files_scanned = 0
    
    dangerous_calls = ["eval", "exec", "compile", "__import__", "subprocess", "os.system"]
    dangerous_imports = ["os", "subprocess", "sys", "shutil"]
    
    for filepath in files:
        try:
            content = filepath.read_text(errors="ignore")
            tree = ast.parse(content)
            files_scanned += 1

            for node in ast.walk(tree):
                # Check dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in dangerous_calls:
                            findings.append({
                                "file": str(filepath),
                                "line": node.lineno,
                                "type": "DANGEROUS_CALL",
                                "message": f"Dangerous function: {node.func.id}()"
                            })
                    elif isinstance(node.func, ast.Attribute):
                        full_name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"
                        if full_name in dangerous_calls or node.func.attr in ["system", "popen", "call", "run"]:
                            findings.append({
                                "file": str(filepath),
                                "line": node.lineno,
                                "type": "DANGEROUS_CALL",
                                "message": f"Dangerous function: {full_name}()"
                            })
                
                # Check dangerous imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in dangerous_imports:
                            findings.append({
                                "file": str(filepath),
                                "line": node.lineno,
                                "type": "DANGEROUS_IMPORT",
                                "message": f"System module imported: {alias.name}"
                            })
                            
        except SyntaxError:
            print(f"   ⚠️  Could not parse {filepath}")
            errors.append(f"could not parse {filepath}")
        except Exception as e:
            print(f"   ⚠️  Could not scan {filepath}: {e}")
            errors.append(f"could not scan {filepath}")
    
    output_results(findings, output_format, "code", files_scanned)
    _finish_scan("code", findings, files_scanned, errors)


# ============== VERIFY-SHELL MODE ==============
def action_verify_shell():
    """Lint shell scripts for dangerous patterns."""
    paths = get_env("PATHS")
    output_format = get_env("OUTPUT_FORMAT", "text")

    print("💻 QWED Shell Linter v3.0")
    print(f"   Scanning: {paths or SHELL_PATTERNS}")

    guard = SystemGuard()
    files, errors = expand_paths(paths, SHELL_PATTERNS, (".sh",))
    findings = []
    files_scanned = 0

    for filepath in files:
        try:
            content = filepath.read_text(errors="ignore")
            files_scanned += 1

            for lineno, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                result = guard.verify_shell_command(line)
                
                if not result["verified"]:
                    findings.append({
                        "file": str(filepath),
                        "line": lineno,
                        "type": result.get("risk", "SECURITY_RISK"),
                        "message": result.get("message", "Dangerous command detected")
                    })
                    
        except Exception as e:
            print(f"   ⚠️  Could not scan {filepath}: {e}")
            errors.append(f"could not scan {filepath}")
    
    output_results(findings, output_format, "shell", files_scanned)
    _finish_scan("shell", findings, files_scanned, errors)



# ============== VERIFY-PROCESS MODE ==============
def action_verify_process():
    """Verify reasoning process integrity (IRAC & Milestones)."""
    llm_output = get_env("LLM_OUTPUT")
    milestones = get_env("MILESTONES", "")  # Comma-separated
    output_format = get_env("OUTPUT_FORMAT", "text")
    
    if not llm_output:
        print("❌ Error: 'llm_output' is required for verify-process mode.")
        sys.exit(1)
        
    print("🧠 QWED Process Integrity Verifier v3.0")
    verifier = ProcessVerifier()
    
    # Check IRAC Structure
    irac_result = verifier.verify_irac_structure(llm_output)
    
    # Check Milestones (if provided)
    milestone_list = [m.strip() for m in milestones.split(",") if m.strip()]
    milestone_result = verifier.verify_trace(llm_output, milestone_list)
    
    # Combined Verdict
    authorized = irac_result["verified"] and milestone_result["verified"]
    
    findings = []
    if not irac_result["verified"]:
        findings.append({
            "type": "MISSING_STRUCTURE",
            "message": f"Missing IRAC steps: {', '.join(irac_result['missing_steps'])}",
            "score": irac_result["score"]
        })
        
    if not milestone_result["verified"]:
        findings.append({
            "type": "MISSED_MILESTONE",
            "message": f"Missed required milestones: {', '.join(milestone_result['missed_milestones'])}",
            "process_rate": milestone_result["process_rate"]
        })
    
    # Output
    if output_format == "json":
        print(json.dumps({
            "verified": authorized,
            "irac_score": irac_result["score"],
            "process_rate": milestone_result["process_rate"],
            "findings": findings
        }, indent=2))
    else:
        print(f"   🔍 Integration Score: {irac_result['score']:.0%}")
        print(f"   📉 Process Rate:     {milestone_result['process_rate']:.0%}")
        
        if findings:
            print("\n❌ Process Integrity Issues:")
            for f in findings:
                print(f"   - [{f['type']}] {f['message']}")
        else:
            print("\n✅ Reasoning Process Verified (IRAC Compliant)")
            
            
    set_output("verified", str(authorized).lower())
    set_output("badge_url", generate_badge_url(authorized))
    set_output("irac_score", f"{irac_result['score']:.4f}")
    set_output("process_rate", f"{milestone_result['process_rate']:.4f}")
    set_output("findings", json.dumps(findings))
    
    verdict = "VERIFIED" if authorized else "UNVERIFIABLE"
    admission = "ADMIT" if authorized else "DENY"
    _set_vc_outputs(verdict, admission, {"irac_score": irac_result["score"], "process_rate": milestone_result["process_rate"]}, "process")
    
    if not authorized and get_env("FAIL_ON_FINDINGS", "true") == "true":
        sys.exit(1)


# ============== OUTPUT HELPERS ==============
def output_results(findings: list, format: str, scan_type: str, files_scanned: int | None = None):
    """Output findings in requested format."""
    
    """Output findings in requested format."""
    
    # NOTE: This function is NO LONGER called for "secrets" scan type.
    # Secret scanning handles its own output to prevent taint flow.

    # For valid non-secret scans (code, shell), we can show safe details
    if format == "json":
        # Sanitize findings for JSON output
        safe_findings = []
        for f in findings:
            safe_findings.append({
                "type": f.get("type", "UNKNOWN"),
                "file": os.path.basename(f.get("file", "")), # Only show basename
                "line": f.get("line", "?")
            })
        print(json.dumps({"findings": safe_findings, "count": len(findings)}, indent=2))
        
    elif format == "sarif":
        sarif = generate_sarif(findings, scan_type)
        sarif_path = "qwed-results.sarif"
        with open(sarif_path, "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"📊 SARIF output written to: {sarif_path}")
        set_output("sarif_file", sarif_path)
        
    else:  # text
        if findings:
            print(f"\n❌ Found {len(findings)} issue(s):\n")
            for f in findings[:20]:  # Limit output
                safe_file = os.path.basename(f.get("file", "?"))
                # Sanitize output variables to prevent injection/leakage (CodeQL Requirement)
                raw_type = str(f.get("type", "UNKNOWN"))
                safe_type = "".join(ch for ch in raw_type if ch.isalnum() or ch in ("_", "-")) or "UNKNOWN"
                
                raw_line = f.get("line", "?")
                safe_line = str(raw_line) if isinstance(raw_line, (int, str)) else "?"
                
                print(f"   [{safe_type}] {safe_file}:{safe_line}")
                print(f"   └── Detected potential {safe_type} issue.\n")
            if len(findings) > 20:
                print(f"   ... and {len(findings) - 20} more issues.")
        elif files_scanned is None:
            print("\n✅ No issues found!\n")
        elif files_scanned:
            print(f"\n✅ No issues found in {files_scanned} file(s).\n")


def generate_sarif(findings: list, scan_type: str) -> dict:
    """Generate SARIF 2.1.0 output for GitHub Security tab."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "QWED Protocol",
                    "version": "3.0.0",
                    "informationUri": "https://github.com/QWED-AI/qwed-verification",
                    "rules": [
                        {
                            "id": f"qwed/{scan_type}/security",
                            "name": f"QWED {scan_type.title()} Security Check",
                            "shortDescription": {"text": f"Security issue detected by QWED {scan_type} scanner"},
                            "defaultConfiguration": {"level": "error"}
                        }
                    ]
                }
            },
            "results": [
                {
                    "ruleId": f"qwed/{scan_type}/security",
                    "level": "error",
                    "message": {"text": f["message"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": f.get("line", 1)}
                        }
                    }]
                }
                for f in findings
            ]
        }]
    }


def generate_badge_url(passed: bool) -> str:
    """Generate shields.io badge URL."""
    if passed:
        return "https://img.shields.io/badge/QWED-verified-brightgreen?logo=data:image/svg+xml;base64,..."
    else:
        return "https://img.shields.io/badge/QWED-failed-red?logo=data:image/svg+xml;base64,..."


# ============== VERIFICATION CONTEXT v1.0 ==============
def _formal_statement_for(scan_type: str, verdict: str, reason: str | None = None) -> str:
    if verdict == "VERIFIED":
        return f"QWED {scan_type} verification passed with no findings"
    elif reason:
        return f"QWED {scan_type} verification was not admitted: {reason}"
    elif verdict == "UNVERIFIABLE":
        return f"QWED {scan_type} verification detected findings and was not admitted"
    else:
        return f"QWED {scan_type} verification was blocked"


def _build_verification_context(
    verdict: str,
    admission: str,
    proof_ref,
    evidence: dict,
    scan_type: str,
    reason: str | None = None,
) -> dict:
    configuration: dict = {"action": get_env("ACTION", "verify")}
    paths = get_env("PATHS", "")
    if paths:
        configuration["paths"] = paths

    return {
        "spec_version": "1.0",
        "object": {
            "formal_statement": _formal_statement_for(scan_type, verdict, reason),
        },
        "context": {
            "interpretation": {
                "theory": f"QWED {scan_type} verification",
                "logic": "deterministic pattern matching",
            },
            "proof": {
                "verifier": "QWED Action",
                "verifier_version": "3.1.0",
                "configuration": configuration,
                "theory_scope": f"QWED {scan_type} verification",
                "trusted_dependencies": ("qwed-verification",),
                "outcome_treatment": "unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
            },
            "evidence": {
                "evidence": evidence,
                "proof_ref": proof_ref,
            },
            "decision": {
                "admission": admission,
            },
        },
        "verdict": verdict,
    }


def _compute_vc_proof_ref(formal_statement: str, context: dict) -> str:
    bound_context: dict = {k: v for k, v in context.items() if k != "proof_ref"}
    if "evidence" in bound_context:
        bound_context["evidence"] = {
            k: v for k, v in bound_context["evidence"].items() if k != "proof_ref"
        }
    bound = {
        "formal_statement": formal_statement,
        "context": bound_context,
    }
    canonical = _canonical_json(bound)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _set_vc_outputs(verdict: str, admission: str, evidence: dict, scan_type: str, reason: str | None = None):
    output_format = get_env("OUTPUT_FORMAT", "text")
    formal_statement = _formal_statement_for(scan_type, verdict, reason)

    if verdict == "VERIFIED":
        vc_for_hash = _build_verification_context(verdict, admission, None, evidence, scan_type, reason)
        proof_ref = _compute_vc_proof_ref(formal_statement, vc_for_hash["context"])
    else:
        proof_ref = None

    set_output("verdict", verdict)
    set_output("admission", admission)
    set_output("proof_ref", proof_ref if proof_ref is not None else "")

    if output_format in ("verification-context", "json"):
        vc = _build_verification_context(verdict, admission, proof_ref, evidence, scan_type, reason)
        set_output("verification_context", json.dumps(vc, separators=(",", ":")))


# ============== MAIN ==============
def main():
    action = get_env("ACTION", "verify")
    
    print("=" * 50)
    print("  🔬 QWED Protocol v3.0 - GitHub Action")
    print("  https://github.com/QWED-AI/qwed-verification")
    print("=" * 50)
    
    if action == "verify":
        action_verify()
    elif action == "scan-secrets":
        action_scan_secrets()
    elif action == "scan-code":
        action_scan_code()
    elif action == "verify-shell":
        action_verify_shell()
    elif action == "verify-process":
        action_verify_process()
    else:
        print(f"❌ Unknown action: {action}")
        print("   Supported: verify, scan-secrets, scan-code, verify-shell, verify-process")
        sys.exit(1)


if __name__ == "__main__":
    # Initialize Sentry if DSN is provided
    sentry_dsn = get_env("SENTRY_DSN") or os.environ.get("SENTRY_DSN")
    if sentry_dsn and sentry_sdk:
        print("🔭 Initializing Sentry SDK...")
        sentry_sdk.init(
            dsn=sentry_dsn,
            traces_sample_rate=1.0,  # Capture 100% of transactions for performance monitoring
            environment="production",
            release=os.environ.get("GITHUB_SHA", "unknown"),
        )
        sentry_sdk.set_tag("repository", os.environ.get("GITHUB_REPOSITORY", "unknown"))
        sentry_sdk.set_tag("actor", os.environ.get("GITHUB_ACTOR", "unknown"))
        sentry_sdk.set_tag("run_id", os.environ.get("GITHUB_RUN_ID", "unknown"))
        
        # Capture strictly necessary context, avoid PII unless explicitly enabled
        sentry_sdk.set_context("github", {
            "ref": os.environ.get("GITHUB_REF"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "action": os.environ.get("GITHUB_ACTION"),
        })

    try:
        main()
    except Exception as e:
        if sentry_dsn and sentry_sdk:
            sentry_sdk.capture_exception(e)
        raise
