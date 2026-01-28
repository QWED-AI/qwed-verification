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
import glob
from pathlib import Path

# QWED SDK imports
try:
    from qwed_sdk import QWEDClient
    from qwed_sdk.guards.system_guard import SystemGuard
    from qwed_sdk.guards.config_guard import ConfigGuard
except ImportError:
    # Fallback for local development
    sys.path.insert(0, "/app")
    from qwed_sdk import QWEDClient
    from qwed_sdk.guards.system_guard import SystemGuard
    from qwed_sdk.guards.config_guard import ConfigGuard


def get_env(name: str, default: str = "") -> str:
    """Get environment variable with fallback."""
    return os.environ.get(f"INPUT_{name.upper()}", default)


def set_output(name: str, value: str):
    """Set GitHub Action output."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")
    print(f"::set-output name={name}::{value}")  # Legacy fallback


def expand_paths(patterns: str) -> list[Path]:
    """Expand glob patterns to file paths."""
    files = []
    for pattern in patterns.split(","):
        pattern = pattern.strip()
        if pattern:
            files.extend(Path(".").glob(pattern.strip()))
    return [f for f in files if f.is_file()]


# ============== VERIFY MODE (Legacy) ==============
def action_verify():
    """Single verification mode (legacy v2.x behavior)."""
    api_key = get_env("API_KEY")
    query = get_env("QUERY")
    llm_output = get_env("LLM_OUTPUT")
    engine = get_env("ENGINE", "math")
    
    if not query or not llm_output:
        print("❌ Error: 'query' and 'llm_output' are required for verify mode.")
        sys.exit(1)
    
    print(f"🚀 QWED Verification (Engine: {engine})")
    
    try:
        client = QWEDClient(api_key=api_key)
        
        if engine == "math":
            result = client.verify_math(query=query, llm_output=llm_output)
        elif engine == "logic":
            result = client.verify_logic(query=query, llm_output=llm_output)
        elif engine == "code":
            result = client.verify_code(code=llm_output)
        else:
            print(f"❌ Unsupported engine: {engine}")
            sys.exit(1)
        
        print(f"🔍 Verdict: {result.verified}")
        print(f"📝 Explanation: {result.explanation}")
        
        set_output("verified", str(result.verified).lower())
        set_output("explanation", result.explanation)
        set_output("badge_url", generate_badge_url(result.verified))
        
        if not result.verified and get_env("FAIL_ON_FINDINGS", "true") == "true":
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Verification Error: {e}")
        sys.exit(1)


# ============== SCAN-SECRETS MODE ==============
def action_scan_secrets():
    """Scan files for leaked secrets."""
    paths = get_env("PATHS", ".")
    output_format = get_env("OUTPUT_FORMAT", "text")
    
    print("🔐 QWED Secret Scanner v3.0")
    print(f"   Scanning: {paths}")
    
    guard = ConfigGuard()
    files = expand_paths(paths)
    
    if not files:
        # Default: scan common secret-containing files
        common_patterns = ["**/*.env", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.toml", "**/*.ini"]
        for pattern in common_patterns:
            files.extend(Path(".").glob(pattern))
        files = [f for f in files if f.is_file()]
    
    findings = []
    
    for filepath in files:
        try:
            content = filepath.read_text(errors="ignore")
            
            # Scan as string (for non-JSON files)
            result = guard.scan_string(content)
            
            if not result["verified"]:
                for secret in result.get("secrets_found", []):
                    findings.append({
                        "file": str(filepath),
                        "type": secret["type"],
                        "message": secret["message"]
                    })
        except Exception as e:
            print(f"   ⚠️  Could not scan {filepath}: {e}")
    
    # Output results
    output_results(findings, output_format, "secrets")
    
    set_output("verified", "true" if len(findings) == 0 else "false")
    set_output("findings_count", str(len(findings)))
    set_output("badge_url", generate_badge_url(len(findings) == 0))
    
    if findings and get_env("FAIL_ON_FINDINGS", "true") == "true":
        sys.exit(1)


# ============== SCAN-CODE MODE ==============
def action_scan_code():
    """Batch scan Python files for dangerous patterns."""
    import ast
    
    paths = get_env("PATHS", "**/*.py")
    output_format = get_env("OUTPUT_FORMAT", "text")
    
    print("🛡️  QWED Code Scanner v3.0")
    print(f"   Scanning: {paths}")
    
    files = expand_paths(paths)
    findings = []
    
    dangerous_calls = ["eval", "exec", "compile", "__import__", "subprocess", "os.system"]
    dangerous_imports = ["os", "subprocess", "sys", "shutil"]
    
    for filepath in files:
        if not str(filepath).endswith(".py"):
            continue
            
        try:
            content = filepath.read_text(errors="ignore")
            tree = ast.parse(content)
            
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
            pass  # Skip files with syntax errors
        except Exception as e:
            print(f"   ⚠️  Could not scan {filepath}: {e}")
    
    output_results(findings, output_format, "code")
    
    set_output("verified", "true" if len(findings) == 0 else "false")
    set_output("findings_count", str(len(findings)))
    set_output("badge_url", generate_badge_url(len(findings) == 0))
    
    if findings and get_env("FAIL_ON_FINDINGS", "true") == "true":
        sys.exit(1)


# ============== VERIFY-SHELL MODE ==============
def action_verify_shell():
    """Lint shell scripts for dangerous patterns."""
    paths = get_env("PATHS", "**/*.sh")
    output_format = get_env("OUTPUT_FORMAT", "text")
    
    print("💻 QWED Shell Linter v3.0")
    print(f"   Scanning: {paths}")
    
    guard = SystemGuard()
    files = expand_paths(paths)
    findings = []
    
    for filepath in files:
        if not str(filepath).endswith(".sh"):
            continue
            
        try:
            content = filepath.read_text(errors="ignore")
            
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
    
    output_results(findings, output_format, "shell")
    
    set_output("verified", "true" if len(findings) == 0 else "false")
    set_output("findings_count", str(len(findings)))
    set_output("badge_url", generate_badge_url(len(findings) == 0))
    
    if findings and get_env("FAIL_ON_FINDINGS", "true") == "true":
        sys.exit(1)


# ============== OUTPUT HELPERS ==============
def output_results(findings: list, format: str, scan_type: str):
    """Output findings in requested format."""
    if format == "json":
        print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
        
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
                print(f"   [{f['type']}] {f['file']}:{f.get('line', '?')}")
                print(f"   └── {f['message']}\n")
            if len(findings) > 20:
                print(f"   ... and {len(findings) - 20} more issues.")
        else:
            print("\n✅ No issues found!\n")


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
    else:
        print(f"❌ Unknown action: {action}")
        print("   Supported: verify, scan-secrets, scan-code, verify-shell")
        sys.exit(1)


if __name__ == "__main__":
    main()
