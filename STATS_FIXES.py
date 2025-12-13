"""
Quick script to fix Stats Engine detection issues
Fixes: os.system() CRITICAL, subprocess CRITICAL, DataFrame.eval() test
"""

# Fix 1: code_verifier.py - Add os.system check before WARNING_FUNCTIONS
code_verifier_fix1 = """                if func_name in self.CRITICAL_FUNCTIONS:
                    issues.append(SecurityIssue(
                        Severity.CRITICAL,
                        f"Dangerous function: {func_name}",
                        line=line_no,
                        remediation=f"Avoid {func_name}() - use safer alternatives"
                    ))
                # Special case: os.system is always CRITICAL (command injection)
                elif func_name == "os.system":
                    issues.append(SecurityIssue(
                        Severity.CRITICAL,
                        "Shell command execution via os.system() - command injection risk",
                        line=line_no,
                        remediation="Use subprocess with argument list instead of os.system()"
                    ))
                elif func_name in self.WARNING_FUNCTIONS:"""

# Fix 2: code_verifier.py - Simplify subprocess to always CRITICAL
code_verifier_fix2 = """                    
                    # Subprocess: always CRITICAL (any subprocess usage is risky)
                    elif func_name.startswith("subprocess."):
                        issues.append(SecurityIssue(
                            Severity.CRITICAL,
                            f"Subprocess usage detected: {func_name} - command injection risk",
                            line=line_no,
                            remediation="Validate and sanitize all subprocess arguments, use absolute paths, avoid user input"
                        ))
                    
                    else:"""

# Fix 3: stats_engine_security.py - Fix DataFrame.eval test
test_fix = """        
        # Should detect as unsafe - eval is dangerous
        issues = response.data.get("issues", [])
        # Issues can be strings or dicts - handle both
        has_eval_warning = any("eval" in str(issue).lower() for issue in issues)
        is_unsafe = not response.data.get("is_safe", True)
        
        passed = is_unsafe or has_eval_warning
        """

print("Apply these 3 fixes manually:")
print("\n=== FIX 1: code_verifier.py line ~196 ===")
print(code_verifier_fix1)
print("\n=== FIX 2: code_verifier.py line ~226 (replace entire subprocess block) ===")
print(code_verifier_fix2)
print("\n=== FIX 3: stats_engine_security.py line ~49 ===")
print(test_fix)
