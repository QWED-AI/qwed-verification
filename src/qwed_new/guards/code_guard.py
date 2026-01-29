import ast
from typing import Dict, Any, List, Set

class CodeGuard:
    """
    Statically analyzes Python code for security risks using AST.
    Blocks Remote Code Execution (RCE) vectors.
    """
    def __init__(self):
        # Blocklist of dangerous functions and imports
        self.dangerous_functions: Set[str] = {'eval', 'exec', 'compile', 'open', 'system', 'popen'}
        self.dangerous_modules: Set[str] = {'os', 'subprocess', 'sys', 'shutil', 'socket', 'pickle'}

    def verify_safety(self, code_snippet: str, language: str = "python") -> Dict[str, Any]:
        """
        Statically analyzes code for security risks.
        Supports: Python (AST), Bash (Regex/Heuristics)
        """
        # Normalize language
        lang = language.lower()

        if lang in ["bash", "sh", "shell"]:
            return self._verify_bash(code_snippet)
        
        # Default to Python AST
        try:
            tree = ast.parse(code_snippet)
        except SyntaxError as e:
            # If it looks like bash but was passed as python, give a hint
            if "curl" in code_snippet or "wget" in code_snippet:
                return {"verified": False, "error": "Syntax Error: Code appears to be Shell/Bash but parsed as Python. Specify language='bash'."}
            return {"verified": False, "error": f"Syntax Error: {e}"}

        violations: List[str] = []

        for node in ast.walk(tree):
            # Check for dangerous function calls (e.g., eval())
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in self.dangerous_functions:
                    violations.append(f"Forbidden function call: {node.func.id}()")
            
            # Check for dangerous imports (e.g., import os)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.dangerous_modules:
                        violations.append(f"Forbidden import: {alias.name}")
            
            # Check for dangerous 'from X import Y'
            elif isinstance(node, ast.ImportFrom):
                if node.module in self.dangerous_modules:
                    violations.append(f"Forbidden import from: {node.module}")
        
        if violations:
            return {
                "verified": False,
                "risk": "SECURITY_VULNERABILITY",
                "violations": violations,
                "message": f"Security Violations Found: {', '.join(violations)}"
            }

        return {
            "verified": True,
            "scan_method": "AST_STATIC_ANALYSIS",
            "message": "Code structure verified safe (No dangerous imports/functions)."
        }

    def _verify_bash(self, code: str) -> Dict[str, Any]:
        """Verify Bash/Shell commands using regex patterns."""
        import re
        
        dangerous_patterns = [
            (r"curl\s+.*\|\s*bash", "Pipe to Bash detected (RCE Risk)"),
            (r"wget\s+.*\|\s*bash", "Pipe to Bash detected (RCE Risk)"),
            (r"rm\s+-rf", "Destructive command (rm -rf)"),
            (r":\(\)\{\s*:\|:\&\s*\}\;", "Fork Bomb detected"),
            (r"nc\s+.*-e\s+/bin/sh", "Netcat Reverse Shell"),
            (r"/dev/tcp/", "Direct TCP connection (Reverse Shell Risk)"),
            (r"base64\s+-d", "Base64 Decoding (Obfuscation Risk)"),
            (r"chmod\s+777", "Insecure permissions (chmod 777)"),
            (r"sudo\s+", "Privilege Escalation attempt (sudo)"),
        ]

        violations = []
        for pattern, desc in dangerous_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                violations.append(desc)
        
        if violations:
            return {
                "verified": False,
                "risk": "SHELL_INJECTION_RISK",
                "violations": violations,
                "message": f"Shell Violations: {', '.join(violations)}"
            }
            
        return {
            "verified": True,
            "scan_method": "REGEX_HEURISTICS",
            "message": "Shell command verified safe."
        }
