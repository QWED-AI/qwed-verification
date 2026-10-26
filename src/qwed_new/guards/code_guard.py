import ast
from typing import Dict, Any, List, Set

class CodeGuard:
    """
    Statically screens Python code for security risks using AST.
    Blocks Remote Code Execution (RCE) vectors it recognises.

    A blocklist pre-filter, not a verification (GHSA-4rj3-8wqj-cqwc): a pass
    means only that no listed pattern was found. Use it to refuse code
    early, never to admit it; code that must be admitted goes through the
    server's CodeVerifier (``QWEDClient.verify_code``).
    """
    def __init__(self):
        # Blocklist of dangerous functions and imports
        self.dangerous_functions: Set[str] = {'eval', 'exec', 'compile', 'open', 'system', 'popen', '__import__', 'spawn'}
        self.dangerous_modules: Set[str] = {
            'os', 'subprocess', 'sys', 'shutil', 'socket', 'pickle', 'pty',
            'importlib', 'builtins', 'ctypes', 'marshal',
        }
        # Indirect access that reaches the above without naming it.
        self.reflective_functions: Set[str] = {
            'getattr', 'setattr', 'delattr', 'globals', 'locals', 'vars', 'breakpoint',
        }

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
                # Direct calls: eval()
                if isinstance(node.func, ast.Name) and node.func.id in self.dangerous_functions:
                    violations.append(f"Forbidden function call: {node.func.id}()")
                # Method calls: os.system()
                elif isinstance(node.func, ast.Attribute) and node.func.attr in self.dangerous_functions:
                    violations.append(f"Forbidden method call: .{node.func.attr}()")
            
            # Reflection that reaches blocked names indirectly:
            # getattr(__builtins__, 'ev' + 'al'), ().__class__.__base__, ...
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in self.reflective_functions:
                violations.append(f"Forbidden reflective call: {node.func.id}()")
            elif isinstance(node, ast.Name) and node.id == "__builtins__":
                violations.append("Forbidden name: __builtins__")
            elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr.endswith("__"):
                violations.append(f"Forbidden dunder attribute: .{node.attr}")

            # Check for dangerous imports (e.g., import os)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in self.dangerous_modules:
                        violations.append(f"Forbidden import: {alias.name}")
            
            # Check for dangerous 'from X import Y'
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in self.dangerous_modules:
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
            "advisory": True,
            "scan_method": "AST_STATIC_ANALYSIS",
            "message": "No blocked import or call found. A blocklist pre-filter, not a verification of the code.",
        }

    def _verify_bash(self, code: str) -> Dict[str, Any]:
        """Verify Bash/Shell commands using regex patterns."""
        import re
        
        dangerous_patterns = [
            (r"(?:curl|wget)\s+.*(?:\||&&|;)\s*(?:bash|sh|python|perl|ruby|php)", "Remote Code Execution (RCE) chain detected"),
            (r"rm\s+-rf", "Destructive command (rm -rf)"),
            (r":\(\)\{\s*:\|:\&\s*\}\;", "Fork Bomb detected"),
            (r"nc\s+", "Netcat usage detected (Data Exfiltration/Reverse Shell Risk)"),
            (r"netcat\s+", "Netcat usage detected"),
            (r"/dev/tcp/", "Direct TCP connection (Reverse Shell Risk)"),
            (r"/etc/passwd", "Sensitive file access (/etc/passwd)"),
            (r"/etc/shadow", "Sensitive file access (/etc/shadow)"),
            (r"id_rsa", "SSH Private Key access detected"),
            (r"printenv", "Environment Variable Dumping detected"),
            (r"grep\s+.*(?:pass|token|key|secret)", "Credential Hunting (grep for secrets) detected"),
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
            "advisory": True,
            "scan_method": "REGEX_HEURISTICS",
            "message": "No blocked shell pattern found. A blocklist pre-filter, not a verification of the command.",
        }
