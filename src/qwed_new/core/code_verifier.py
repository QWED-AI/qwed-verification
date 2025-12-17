"""
Code Verifier: Security Analysis for Code Snippets.

This module provides static analysis and security verification
for code generated or processed by LLMs.
"""

from typing import Dict, Any, List, Set
import ast
import re


class CodeVerifier:
    """
    Verifies code snippets for security vulnerabilities and correctness.
    
    This is Engine 6 of QWED's 8-engine architecture.
    """
    
    # CRITICAL: Always dangerous (auto-block)
    CRITICAL_FUNCTIONS = {
        "eval", "exec", "compile", "__import__",
        "pickle.loads", "pickle.load",
        "yaml.unsafe_load",
        "getattr",  # Can execute arbitrary methods
    }
    
    # Weak cryptographic functions (CRITICAL for passwords)
    WEAK_CRYPTO_FUNCTIONS = {
        "hashlib.md5", "hashlib.sha1",  # Broken for passwords
    }
    
    # Password-related variable names
    PASSWORD_INDICATORS = {
        "password", "passwd", "pwd", "pass",
        "credential", "cred", "auth",
        "secret", "token", "key"
    }
    
    # Dangerous pandas/dataframe methods (execute eval internally)
    DANGEROUS_DATAFRAME_METHODS = {
        "eval", "query"  # df.eval() and df.query() use eval() internally
    }
    
    # WARNING: Context-dependent (manual review)
    WARNING_FUNCTIONS = {
        # File operations (safe if hardcoded, risky if user input)
        "open",
        # OS operations
        "os.system", "os.popen", "os.spawn", "os.spawnl", "os.spawnv",
        "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
        "os.rename", "os.chmod", "os.chown", "os.kill", "os.fork",
        # Subprocess
        "subprocess.call", "subprocess.Popen", "subprocess.run", "subprocess.check_output",
        # File operations
        "shutil.rmtree", "shutil.move", "shutil.copy", "shutil.copyfile",
        # Network
        "socket.socket", "socket.create_connection",
        "urllib.request.urlopen", "urllib.request.urlretrieve",
        "requests.get", "requests.post",
        "http.client.HTTPConnection", "http.client.HTTPSConnection",
    }
    
    # Dangerous modules (import triggers WARNING)
    DANGEROUS_MODULES = {
        "telnetlib", "ftplib",
        "os", "subprocess", "shutil",
        "socket", "urllib", "http.client", "requests",
        "pickle", "marshal",
        "importlib", "imp",
    }
    
    # Dangerous attributes
    DANGEROUS_ATTRIBUTES = {
        "__class__", "__base__", "__subclasses__", "__globals__",
        "__builtins__", "__import__", "__code__", "__dict__"
    }
    
    # User input indicators (for context-aware detection)
    USER_INPUT_INDICATORS = {
        "input", "raw_input",  # Direct user input
        "request", "req",      # Web requests
        "argv", "args",        # Command-line args
        "environ", "getenv",   # Environment variables
    }
    
    def verify_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Verify code for security vulnerabilities and correctness.
        
        Args:
            code: The code snippet to verify
            language: Programming language (currently only python supported)
            
        Returns:
            Dict with verification results
        """
        if language.lower() != "python":
            return {
                "is_safe": False,
                "error": f"Language '{language}' not supported. Only Python is supported.",
                "issues": []
            }
        
        issues = []
        
        # 1. Check for critical functions
        critical_found = self._check_critical_functions(code)
        if critical_found:
            issues.extend([{
                "severity": "CRITICAL",
                "type": "dangerous_function",
                "function": func,
                "message": f"Critical function '{func}' detected. This is blocked."
            } for func in critical_found])
        
        # 2. Check for dangerous attributes
        attr_found = self._check_dangerous_attributes(code)
        if attr_found:
            issues.extend([{
                "severity": "CRITICAL",
                "type": "dangerous_attribute",
                "attribute": attr,
                "message": f"Dangerous attribute '{attr}' detected."
            } for attr in attr_found])
        
        # 3. Check for warning-level functions
        warnings_found = self._check_warning_functions(code)
        if warnings_found:
            issues.extend([{
                "severity": "WARNING",
                "type": "context_dependent_function",
                "function": func,
                "message": f"Function '{func}' requires manual review."
            } for func in warnings_found])
        
        # 4. Check for dangerous module imports
        modules_found = self._check_dangerous_modules(code)
        if modules_found:
            issues.extend([{
                "severity": "WARNING",
                "type": "dangerous_import",
                "module": mod,
                "message": f"Import of '{mod}' requires review."
            } for mod in modules_found])
        
        # 5. Check for weak crypto with passwords
        crypto_issues = self._check_weak_crypto(code)
        if crypto_issues:
            issues.extend(crypto_issues)
        
        # Determine overall safety
        has_critical = any(i["severity"] == "CRITICAL" for i in issues)
        
        return {
            "is_safe": not has_critical,
            "issues": issues,
            "critical_count": sum(1 for i in issues if i["severity"] == "CRITICAL"),
            "warning_count": sum(1 for i in issues if i["severity"] == "WARNING"),
            "status": "BLOCKED" if has_critical else ("REVIEW" if issues else "SAFE")
        }
    
    def _check_critical_functions(self, code: str) -> Set[str]:
        """Check for critical dangerous functions."""
        found = set()
        for func in self.CRITICAL_FUNCTIONS:
            if func in code:
                found.add(func)
        return found
    
    def _check_dangerous_attributes(self, code: str) -> Set[str]:
        """Check for dangerous attributes."""
        found = set()
        for attr in self.DANGEROUS_ATTRIBUTES:
            if attr in code:
                found.add(attr)
        return found
    
    def _check_warning_functions(self, code: str) -> Set[str]:
        """Check for warning-level functions."""
        found = set()
        for func in self.WARNING_FUNCTIONS:
            if func in code:
                found.add(func)
        return found
    
    def _check_dangerous_modules(self, code: str) -> Set[str]:
        """Check for dangerous module imports."""
        found = set()
        for mod in self.DANGEROUS_MODULES:
            pattern = rf"import\s+{mod}|from\s+{mod}"
            if re.search(pattern, code):
                found.add(mod)
        return found
    
    def _check_weak_crypto(self, code: str) -> List[Dict[str, Any]]:
        """Check for weak cryptography used with passwords."""
        issues = []
        code_lower = code.lower()
        
        # Check if any password indicators are present
        has_password_context = any(
            indicator in code_lower 
            for indicator in self.PASSWORD_INDICATORS
        )
        
        if has_password_context:
            for func in self.WEAK_CRYPTO_FUNCTIONS:
                if func in code:
                    issues.append({
                        "severity": "CRITICAL",
                        "type": "weak_crypto_with_password",
                        "function": func,
                        "message": f"Weak hash '{func}' used in password context. Use bcrypt/argon2."
                    })
        
        return issues
