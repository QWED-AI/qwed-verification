import ast
import re
from typing import List, Dict, Any, Set
from enum import Enum

class Severity(Enum):
    """Issue severity levels for security findings."""
    CRITICAL = "CRITICAL"  # Auto-block: High confidence vulnerability
    WARNING = "WARNING"    # Manual review: Potential risk, context-dependent
    INFO = "INFO"          # Best practice: Log only, no block

class SecurityIssue:
    """Structured security issue with severity and metadata."""
    def __init__(self, severity: Severity, message: str, line: int = None, 
                 requires_manual_review: bool = False, remediation: str = None):
        self.severity = severity.value
        self.message = message
        self.line = line
        self.requires_manual_review = requires_manual_review
        self.remediation = remediation
    
    def to_dict(self):
        return {
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "requires_manual_review": self.requires_manual_review,
            "remediation": self.remediation
        }

class CodeVerifier:
    """
    Engine 5: Code Security Verifier.
    Performs static analysis (AST & Regex) with enterprise-grade severity levels.
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
        """Enhanced verification with severity levels and manual review flags."""
        if language != "python":
            return {"is_safe": True, "issues": [], "message": "Only Python supported"}
        
        issues_list = []
        
        try:
            tree = ast.parse(code)
            issues_list.extend(self._check_ast(tree, code))
        except SyntaxError as e:
            issues_list.append(SecurityIssue(
                Severity.CRITICAL,
                f"Syntax error: {e}",
                line=e.lineno
            ))
        
        # Check for hardcoded secrets
        issues_list.extend(self._check_secrets(code))
        
        # Determine if code is safe based on CRITICAL issues only
        critical_issues = [i for i in issues_list if i.severity == "CRITICAL"]
        is_safe = len(critical_issues) == 0
        
        # Convert to dict format
        issues_dict = [issue.to_dict() for issue in issues_list]
        
        # Legacy format for backward compatibility
        legacy_issues = [issue.message for issue in issues_list]
        
        return {
            "is_safe": is_safe,
            "issues": legacy_issues,  # Keep for backward compatibility
            "detailed_issues": issues_dict,  # New structured format
            "requires_manual_review": any(i.requires_manual_review for i in issues_list),
            "severity_summary": {
                "critical": len([i for i in issues_list if i.severity == "CRITICAL"]),
                "warning": len([i for i in issues_list if i.severity == "WARNING"]),
                "info": len([i for i in issues_list if i.severity == "INFO"])
            }
        }
    
    def _has_user_input_nearby(self, tree: ast.AST, target_node: ast.AST) -> bool:
        """Check if user input functions are used in the same scope as target node."""
        # Simple heuristic: check if input/request appears anywhere in the code
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if any(indicator in node.id.lower() for indicator in self.USER_INPUT_INDICATORS):
                    return True
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in self.USER_INPUT_INDICATORS:
                    return True
        return False
    
    def _check_ast(self, tree: ast.AST, code: str) -> List[SecurityIssue]:
        """Enhanced AST analysis with severity levels."""
        issues = []
        
        for node in ast.walk(tree):
            line_no = getattr(node, 'lineno', None)
            
            # 1. Check for dangerous imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_names = []
                if isinstance(node, ast.Import):
                    module_names = [n.name for n in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    module_names = [node.module]
                
                for module in module_names:
                    if module in self.DANGEROUS_MODULES:
                        # Special case: pickle is CRITICAL due to RCE risk
                        if module == "pickle":
                            issues.append(SecurityIssue(
                                Severity.CRITICAL,
                                f"Import of dangerous module: {module}",
                                line=line_no,
                                remediation="Use json or safer serialization instead"
                            ))
                        else:
                            issues.append(SecurityIssue(
                                Severity.WARNING,
                                f"Import of restricted module: {module} - verify usage is necessary",
                                line=line_no,
                                requires_manual_review=True,
                                remediation="Ensure module usage is validated and necessary for functionality"
                            ))
            
            # 2. Check for dangerous function calls
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                
                if func_name in self.CRITICAL_FUNCTIONS:
                    issues.append(SecurityIssue(
                        Severity.CRITICAL,
                        f"Dangerous function: {func_name}",
                        line=line_no,
                        remediation=f"Avoid {func_name}() - use safer alternatives"
                    ))
                elif func_name in self.WARNING_FUNCTIONS:
                    # Context-aware check for open()
                    if func_name == "open":
                        has_user_input = self._has_user_input_nearby(tree, node)
                        if has_user_input:
                            issues.append(SecurityIssue(
                                Severity.CRITICAL,
                                "File I/O with potential user input - path traversal risk",
                                line=line_no,
                                remediation="Validate and sanitize file paths against whitelist"
                            ))
                        else:
                            # Check if it's a variable (needs review) or hardcoded (safe)
                            if node.args and isinstance(node.args[0], (ast.Name, ast.Attribute, ast.Call)):
                                issues.append(SecurityIssue(
                                    Severity.WARNING,
                                    f"File I/O with variable path - verify input validation",
                                    line=line_no,
                                    requires_manual_review=True,
                                    remediation="Ensure file path is validated and within allowed directory"
                                ))
                            # If hardcoded string, it's safe - don't flag
                    
                    # Subprocess: always CRITICAL
                    elif func_name.startswith("subprocess."):
                        issues.append(SecurityIssue(
                            Severity.CRITICAL,
                            f"Subprocess usage: {func_name} - command injection risk",
                            line=line_no,
                            remediation="Validate and sanitize all subprocess arguments"
                        ))
                    
                        else:
                            issues.append(SecurityIssue(
                                Severity.WARNING,
                                f"Use of {func_name} detected - verify security context",
                                line=line_no,
                                requires_manual_review=True
                            ))
                    
                    else:
                        issues.append(SecurityIssue(
                            Severity.WARNING,
                            f"Use of {func_name} detected - verify security context",
                            line=line_no,
                            requires_manual_review=True
                        ))
                
                # Check for getattr with user input (reflection RCE)
                if func_name == "getattr":
                    # getattr allows arbitrary attribute/method access
                    has_user_input = self._has_user_input_nearby(tree, node)
                    if has_user_input or (node.args and len(node.args) >= 2):
                        # If second argument (attribute name) is user-controlled
                        if node.args and len(node.args) >= 2:
                            attr_arg = node.args[1]
                            if isinstance(attr_arg, (ast.Name, ast.Call)):
                                issues.append(SecurityIssue(
                                    Severity.CRITICAL,
                                    "Reflection vulnerability: getattr() with user-controlled attribute name allows arbitrary method execution",
                                    line=line_no,
                                    remediation="Use explicit attribute access or whitelist allowed attributes"
                                ))
                
                # Check for weak crypto (MD5, SHA1) used for password hashing
                if func_name.startswith("hashlib."):
                    # Check if we're in a password context
                    in_password_context = self._is_password_context(tree, node)
                    
                    if func_name in ["hashlib.md5", "hashlib.sha1"] and in_password_context:
                        issues.append(SecurityIssue(
                            Severity.CRITICAL,
                            f"{func_name} is cryptographically broken - MUST NOT be used for password hashing",
                            line=line_no,
                            remediation="Use bcrypt, scrypt, or argon2 for password hashing"
                        ))
                    elif func_name.startswith("hashlib.sha") and in_password_context:
                        # SHA-256/512 without proper salt/KDF is also bad for passwords
                        issues.append(SecurityIssue(
                            Severity.CRITICAL,
                            f"{func_name} without salt/key stretching is insufficient for passwords",
                            line=line_no,
                            remediation="Use bcrypt, scrypt, or argon2 with proper salt and iterations"
                        ))
                
                # Check for shell=True in subprocess
                for keyword in node.keywords:
                    if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        issues.append(SecurityIssue(
                            Severity.CRITICAL,
                            "Shell injection risk: subprocess with shell=True",
                            line=line_no,
                            remediation="Use shell=False and pass command as list"
                        ))
                    
                    # Check for verify=False in requests
                    if keyword.arg == 'verify' and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                        issues.append(SecurityIssue(
                            Severity.CRITICAL,
                            "Insecure SSL configuration (verify=False)",
                            line=line_no,
                            remediation="Enable SSL verification or use proper certificates"
                        ))
            
            # 3. Check for dangerous DataFrame methods (df.eval, df.query)
            if isinstance(node, ast.Attribute):
                if node.attr in self.DANGEROUS_DATAFRAME_METHODS:
                    # This is df.eval() or df.query() - both use eval() internally
                    issues.append(SecurityIssue(
                        Severity.CRITICAL,
                        f"Dangerous DataFrame method: .{node.attr}() uses eval() internally - RCE risk",
                        line=line_no,
                        remediation=f"Avoid DataFrame.{node.attr}() with user input - use explicit column operations instead"
                    ))
            
            # 4. Check for dangerous attribute access
            if isinstance(node, ast.Attribute):
                if node.attr in self.DANGEROUS_ATTRIBUTES:
                    issues.append(SecurityIssue(
                        Severity.CRITICAL,
                        f"Access to dangerous attribute: {node.attr}",
                        line=line_no
                    ))
            
            # 5. Check for subscript access to __builtins__
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if node.value.id == "__builtins__":
                    issues.append(SecurityIssue(
                        Severity.CRITICAL,
                        "Subscript access to __builtins__",
                        line=line_no
                    ))
            
            # 6. Check for infinite loops
            if isinstance(node, ast.While):
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    issues.append(SecurityIssue(
                        Severity.CRITICAL,
                        "Infinite loop detected: while True",
                        line=line_no
                    ))
            
            # 7. Check for PII in Logging (Enhanced)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ['info', 'warning', 'error', 'debug', 'critical']:
                    for arg in node.args:
                        if isinstance(arg, ast.JoinedStr):
                            try:
                                for subnode in ast.walk(arg):
                                    if isinstance(subnode, ast.Name):
                                        if any(s in subnode.id.lower() for s in ['password', 'secret', 'key', 'token', 'auth']):
                                            issues.append(SecurityIssue(
                                                Severity.CRITICAL,
                                                f"PII/Secret leakage in logs: {subnode.id}",
                                                line=line_no,
                                                remediation="Never log sensitive credentials"
                                            ))
                            except:
                                pass
            
            # 8. Check for Hardcoded Secrets and Encryption Keys
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check for hardcoded encryption keys (including those in bytes)
                        if 'key' in target.id.lower():
                            if isinstance(node.value, ast.Constant):
                                val = node.value.value
                                # Detect encryption keys (strings or bytes longer than 20 chars)
                                if isinstance(val, (str, bytes)):
                                    if len(val) > 20:
                                        issues.append(SecurityIssue(
                                            Severity.CRITICAL,
                                            f"Hardcoded encryption key detected: {target.id}",
                                            line=line_no,
                                            remediation="Use environment variables or Key Management Service"
                                        ))
                        
                        # Check for other secrets
                        elif any(s in target.id.upper() for s in ['_TOKEN', '_SECRET', 'PASSWORD']):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                if len(node.value.value) > 20:
                                    issues.append(SecurityIssue(
                                        Severity.CRITICAL,
                                        f"Hardcoded secret detected: {target.id}",
                                        line=line_no,
                                        remediation="Use environment variables or secret management service"
                                    ))
            
            # 9. Check for Permissive CORS
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == 'allow_origins':
                        if isinstance(keyword.value, ast.List):
                            for elt in keyword.value.elts:
                                if isinstance(elt, ast.Constant) and elt.value == "*":
                                    issues.append(SecurityIssue(
                                        Severity.CRITICAL,
                                        "Over-permissive CORS configuration",
                                        line=line_no,
                                        remediation="Specify exact allowed origins instead of '*'"
                                    ))
        
        return issues
    
    def _get_func_name(self, node):
        """Extract function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            elif isinstance(node.value, ast.Attribute):
                return f"{self._get_func_name(node.value)}.{node.attr}"
        return ""
    
    def _check_secrets(self, code: str) -> List[SecurityIssue]:
        """Check for common secret patterns in code."""
        issues = []
        
        secret_patterns = [
            (r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']', "API key"),
            (r'secret[_-]?key\s*=\s*["\'][^"\']{20,}["\']', "Secret key"),
            (r'password\s*=\s*["\'][^"\']{8,}["\']', "Password"),
            (r'token\s*=\s*["\'][^"\']{20,}["\']', "Token"),
            (r'sk-[a-zA-Z0-9]{20,}', "API key pattern"),
        ]
        
        for pattern, name in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_no = code[:match.start()].count('\n') + 1
                issues.append(SecurityIssue(
                    Severity.CRITICAL,
                    f"Potential hardcoded {name} detected",
                    line=line_no,
                    remediation="Store secrets in environment variables or secret manager"
                ))
        
        return issues
    
    def _is_password_context(self, tree, node):
        """Check if a hash function is being used in a password context."""
        for arg in node.args:
            if isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Attribute) and arg.func.attr == 'encode':
                    if isinstance(arg.func.value, ast.Name):
                        var_name = arg.func.value.id.lower()
                        if any(indicator in var_name for indicator in self.PASSWORD_INDICATORS):
                            return True
            elif isinstance(arg, ast.Name):
                var_name = arg.id.lower()
                if any(indicator in var_name for indicator in self.PASSWORD_INDICATORS):
                    return True
        
        for other_node in ast.walk(tree):
            if isinstance(other_node, ast.Assign):
                for target in other_node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(indicator in var_name for indicator in self.PASSWORD_INDICATORS):
                            return True
        
        return False