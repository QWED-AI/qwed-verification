"""
SystemGuard: Deterministic Shell & File Firewall.
Blocks dangerous commands and enforces sandboxing.
"""
import re
import os
from typing import Dict, Any, List, Optional

class SystemGuard:
    """
    Deterministic guard for system-level operations.
    Prevents RCE and sandbox escapes via static analysis.
    """
    
    # Default blocklist of dangerous commands
    DEFAULT_BLOCKED_COMMANDS = [
        "rm", "rmdir", "del",           # Deletion
        "chmod", "chown", "chattr",     # Permission changes
        "wget", "curl", "fetch",        # Network downloads
        "ssh", "scp", "rsync", "nc",    # Remote access
        "sudo", "su", "doas",           # Privilege escalation
        "mkfs", "fdisk", "dd",          # Disk operations
        "reboot", "shutdown", "halt",   # System control
        "kill", "pkill", "killall",     # Process control
        "eval", "exec",                 # Code execution
    ]
    
    # Forbidden path patterns (regex)
    DEFAULT_FORBIDDEN_PATHS = [
        r"\.\.",                        # Path traversal
        r"~/.ssh",                      # SSH keys
        r"/etc/passwd",                 # User database
        r"/etc/shadow",                 # Password hashes
        r"/root",                       # Root home
        r"/var/log",                    # System logs
        r"\.env",                       # Environment files
        r"\.git/config",                # Git credentials
        r"id_rsa",                      # SSH private keys
        r"\.pem$",                      # SSL certificates
    ]
    
    def __init__(
        self,
        allowed_paths: Optional[List[str]] = None,
        blocked_commands: Optional[List[str]] = None,
        forbidden_path_patterns: Optional[List[str]] = None
    ):
        self.allowed_paths = allowed_paths or ["/tmp", "./workspace", "."]
        self.blocked_commands = blocked_commands or self.DEFAULT_BLOCKED_COMMANDS
        self.forbidden_patterns = [
            re.compile(p, re.IGNORECASE) 
            for p in (forbidden_path_patterns or self.DEFAULT_FORBIDDEN_PATHS)
        ]
    
    def verify_shell_command(self, command: str) -> Dict[str, Any]:
        """
        Statically analyze a shell command for dangerous patterns.
        
        Returns:
            {"verified": True/False, "risk": str, "message": str}
        """
        if not command or not command.strip():
            return {"verified": True, "message": "Empty command."}
        
        # Normalize command
        cmd_lower = command.lower().strip()
        
        # 1. Check for blocked base commands
        # Split by common shell operators to get base command
        tokens = re.split(r'[;\|\&\s]+', cmd_lower)
        base_commands = [t.split('/')[-1] for t in tokens if t]  # Handle full paths
        
        for base_cmd in base_commands:
            if base_cmd in self.blocked_commands:
                return {
                    "verified": False,
                    "risk": "BLOCKED_COMMAND",
                    "message": f"Command '{base_cmd}' is prohibited by security policy."
                }
        
        # 2. Check for pipe to shell (common RCE pattern: curl ... | bash)
        if re.search(r'\|\s*(bash|sh|zsh|ksh|python|perl|ruby|node)', cmd_lower):
            return {
                "verified": False,
                "risk": "PIPE_TO_SHELL",
                "message": "Piping to shell interpreter is prohibited (RCE risk)."
            }
        
        # 3. Check for path traversal / forbidden paths
        for pattern in self.forbidden_patterns:
            if pattern.search(command):
                return {
                    "verified": False,
                    "risk": "PATH_VIOLATION",
                    "message": f"Access to protected path pattern is denied."
                }
        
        # 4. Check for backticks or $() command substitution
        if '`' in command or '$(' in command:
            return {
                "verified": False,
                "risk": "COMMAND_SUBSTITUTION",
                "message": "Command substitution (backticks/$(...)  ) is prohibited."
            }
        
        return {"verified": True, "message": "Command passed security checks."}
    
    def verify_file_access(
        self, 
        filepath: str, 
        operation: str = "read"
    ) -> Dict[str, Any]:
        """
        Verify if a file path is within allowed sandbox directories.
        
        Args:
            filepath: The path to check.
            operation: "read" or "write" (for logging purposes).
        """
        if not filepath:
            return {"verified": False, "risk": "EMPTY_PATH", "message": "Empty file path."}
        
        # 1. Check forbidden patterns first
        for pattern in self.forbidden_patterns:
            if pattern.search(filepath):
                return {
                    "verified": False,
                    "risk": "FORBIDDEN_PATH",
                    "message": f"Access to path matching forbidden pattern is denied."
                }
        
        # 2. Resolve to absolute path
        try:
            abs_path = os.path.abspath(filepath)
        except Exception:
            return {
                "verified": False,
                "risk": "INVALID_PATH",
                "message": "Could not resolve path."
            }
        
        # 3. Check if within allowed directories
        is_allowed = any(
            abs_path.startswith(os.path.abspath(allowed_dir))
            for allowed_dir in self.allowed_paths
        )
        
        if not is_allowed:
            return {
                "verified": False,
                "risk": "SANDBOX_ESCAPE",
                "message": f"Path '{filepath}' is outside allowed workspace."
            }
        
        return {"verified": True, "message": f"File {operation} access permitted."}
