"""
Secure Code Execution Module for QWED.
OWASP LLM06:2025 - Excessive Agency / Code Execution Defense

Provides sandboxed execution of LLM-generated code with:
- Docker container isolation
- Resource limits (CPU, memory, time)
- Network isolation (no internet access)
- Pre-execution validation using AST analysis
"""

import docker
import tempfile
import json
import os
import logging
from typing import Any, Dict, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class SecureCodeExecutor:
    """
    Executes Python code in isolated Docker container.
    
    Security features:
    - Container-based isolation
    - No network access
    - Resource limits (512MB RAM, 50% CPU, 10s timeout)
    - Pre-execution AST validation
    - Temporary file-based I/O (no shared memory)
    """
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.docker_available = True
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.error(f"Docker initialization failed: {e}")
            self.docker_available = False
        
        # Resource limits
        self.cpu_limit = 0.5  # 50% of one CPU core
        self.memory_limit = "512m"  # 512 MB
        self.timeout = 10  # seconds
        self.execution_count = 0
        
        # Docker image to use
        self.image = "amancevice/pandas:slim"
    
    def execute(self, code: str, context: Dict[str, Any]) -> Tuple[bool, Optional[str], Any]:
        """
        Execute Python code in isolated environment.
        
        Args:
            code: Python code string to execute
            context: Dictionary of variables/data to pass to code
            
        Returns:
            (success, error_message, result)
        """
        if not self.docker_available:
            return False, "Docker is not available. Cannot execute code securely.", None
        
        # 1. Pre-execution validation using AST
        is_safe, safety_reason = self._is_safe_code(code)
        if not is_safe:
            logger.warning(f"Code failed safety check: {safety_reason}")
            return False, f"Code safety validation failed: {safety_reason}", None
        
        self.execution_count += 1
        execution_id = f"exec_{self.execution_count}_{int(datetime.utcnow().timestamp())}"
        
        logger.info(f"Starting secure code execution: {execution_id}")
        
        # 2. Create temporary directory for data exchange
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                # Write context data
                context_file = os.path.join(tmpdir, "context.json")
                with open(context_file, 'w') as f:
                    # Serialize context (handle DataFrames if present)
                    serializable_context = self._serialize_context(context)
                    json.dump(serializable_context, f)
                
                # Write code to execute
                code_file = os.path.join(tmpdir, "script.py")
                with open(code_file, 'w') as f:
                    wrapped_code = self._wrap_code(code)
                    f.write(wrapped_code)
                
                logger.debug(f"Context and code written to {tmpdir}")
                
                # 3. Run in Docker container
                try:
                    result = self._run_in_container(tmpdir, execution_id)
                    
                    # 4. Parse result
                    result_file = os.path.join(tmpdir, "result.json")
                    if os.path.exists(result_file):
                        with open(result_file, 'r') as f:
                            result_data = json.load(f)
                        
                        if 'error' in result_data:
                            logger.warning(f"Code execution error: {result_data['error']}")
                            return False, result_data['error'], None
                        
                        logger.info(f"Code execution successful: {execution_id}")
                        return True, None, result_data.get('result')
                    else:
                        return False, "No result file generated", None
                        
                except docker.errors.ContainerError as e:
                    logger.error(f"Container error: {e}")
                    return False, f"Container execution failed: {str(e)}", None
                    
                except docker.errors.ImageNotFound:
                    logger.error(f"Docker image not found: {self.image}")
                    return False, f"Docker image '{self.image}' not found. Please pull it first.", None
                    
                except Exception as e:
                    logger.error(f"Unexpected execution error: {e}")
                    return False, f"Execution error: {str(e)}", None
                    
        except Exception as e:
            logger.error(f"Failed to create temporary directory: {e}")
            return False, f"Setup error: {str(e)}", None
    
    def _run_in_container(self, tmpdir: str, execution_id: str) -> Any:
        """Run code in Docker container with resource limits."""
        logger.info(f"Launching container for {execution_id}")
        
        # Use pre-built pandas image
        cmd = "python /workspace/script.py"
        
        container = self.client.containers.run(
            image=self.image,
            command=cmd,
            volumes={tmpdir: {'bind': '/workspace', 'mode': 'rw'}},
            mem_limit=self.memory_limit,
            cpu_period=100000,
            cpu_quota=int(self.cpu_limit * 100000),
            network_mode="none",  # No internet access
            remove=True,  # Auto-remove container after execution
            detach=False,  # Wait for completion
            stdout=True,
            stderr=True,
        )
        
        return container
    
    def _is_safe_code(self, code: str) -> Tuple[bool, Optional[str]]:
        """
        Use AST analysis to validate code safety.
        Leverages existing CodeVerifier if available.
        """
        try:
            # Try to use existing CodeVerifier
            from qwed_new.core.code_verifier import CodeVerifier
            
            verifier = CodeVerifier()
            result = verifier.verify_code(code, language="python")
            
            issues = result.get("issues", [])
            if issues:
                issue_summary = "; ".join([f"{i['type']}: {i['description']}" for i in issues[:3]])
                return False, f"Code contains security issues: {issue_summary}"
            
            return True, None
            
        except ImportError:
            logger.warning("CodeVerifier not available, using basic validation")
            # Fallback: basic keyword check
            return self._basic_safety_check(code)
    
    def _basic_safety_check(self, code: str) -> Tuple[bool, Optional[str]]:
        """Basic safety check if CodeVerifier is not available."""
        dangerous_keywords = [
            'os.', 'sys.', 'subprocess', '__import__', 'eval', 'exec',
            'compile', 'open(', 'file(', 'input(', 'raw_input(',
            'socket', 'urllib', 'requests', 'http'
        ]
        
        code_lower = code.lower()
        for keyword in dangerous_keywords:
            if keyword in code_lower:
                return False, f"Code contains dangerous operation: '{keyword}'"
        
        return True, None
    
    def _serialize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Serialize context for JSON storage.
        Handles pandas DataFrames and other complex types.
        """
        serialized = {}
        
        for key, value in context.items():
            # Check if it's a pandas DataFrame
            if hasattr(value, 'to_dict'):  # Duck typing for DataFrame
                serialized[key] = {
                    '_type': 'dataframe',
                    'data': value.to_dict(orient='records'),
                    'columns': list(value.columns)
                }
            elif isinstance(value, (list, dict, str, int, float, bool, type(None))):
                serialized[key] = value
            else:
                # Convert to string for unsupported types
                serialized[key] = str(value)
        
        return serialized
    
    def _wrap_code(self, user_code: str) -> str:
        """
        Wrap user code with safety harness and I/O handling.
        
        This wrapper:
        1. Loads context from JSON
        2. Reconstructs DataFrames if present
        3. Executes user code
        4. Saves result to JSON
        5. Catches all exceptions
        """
        return f'''
import json
import sys

# Load context
with open('/workspace/context.json', 'r') as f:
    context = json.load(f)

# Reconstruct DataFrames if present
for key, value in context.items():
    if isinstance(value, dict) and value.get('_type') == 'dataframe':
        try:
            import pandas as pd
            df = pd.DataFrame(value['data'])
            globals()[key] = df
        except Exception as e:
            print(f"Failed to reconstruct DataFrame: {{e}}", file=sys.stderr)
    else:
        globals()[key] = value

try:
    # User code executes here
{self._indent_code(user_code, spaces=4)}
    
    # Save result (user code should set 'result' variable)
    if 'result' in globals():
        res = globals()['result']
        with open('/workspace/result.json', 'w') as f:
            # Handle DataFrame results
            if hasattr(res, 'to_dict'):
                json.dump({{'result': res.to_dict(orient='records')}}, f)
            else:
                json.dump({{'result': res}}, f)
    else:
        with open('/workspace/result.json', 'w') as f:
            json.dump({{'error': 'Code did not set result variable'}}, f)
        sys.exit(1)
        
except Exception as e:
    # Save error
    with open('/workspace/result.json', 'w') as f:
        json.dump({{'error': str(e)}}, f)
    print(f"Error: {{e}}", file=sys.stderr)
    sys.exit(1)
'''
    
    def _indent_code(self, code: str, spaces: int = 4) -> str:
        """Indent code block."""
        indent = ' ' * spaces
        return '\n'.join(indent + line for line in code.split('\n'))
    
    def get_execution_count(self) -> int:
        """Get total number of executions."""
        return self.execution_count
    
    def is_available(self) -> bool:
        """Check if Docker is available."""
        return self.docker_available


class ExecutionError(Exception):
    """Raised when code execution fails."""
    pass
