"""
Secure Code Execution Module for QWED.
OWASP LLM06:2025 - Excessive Agency / Code Execution Defense

Provides sandboxed execution of LLM-generated code with:
- Docker container isolation
- Resource limits (CPU, memory, time)
- Network isolation (no internet access)
- Pre-execution validation using AST analysis
"""

import ast
import docker
from docker.types import LogConfig
import tempfile
import json
import os
import time
import logging
from typing import Any, Dict, Tuple, Optional

from .diagnostics import AdvisoryCheck, DiagnosticResult


logger = logging.getLogger(__name__)
SECURE_RUNTIME_UNAVAILABLE = "SECURE_RUNTIME_UNAVAILABLE"
CONSTRAINT_VERIFIER_UNAVAILABLE = "secure_code_executor.verifier_unavailable"
CONSTRAINT_BASIC_SAFETY_ADVISORY = "secure_code_executor.basic_safety_advisory"
CONSTRAINT_DANGEROUS_PATTERN = "secure_code_executor.dangerous_pattern"

DANGEROUS_KEYWORDS = [
    'os.', 'sys.', 'subprocess', '__import__', 'eval', 'exec',
    'compile', 'open(', 'file(', 'input(', 'raw_input(',
    'socket', 'urllib', 'requests', 'http'
]

# v2 (#336): added posix (what os.system delegates to on POSIX), nt, the
# import/reflection machinery (importlib, ctypes, builtins). pandas/numpy
# remain allowed at their public surface — gadgets through their internals
# are caught at the attribute-chain check below.
_DANGEROUS_MODULE_ROOTS = {"os", "sys", "subprocess", "socket", "urllib", "requests", "http", "posix", "nt", "importlib", "ctypes", "builtins"}
_DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__", "open", "file", "input", "raw_input"}
# OS primitives reachable through module indirection (#336): `system` /
# `popen` via package-internal re-exports, `import_module` via importlib, the
# full exec/spawn family (v and l variants) and fork via posix/nt. Matched on
# bare names and attribute call targets alike.
_DANGEROUS_OS_CALLS = {
    "system", "popen", "import_module",
    "execv", "execve", "execvp", "execvpe",
    "execl", "execle", "execlp", "execlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "fork", "forkpty",
}
_DANGEROUS_CALL_TARGETS = frozenset(_DANGEROUS_BUILTINS | _DANGEROUS_OS_CALLS)


def _strip_python_comments(code: str) -> str:
    """Blank comment and string-literal text while preserving line structure."""
    out = []
    i = 0
    n = len(code)
    while i < n:
        ch = code[i]
        if ch in ('"', "'"):
            i = _skip_string_literal(code, i, out)
            continue
        if ch == '#':
            i = _skip_line_comment(code, i, out)
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _skip_string_literal(code: str, start: int, out: list) -> int:
    """Blank a string literal starting at *start*, returning the next index."""
    n = len(code)
    quote = code[start]
    out.append(' ')
    i = start + 1
    while i < n:
        out.append(' ')
        if code[i] == '\\':
            i += 2
            continue
        i += 1
        if i - 1 != start and code[i - 1] == quote:
            break
    return i


def _skip_line_comment(code: str, start: int, out: list) -> int:
    """Blank a '#' comment up to (not including) the newline."""
    n = len(code)
    i = start
    while i < n and code[i] != '\n':
        out.append(' ')
        i += 1
    return i


def _dangerous_import(node: ast.AST) -> Optional[str]:
    """Return a dangerous module name imported by *node*, or None.

    EVERY dotted segment is checked (#336): the first-segment check let
    `import importlib`, `import posix`, `import ctypes` through because
    their dangerousness IS the first segment the old set simply omitted,
    and future `dangerous.submodule` shapes would slip past a root-only
    match. ImportFrom MEMBER names are checked too (#346 review): the
    gadget `from pandas.io.common import os as safe` binds the real OS
    module under an innocuous alias while the module path itself is
    clean."""
    if isinstance(node, ast.Import):
        names = [a.name for a in node.names]
    elif isinstance(node, ast.ImportFrom) and node.module:
        names = [node.module] + [a.name for a in node.names]
    else:
        return None
    for name in names:
        if any(seg in _DANGEROUS_MODULE_ROOTS for seg in name.split(".")):
            return name
    return None


def _dangerous_attribute(node: ast.AST) -> Optional[str]:
    """Return a dangerous attribute chain, or None.

    EVERY segment of the chain is checked (#336): gadgets reach os/sys
    through package-internal re-exports bound to innocuous aliases — the
    pandas and numpy internals each re-export the OS module — where the
    innermost base is `pd`/`np`, not a dangerous root. A dangerous module
    name anywhere in the chain flags the whole access.

    Known trade-off: a DATA attribute named like a dangerous module (e.g.
    a column accessed as `df.os`) is rejected as well — per-name static
    resolution cannot distinguish it from a gadget, and fail-closed beats
    misclassifying one; use subscript access (`df['os']`) instead."""
    if not isinstance(node, ast.Attribute):
        return None
    parts = []
    value = node
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
        if any(p in _DANGEROUS_MODULE_ROOTS for p in parts):
            return ".".join(reversed(parts))
    return None


def _dangerous_call(node: ast.AST) -> Optional[str]:
    """Return a dangerous call target, or None.

    Beyond the interpreter builtins, the OS-primitive call names (#336) are
    matched on bare names (`system('id')` after `from os import system`) and
    attribute targets (`importlib.import_module('os').system('id')`, whose
    chain root is a Call the attribute matcher cannot resolve)."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name) and func.id in _DANGEROUS_CALL_TARGETS:
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in _DANGEROUS_CALL_TARGETS:
        return func.attr
    return None


def _find_dangerous_pattern(code: str) -> Optional[str]:
    """Return the first dangerous operation keyword present in *code*, or None.

    This is the executor's own defense-in-depth gate (OWASP LLM06), independent
    of the verifier's proof verdict: certain operations are blocklisted for
    execution regardless of whether the code otherwise verifies.

    The scan is AST-aware: it inspects **executable statements** (imports,
    attribute access, and calls) rather than the raw source text, so dangerous
    keywords that merely appear inside comments, docstrings, or string literals
    (e.g. a URL in a docstring) are never treated as a real operation. When the
    code cannot be parsed as Python, a conservative comment-and-string-stripped
    scan is used so the gate still fails closed.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _find_dangerous_pattern_fallback(code)

    for node in ast.walk(tree):
        check = _dangerous_import(node) or _dangerous_attribute(node) or _dangerous_call(node)
        if check:
            return check
    return None


def _find_dangerous_pattern_fallback(code: str) -> Optional[str]:
    """Fail-closed substring scan on comment/string-stripped Python source."""
    code_lower = _strip_python_comments(code).lower()
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in code_lower:
            return keyword
    return None

def _sanitize_log_msg(msg: str) -> str:
    """Strip newline characters to prevent log injection."""
    return str(msg).replace('\n', ' ').replace('\r', ' ')


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
        self.client = None
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
        # #338: process count is the last kernel resource the container
        # config left unbounded — a gate-passing fork bomb allocates host
        # PIDs up to kernel.pid_max for the whole execution window.
        self.pids_limit = 128
        # #339: result.json read-back cap. json.load reads the whole file
        # plus the decoded value into this process; gate-passing code can
        # multiply references under the container memory cap to grow the
        # on-disk JSON unboundedly.
        self.max_result_bytes = 2 * 1024 * 1024
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
        if not self.is_available():
            return False, SECURE_RUNTIME_UNAVAILABLE, None
        
        # 1. Pre-execution validation using AST
        safety = self._is_safe_code(code)
        if not safety.is_verified or safety.developer_fields.get("is_valid") is not True:
            logger.warning("Code failed safety check: %s", safety.agent_message)
            return False, f"Code safety validation failed: {safety.agent_message}", None
        
        self.execution_count += 1
        execution_id = f"exec_{self.execution_count}"
        
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
                    self._run_in_container(tmpdir, execution_id)
                    
                    # 4. Parse result
                    result_file = os.path.join(tmpdir, "result.json")
                    if os.path.exists(result_file):
                        # #339: size-check BEFORE reading — json.load holds the
                        # whole file plus the decoded value in this process,
                        # parsed synchronously on the event loop. The wrapper
                        # enforces the same cap, so reaching this branch with
                        # an oversized file means the cap was bypassed.
                        if os.path.getsize(result_file) > self.max_result_bytes:
                            logger.warning("Result file exceeds size cap for %s", execution_id)
                            return False, "Result exceeds maximum allowed size", None
                        with open(result_file, 'r') as f:
                            result_data = json.load(f)
                        
                        if 'error' in result_data:
                            # Log a static message (S5145: don't log user-controlled data)
                            logger.warning("Code execution returned an error for %s", execution_id)
                            return False, _sanitize_log_msg(str(result_data['error'])), None
                        
                        logger.info(f"Code execution successful: {execution_id}")
                        return True, None, result_data.get('result')
                    else:
                        return False, "No result file generated", None
                        
                except docker.errors.ContainerError as e:
                    logger.exception("Container execution failed")
                    return False, f"Container execution failed: {e!s}", None
                    
                except docker.errors.ImageNotFound:
                    safe_image = _sanitize_log_msg(str(self.image))
                    logger.exception("Docker image not found: %s", safe_image)
                    return False, f"Docker image '{safe_image!s}' not found. Please pull it first.", None
                    
                except Exception as e:
                    logger.exception("Unexpected execution error")
                    return False, f"Execution error: {e!s}", None
                    
        except OSError as e:
            logger.exception("Failed to create temporary directory")
            return False, f"Setup error: {e!s}", None
    
    def _run_in_container(self, tmpdir: str, execution_id: str) -> Any:
        """Run code in Docker container with resource limits."""
        logger.info(f"Launching container for {execution_id}")
        
        # Use pre-built pandas image
        cmd = "python /workspace/script.py"

        # Create first, start INSIDE the cleanup scope (#351 review): the SDK's
        # containers.run() creates the container and only then starts it, so a
        # start failure raised before our finally existed and leaked the created
        # container. With create() + start(), the finally covers the whole
        # post-creation lifecycle. One kwargs dict shared by both create calls
        # (CodeRabbit: a limit added to only one copy would silently miss the
        # pull-retry path).
        create_kwargs = {
            "image": self.image,
            "command": cmd,
            "volumes": {tmpdir: {'bind': '/workspace', 'mode': 'rw'}},
            "mem_limit": self.memory_limit,
            "cpu_period": 100000,
            "cpu_quota": int(self.cpu_limit * 100000),
            "network_mode": "none",  # No internet access
            # #338: the daemon's default json-file driver is unbounded —
            # sandbox stdout grows on the daemon HOST, outside every
            # container resource limit, until the disk fills.
            "log_config": LogConfig(
                type=LogConfig.types.JSON,
                config={"max-size": "10m", "max-file": "1"},
            ),
            "pids_limit": self.pids_limit,
        }
        try:
            container = self.client.containers.create(**create_kwargs)
        except docker.errors.ImageNotFound:
            # containers.run() auto-pulled a missing image; create() does not
            # (CI never pre-pulls the sandbox image). Pull, then retry — the
            # 404 means no container was created, so no cleanup is owed.
            logger.info("Sandbox image %s missing; pulling", self.image)
            self.client.images.pull(self.image)
            container = self.client.containers.create(**create_kwargs)

        try:
            container.start()
            try:
                # Wait for completion with timeout
                # Note: docker-py wait() timeout is in seconds since v3.0.0
                container.wait(timeout=self.timeout)
            except Exception as e:
                logger.warning(f"Container timeout or error: {e}")
                try:
                    container.kill()
                except Exception:
                    logger.debug("Failed to kill container after timeout", exc_info=True)
                raise ExecutionError(f"Execution timed out after {self.timeout}s") from e
            return container
        finally:
            # #338: every execution must leave no container behind — a stopped
            # container keeps its full json-file log on the daemon host
            # indefinitely. Result read-back uses the mounted result.json,
            # never container logs, so removal here is safe.
            #
            # Cleanup failure is warn-only, NOT fail-closed (deliberate
            # conflict resolution between three review bots on PR #351):
            # CodeRabbit wanted fail-closed (CWE-400), Greptile wanted a
            # retry/reaper, Sentry HIGH correctly noted a removal failure
            # does not remove the leak either way — raising would only
            # discard a validly computed verification result. Resolution:
            # one automatic retry (most removal failures are transient
            # daemon races right after wait/kill), then a loud warning as
            # the operator signal — alert on it; a daemon-side reaper
            # (label-filtered `docker container prune`) remains follow-up
            # material if leak accumulation is ever observed.
            try:
                try:
                    container.remove(force=True)
                except Exception:
                    time.sleep(0.5)
                    container.remove(force=True)
            except Exception:
                logger.warning(
                    "Failed to remove sandbox container for %s", execution_id,
                    exc_info=True,
                )
    
    def _is_safe_code(self, code: str) -> DiagnosticResult:
        """
        Use AST analysis to validate code safety.
        Leverages existing CodeVerifier if available.
        """
        try:
            # Try to use existing CodeVerifier
            from qwed_new.core.code_verifier import CodeVerifier

            verifier = CodeVerifier()
            result = verifier.verify_code(code, language="python")

        except ImportError:
            logger.error("CodeVerifier not available; blocking execution")
            return self._build_fail_closed_safety_denial(code)
        except Exception as e:
            logger.error(
                "CodeVerifier failed during safety validation; blocking execution: %s",
                _sanitize_log_msg(str(e)),
            )
            return self._build_fail_closed_safety_denial(code)

        # Defense-in-depth (OWASP LLM06): blocklist dangerous operations even
        # when the verifier would otherwise pass them (import os, subprocess,
        # open(), etc.). Proof the code is safe is independent of refusal to
        # execute patterns the executor is configured to never run.
        dangerous = _find_dangerous_pattern(code)
        if dangerous is not None:
            return DiagnosticResult.blocked(
                agent_message=f"Code contains dangerous operation: '{dangerous}'",
                developer_fields={
                    "constraint_id": CONSTRAINT_DANGEROUS_PATTERN,
                    "is_valid": False,
                    "is_safe": False,
                    "reason": f"Code contains dangerous operation: '{dangerous}'",
                },
            )

        return result

    def _build_fail_closed_safety_denial(self, code: str) -> DiagnosticResult:
        """Return a deterministic fail-closed denial when CodeVerifier cannot be used.

        Returns an UNVERIFIABLE DiagnosticResult with the basic safety scan
        recorded as advisory / developer metadata (never as a verdict).
        """
        advisory_check = self._basic_safety_check(code)
        return DiagnosticResult.unverifiable(
            agent_message="Code safety verification unavailable",
            developer_fields={
                "constraint_id": CONSTRAINT_VERIFIER_UNAVAILABLE,
                "advisory_checks": [advisory_check.to_dict()],
            },
        )

    def _basic_safety_check(self, code: str) -> AdvisoryCheck:
        """Basic safety check if CodeVerifier is not available (advisory only).

        The result is an advisory check: it never influences the verdict or
        proof_ref and is surfaced to developers/auditors for review only.
        """
        reason = _find_dangerous_pattern(code)
        return AdvisoryCheck(
            name="basic_safety",
            advisory_only=True,
            constraint_id=CONSTRAINT_BASIC_SAFETY_ADVISORY,
            details={"is_safe": reason is None, "reason": reason},
        )
    
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
import numpy as np

# Custom encoder for NumPy types
class QwedEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer): return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.ndarray): return obj.tolist()
        return super().default(obj)

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
        # Handle DataFrame results
        if hasattr(res, 'to_dict'):
            payload = {{'result': res.to_dict(orient='records')}}
        else:
            payload = {{'result': res}}
        # #339: stream-serialize and abort at the cap. A one-shot json.dumps
        # would fully materialize the escaped expansion in container memory
        # before any size check could run; iterencode emits lazily so memory
        # stays bounded. ensure_ascii keeps len(chunk) == bytes on disk.
        total = 0
        exceeded = False
        with open('/workspace/result.json', 'w') as f:
            for chunk in QwedEncoder().iterencode(payload):
                total += len(chunk)
                # a string value is emitted as a single token — reject it
                # immediately rather than materializing it in full
                if total > {self.max_result_bytes} or len(chunk) > {self.max_result_bytes}:
                    exceeded = True
                    break
                f.write(chunk)
        if exceeded:
            with open('/workspace/result.json', 'w') as f:
                f.write(json.dumps({{'error': 'Result exceeds maximum allowed size'}}))
            print('Result exceeds maximum allowed size', file=sys.stderr)
            sys.exit(1)
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
        """Check if Docker is currently available."""
        if self.client is None:
            return False

        try:
            self.client.ping()
            return True
        except Exception as e:
            logger.warning("Docker availability check failed: %s", e)
            return False


class ExecutionError(Exception):
    """Raised when code execution fails."""
    pass
