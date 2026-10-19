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
import requests
import urllib3
from docker.types import LogConfig
import tempfile
import json
import math
import os
import re
import threading
import time
import logging
from typing import Any, Dict, List, Tuple, Optional

from .diagnostics import AdvisoryCheck, DiagnosticResult
# Re-exported: callers import these from here as well as from sandbox_errors.
from .sandbox_errors import (  # noqa: F401
    MAX_ISOLATED_ENV_VALUE_BYTES,
    ExecutionError,
    SandboxUnavailable,
)


logger = logging.getLogger(__name__)

# #341: hard bound on every Docker daemon API call (ping/create/start/kill)
_DOCKER_API_TIMEOUT_SECONDS = 30

# #446: a process-wide admission bound on how many sandbox containers run at
# once. Without it, N concurrent requests start N containers and can exhaust
# host memory/PIDs/CPU. The semaphore is shared across every SecureCodeExecutor
# instance (consensus creates one per request), so the bound is global to the
# worker process. A request that cannot get a slot within the acquire timeout is
# rejected rather than spawning another container.
def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 1 else default


def _env_timeout(name: str, default: float) -> float:
    # A finite, positive timeout only. A non-finite value (e.g. nan) would make
    # semaphore.acquire(timeout=...) poll forever instead of rejecting, so an
    # invalid value falls back to the default — fail closed on the bound.
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if math.isfinite(value) and value > 0 else default


_SANDBOX_MAX_CONCURRENT = _env_int("QWED_SANDBOX_MAX_CONCURRENT", 4)
# Default kept well under the ~30s request deadline on the consensus path, so
# under capacity pressure a request is cleanly rejected (SANDBOX_CAPACITY_REACHED)
# before the outer deadline fires (Sentry on PR #448). Passing the exact
# remaining request budget down to acquire() is a larger change, deferred.
_SANDBOX_ACQUIRE_TIMEOUT_SECONDS = _env_timeout("QWED_SANDBOX_ACQUIRE_TIMEOUT", 10.0)
_sandbox_slots = threading.BoundedSemaphore(_SANDBOX_MAX_CONCURRENT)
SANDBOX_CAPACITY_REACHED = "Sandbox capacity reached — retry shortly."

# Container settings for run_isolated(): analysis tools that import untrusted
# code (CrossHair, #431) get no network, a read-only root, no Linux
# capabilities, no privilege escalation and an unprivileged user. Nothing on
# the host is mounted: inputs arrive in the environment, the only writable
# path is a private tmpfs owned by that user, and the output is read from the
# container log.
_ISOLATED_USER = "65534"
_ISOLATED_SCRATCH = "/workspace"
_ISOLATED_HARDENING = {
    "read_only": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges"],
    "user": f"{_ISOLATED_USER}:{_ISOLATED_USER}",
    "tmpfs": {
        _ISOLATED_SCRATCH: (
            f"rw,noexec,nosuid,nodev,size=16m,"
            f"uid={_ISOLATED_USER},gid={_ISOLATED_USER},mode=0700"
        ),
    },
    "working_dir": _ISOLATED_SCRATCH,
}
_ISOLATED_BASE_ENVIRONMENT = {
    "HOME": _ISOLATED_SCRATCH,
    "TMPDIR": _ISOLATED_SCRATCH,
    "PYTHONDONTWRITEBYTECODE": "1",
}
_DEFAULT_ISOLATED_OUTPUT_BYTES = 64 * 1024

# The image execute() runs code in (#322). A tag such as "slim" can be moved to
# different content at any time; a digest cannot, so the sandbox only ever
# runs the exact image that was reviewed. This is amancevice/pandas:slim as
# published on 2026-08-10. QWED_SANDBOX_IMAGE may name another image, but
# only by digest; any other value is refused and the pinned image is used.
SANDBOX_IMAGE = (
    "amancevice/pandas@sha256:9257b88909bddf60c8a85b06d572fc6dfc708ea9c8a3c3dc2149e312d57f91e3"
)
SANDBOX_IMAGE_ENV = "QWED_SANDBOX_IMAGE"
_DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def _sandbox_image() -> str:
    override = os.environ.get(SANDBOX_IMAGE_ENV, "").strip()
    if not override:
        return SANDBOX_IMAGE
    if _DIGEST_REFERENCE.fullmatch(override):
        return override
    logger.error(
        "%s must name an image by digest (name@sha256:<64 hex>); using the pinned sandbox image",
        SANDBOX_IMAGE_ENV,
    )
    return SANDBOX_IMAGE


# execute() hardening (#322), on top of the network, memory, CPU and PID
# limits: a read-only root, no Linux capabilities, no privilege escalation,
# and never root inside the container. /workspace is the host's private
# exchange directory (inputs in, result.json out); HOME and TMPDIR point
# there because nothing else is writable.
_EXECUTE_HARDENING = {
    "read_only": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges"],
    "environment": {
        "HOME": "/workspace",
        "TMPDIR": "/workspace",
        "MPLCONFIGDIR": "/workspace",
        "PYTHONDONTWRITEBYTECODE": "1",
    },
}
_UNPRIVILEGED_UID = 65534

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
    # Stopgap for the call-name gap (GHSA-j3x4). The structural fix is the
    # isolated execution namespace in SecureCodeExecutor._wrap_code; these just
    # close the obvious holes in the static gate too.
    "posix_spawn", "posix_spawnp",
    "fork", "forkpty",
    "Popen",
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

def _is_wait_timeout(error: BaseException) -> bool:
    """True when ``container.wait`` gave up because the container ran past its
    timeout. docker-py surfaces that as a requests timeout, or, over the Unix
    socket adapter, as a ConnectionError wrapping urllib3's ReadTimeoutError;
    any other error is the daemon failing, not the container running long."""
    if isinstance(error, requests.exceptions.Timeout):
        return True
    if not isinstance(error, requests.exceptions.ConnectionError):
        return False
    for arg in error.args:
        # The adapter wraps the read timeout directly, or in a MaxRetryError
        # whose reason is the timeout; only an untyped cause falls back to
        # the message text.
        if isinstance(arg, urllib3.exceptions.ReadTimeoutError):
            return True
        if isinstance(getattr(arg, "reason", None), urllib3.exceptions.ReadTimeoutError):
            return True
        if isinstance(arg, str) and "timed out" in arg.lower():
            return True
    return False


def _read_capped_logs(container: Any, max_bytes: int, *, stdout: bool, stderr: bool) -> str:
    """One stream of the container log, read as a stream and stopped at
    ``max_bytes`` so a noisy container never loads its whole log (up to the
    10 MB json-file cap) into this process."""
    stream = container.logs(stdout=stdout, stderr=stderr, stream=True, follow=False)
    chunks: List[bytes] = []
    size = 0
    truncated = False
    try:
        for chunk in stream:
            room = max_bytes - size
            if len(chunk) > room:
                chunks.append(chunk[:room])
                truncated = True
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            close()
    output = b"".join(chunks).decode("utf-8", errors="replace")
    return output + "\n[output truncated]" if truncated else output


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
            # #341: without a timeout, ping/create/start/kill calls to the
            # Docker daemon are unbounded — only container.wait was bounded.
            self.client = docker.from_env(timeout=_DOCKER_API_TIMEOUT_SECONDS)
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

        # Docker image to use: pinned by digest (#322).
        self.image = _sandbox_image()
        self._rootless: Optional[bool] = None
    
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
                # All three files are read by python3 inside the container, which
                # decodes source as UTF-8 (PEP 263 default). Write UTF-8 here so a
                # non-UTF-8 host locale can't corrupt a non-ASCII byte on the way
                # in.
                # Write context data
                context_file = os.path.join(tmpdir, "context.json")
                with open(context_file, 'w', encoding='utf-8') as f:
                    # Serialize context (handle DataFrames if present)
                    serializable_context = self._serialize_context(context)
                    json.dump(serializable_context, f)

                # The untrusted user code runs in an ISOLATED namespace, not
                # inline in the harness module scope (GHSA-j3x4). Write it to its
                # own file so the harness can exec it with a restricted builtins
                # set and a module allowlist; the harness (script.py) keeps full
                # builtins to load context and serialize the result.
                with open(os.path.join(tmpdir, "user_code.py"), 'w', encoding='utf-8') as f:
                    f.write(code)

                # Write the trusted harness.
                code_file = os.path.join(tmpdir, "script.py")
                with open(code_file, 'w', encoding='utf-8') as f:
                    wrapped_code = self._wrap_code(code)
                    f.write(wrapped_code)
                
                logger.debug(f"Context and code written to {tmpdir}")
                self._hand_workspace_to_container_user(tmpdir)

                # 3. Run in Docker container, under the process-wide sandbox
                # concurrency bound (#446).
                try:
                    if not self._run_in_container_bounded(tmpdir, execution_id):
                        logger.warning("Sandbox capacity reached, rejecting %s", execution_id)
                        return False, SANDBOX_CAPACITY_REACHED, None

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
    
    def _is_rootless_daemon(self) -> bool:
        """True for a rootless Docker daemon, whose container root is the host
        user itself and holds no host privilege. Asked once per executor."""
        if getattr(self, "_rootless", None) is None:
            try:
                options = self.client.info().get("SecurityOptions") or []
                self._rootless = isinstance(options, list) and any(
                    "name=rootless" in str(option) for option in options
                )
            except Exception:
                self._rootless = False
        return self._rootless

    def _container_user(self) -> str:
        """The uid:gid the execute() container runs as; never a privileged root.

        The exchange directory is the host's private 0700 temp directory, so
        the container runs as its owner: the host user when this process is
        not root, the unprivileged 65534 when it is (execute() hands the
        directory to 65534 first). A rootless daemon maps the container's root
        to the host user, so there root is the owner and unprivileged; any
        other uid would be remapped away from it. Docker Desktop (no getuid)
        shares the folder with every container user.
        """
        getuid = getattr(os, "getuid", None)
        if getuid is None:
            return f"{_UNPRIVILEGED_UID}:{_UNPRIVILEGED_UID}"
        if self._is_rootless_daemon():
            return "0:0"
        uid = getuid()
        if uid == 0:
            return f"{_UNPRIVILEGED_UID}:{_UNPRIVILEGED_UID}"
        return f"{uid}:{os.getgid()}"

    def _hand_workspace_to_container_user(self, tmpdir: str) -> None:
        """When this process is root (and the daemon is not rootless), give the
        private exchange directory to the unprivileged container user, so it
        stays 0700 instead of being opened to every local user."""
        getuid = getattr(os, "getuid", None)
        if getuid is None or getuid() != 0 or self._is_rootless_daemon():
            return
        os.chown(tmpdir, _UNPRIVILEGED_UID, _UNPRIVILEGED_UID)
        for name in os.listdir(tmpdir):
            os.chown(os.path.join(tmpdir, name), _UNPRIVILEGED_UID, _UNPRIVILEGED_UID)

    def _run_in_container_bounded(self, tmpdir: str, execution_id: str) -> bool:
        """Run the container under the process-wide sandbox slot (#446).

        Returns False if no slot was available within the acquire timeout (the
        caller rejects the request). Otherwise runs the container and returns
        True; container errors propagate to the caller. The slot covers the whole
        container lifetime and is released once the container is confirmed
        removed; if removal could not be confirmed the slot is intentionally held,
        because a leaked container still consumes resources (fail closed).
        """
        if not _sandbox_slots.acquire(timeout=_SANDBOX_ACQUIRE_TIMEOUT_SECONDS):
            return False
        # Default: nothing leaked (released). Only a container that was created
        # and could not be removed sets leaked=True; a failure before creation
        # leaks nothing, so the slot frees.
        cleanup_status: Dict[str, Any] = {"leaked": False}
        try:
            self._run_in_container(tmpdir, execution_id, cleanup_status)
        finally:
            if cleanup_status["leaked"]:
                logger.error(
                    "Holding sandbox slot for %s: container removal unconfirmed",
                    execution_id,
                )
            else:
                _sandbox_slots.release()
        return True

    def _remove_container(self, container, execution_id: str) -> bool:
        """Force-remove the container, with one retry. Returns True if it is
        confirmed gone, False if removal failed (the container may still run).

        A NotFound on either attempt counts as confirmed gone — the container is
        already removed (for example the first call removed it but its response
        timed out), so the slot is safe to release."""
        try:
            container.remove(force=True)
            return True
        except docker.errors.NotFound:
            return True
        except Exception:
            time.sleep(0.5)
        try:
            container.remove(force=True)
            return True
        except docker.errors.NotFound:
            return True
        except Exception:
            logger.warning(
                "Failed to remove sandbox container for %s", execution_id,
                exc_info=True,
            )
            return False

    def _run_in_container(self, tmpdir: str, execution_id: str, cleanup_status: Optional[Dict[str, Any]] = None) -> Any:
        """Run code in Docker container with resource limits.

        cleanup_status, if given, receives {'removed': bool} so the caller can
        hold the concurrency slot when a container could not be removed (#446)."""
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
            # #322: read-only root, no capabilities, never root.
            **_EXECUTE_HARDENING,
            "user": self._container_user(),
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
            #
            # #446: the removal outcome is reported so the caller holds the
            # concurrency slot when the container could not be confirmed gone —
            # a leaked container still consumes host resources, so admitting a
            # replacement would exceed the bound (fail closed on the slot).
            removed = self._remove_container(container, execution_id)
            if cleanup_status is not None and not removed:
                cleanup_status["leaked"] = True
    
    def run_isolated(
        self,
        command: List[str],
        *,
        image: str,
        timeout: float,
        environment: Optional[Dict[str, str]] = None,
        max_output_bytes: int = _DEFAULT_ISOLATED_OUTPUT_BYTES,
    ) -> Tuple[int, str, str]:
        """Run ``command`` in a hardened container.

        For analysis tools that import, and therefore execute, untrusted code
        (#431). The container has no network, a read-only root, no
        capabilities, no privilege escalation and runs as an unprivileged
        user (see ``_ISOLATED_HARDENING``), under the same memory, CPU, PID
        and process-wide concurrency bounds as ``execute``. Nothing on the
        host is mounted or written: inputs travel in ``environment`` (each
        value at most ``MAX_ISOLATED_ENV_VALUE_BYTES``), and the command's
        only writable path is its working directory, a private tmpfs. The
        image is never pulled: it must already exist on the daemon.

        Returns ``(exit_code, stdout, stderr)``, each stream of the container
        log read separately and capped at ``max_output_bytes``. Raises ``SandboxUnavailable`` when the
        run cannot happen in the sandbox (no Docker, no free slot, missing
        image, daemon or connection error), ``ExecutionError`` when it
        exceeds ``timeout`` and ``ValueError`` for an oversized input. There
        is no host fallback.
        """
        environment = dict(environment or {})
        for name, value in environment.items():
            if len(str(value).encode("utf-8")) > MAX_ISOLATED_ENV_VALUE_BYTES:
                raise ValueError(f"Isolated input {name} exceeds {MAX_ISOLATED_ENV_VALUE_BYTES} bytes")
        if not self.is_available():
            raise SandboxUnavailable(SECURE_RUNTIME_UNAVAILABLE)

        self.execution_count += 1
        execution_id = f"isolated_{self.execution_count}"
        create_kwargs = {
            "image": image,
            "command": list(command),
            "environment": {**_ISOLATED_BASE_ENVIRONMENT, **environment},
            "mem_limit": self.memory_limit,
            "cpu_period": 100000,
            "cpu_quota": int(self.cpu_limit * 100000),
            "network_mode": "none",
            "log_config": LogConfig(
                type=LogConfig.types.JSON,
                config={"max-size": "10m", "max-file": "1"},
            ),
            "pids_limit": self.pids_limit,
            **_ISOLATED_HARDENING,
        }
        if not _sandbox_slots.acquire(timeout=_SANDBOX_ACQUIRE_TIMEOUT_SECONDS):
            raise SandboxUnavailable(SANDBOX_CAPACITY_REACHED)
        cleanup_status: Dict[str, Any] = {"leaked": False}
        try:
            return self._run_isolated_container(
                create_kwargs, execution_id, timeout, max_output_bytes, cleanup_status
            )
        except docker.errors.ImageNotFound as e:
            raise SandboxUnavailable(
                f"Sandbox image '{_sanitize_log_msg(image)}' is not available on the Docker daemon"
            ) from e
        except (docker.errors.DockerException, requests.exceptions.RequestException) as e:
            # docker-py wraps HTTP status errors in DockerException but lets
            # transport failures (the daemon socket dropping after ping) through
            # as requests exceptions; both mean the sandbox could not run.
            raise SandboxUnavailable(f"Sandbox runtime error: {_sanitize_log_msg(e)}") from e
        finally:
            if cleanup_status["leaked"]:
                logger.error(
                    "Holding sandbox slot for %s: container removal unconfirmed",
                    execution_id,
                )
            else:
                _sandbox_slots.release()

    def _run_isolated_container(
        self,
        create_kwargs: Dict[str, Any],
        execution_id: str,
        timeout: float,
        max_output_bytes: int,
        cleanup_status: Dict[str, Any],
    ) -> Tuple[int, str, str]:
        """Create, start and wait for one isolated container; read its exit
        code and capped stdout and stderr before it is removed (the same create/start/
        remove lifecycle as ``_run_in_container``, which stays untouched)."""
        container = self.client.containers.create(**create_kwargs)
        try:
            container.start()
            try:
                wait_result = container.wait(timeout=timeout)
            except Exception as e:
                try:
                    container.kill()
                except Exception:
                    logger.debug("Failed to kill isolated container", exc_info=True)
                if _is_wait_timeout(e):
                    raise ExecutionError(f"Execution timed out after {timeout}s") from e
                raise  # a daemon error, not a timeout: run_isolated reports it as unavailable
            status = wait_result.get("StatusCode") if isinstance(wait_result, dict) else None
            exit_code = status if isinstance(status, int) else -1
            return (
                exit_code,
                _read_capped_logs(container, max_output_bytes, stdout=True, stderr=False),
                _read_capped_logs(container, max_output_bytes, stdout=False, stderr=True),
            )
        finally:
            if not self._remove_container(container, execution_id):
                cleanup_status["leaked"] = True

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
        """Build the trusted harness that runs the untrusted user code in an
        ISOLATED namespace (GHSA-j3x4).

        The harness keeps full builtins (it loads context and serializes the
        result), but the user code — read from user_code.py — is exec'd in a
        namespace whose ``__builtins__`` is a capability allowlist and whose
        ``__import__`` permits only a safe set of modules. The static gates key
        on identifier syntax and can be defeated (names assembled from string
        literals, ``getattr`` with string constants, ``sys.modules``
        re-acquisition, stored references); once ``eval``/``exec``/``getattr``/
        ``vars``/``__import__``/``sys.modules`` and the os/subprocess/socket/…
        modules are simply absent at runtime, those bypasses reach nothing.

        ``user_code`` is accepted for signature compatibility but is NOT inlined;
        it is written to user_code.py by the caller and read back here.
        """
        return f'''
import json
import sys
import builtins as _builtins
import numpy as np
try:
    import pandas as pd
except Exception:
    pd = None

class QwedEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer): return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.ndarray): return obj.tolist()
        return super().default(obj)

# --- capability allowlist (GHSA-j3x4) -------------------------------------
# Only these modules may be imported by the executed code; everything that
# reaches a process/file/network/reflection primitive is absent.
_ALLOWED_MODULES = {{
    "numpy", "pandas", "scipy", "sklearn", "statsmodels", "patsy",
    "math", "cmath", "statistics", "decimal", "fractions", "random",
    "datetime", "json", "re", "collections", "itertools", "functools",
    "operator", "array", "bisect", "heapq", "string", "typing",
}}
# Safe builtins only. Absent on purpose: eval, exec, compile, __import__
# (replaced by a guarded import below), getattr, setattr, delattr, vars,
# globals, locals, open, input, memoryview — the reflection and
# code/module-acquisition capabilities the bypasses depend on.
_SAFE_BUILTIN_NAMES = (
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
    "callable", "chr", "complex", "dict", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "hash", "hex", "int", "isinstance",
    "issubclass", "iter", "len", "list", "map", "max", "min", "next", "oct",
    "ord", "pow", "print", "range", "repr", "reversed", "round", "set",
    "slice", "sorted", "str", "sum", "tuple", "type", "zip",
    "True", "False", "None",
    "Exception", "ArithmeticError", "ZeroDivisionError", "OverflowError",
    "ValueError", "TypeError", "KeyError", "IndexError", "AttributeError",
    "RuntimeError", "StopIteration", "NotImplementedError", "FloatingPointError",
)
_safe_builtins = {{}}
for _n in _SAFE_BUILTIN_NAMES:
    if hasattr(_builtins, _n):
        _safe_builtins[_n] = getattr(_builtins, _n)

_real_import = _builtins.__import__
def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = name.split(".")[0] if name else name
    if level != 0 or root not in _ALLOWED_MODULES:
        raise ImportError("import of %r is not permitted in the sandbox (GHSA-j3x4)" % (name,))
    return _real_import(name, globals, locals, fromlist, level)
_safe_builtins["__import__"] = _guarded_import

# Isolated namespace for the executed code. Pre-bind the scientific modules the
# generated code uses (np/pd) so it need not import them; nothing dangerous.
_sandbox = {{"__builtins__": _safe_builtins, "np": np, "numpy": np}}
if pd is not None:
    _sandbox["pd"] = pd
    _sandbox["pandas"] = pd

# Load context (trusted harness, full builtins) into the sandbox namespace.
with open('/workspace/context.json', 'r') as f:
    context = json.load(f)
for key, value in context.items():
    if isinstance(value, dict) and value.get('_type') == 'dataframe':
        if pd is None:
            print("pandas unavailable; cannot reconstruct DataFrame", file=sys.stderr)
            continue
        try:
            _sandbox[key] = pd.DataFrame(value['data'])
        except Exception as e:
            print(f"Failed to reconstruct DataFrame: {{e}}", file=sys.stderr)
    else:
        _sandbox[key] = value

# Read and run the untrusted user code in the isolated namespace.
with open('/workspace/user_code.py', 'r') as f:
    _user_src = f.read()

try:
    exec(compile(_user_src, 'user_code.py', 'exec'), _sandbox)

    # Save result (user code should set 'result').
    if 'result' in _sandbox:
        res = _sandbox['result']
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


