"""Sandbox outcomes shared by the executor and its callers.

Kept free of the ``docker`` package, which is an optional dependency: a
caller such as SymbolicVerifier imports these names unconditionally and only
loads SecureCodeExecutor (and docker) when it actually needs the sandbox.
"""

# Linux caps a single environment string at 128 KiB (MAX_ARG_STRLEN); inputs
# passed to SecureCodeExecutor.run_isolated() in the environment stay below it.
MAX_ISOLATED_ENV_VALUE_BYTES = 120 * 1024


class ExecutionError(Exception):
    """Raised when code execution fails."""


class SandboxUnavailable(Exception):
    """Raised when a request cannot run in the sandbox at all: no Docker, no
    free slot, a missing image or a daemon error. Callers must fail closed;
    there is no host fallback."""
