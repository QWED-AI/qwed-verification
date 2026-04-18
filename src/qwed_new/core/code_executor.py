"""
Legacy CodeExecutor disabled for fail-closed safety.

This module intentionally hard-blocks the historical raw-exec path. All code
execution must go through SecureCodeExecutor or another explicitly hardened
execution boundary.
"""

from __future__ import annotations

from typing import Any, Final


LEGACY_CODE_EXECUTOR_DISABLED: Final[str] = (
    "CodeExecutor is disabled because raw exec() is not a valid QWED "
    "verification boundary. Use SecureCodeExecutor instead."
)


class CodeExecutor:
    """
    Legacy executor intentionally disabled.

    The previous implementation executed arbitrary Python through raw exec().
    That behavior violated QWED's fail-closed guarantees, so any attempted use
    now raises a deterministic runtime error.
    """

    ALLOWED_GLOBALS: dict[str, Any] = {}

    def execute(self, code: str, df: Any = None) -> str:
        """Fail closed on every attempted execution."""
        raise RuntimeError(LEGACY_CODE_EXECUTOR_DISABLED)
