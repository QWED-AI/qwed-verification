"""
QWED Progress-Aware Doom Loop Guard

Detects agents that repeat actions without making environmental progress.
Unlike the existing LOOP-003 (repeated fingerprint) guard, this guard binds
each action to the *world state* at the time it was proposed.  If the agent
takes the exact same action on the exact same unchanged state multiple times,
it is stuck — even if step numbers are advancing normally.

Design principles (from ChatGPT / NotebookLM architecture review):
- Additive to existing guards (LOOP-001/002/003), never replaces them
- SHA-256 fingerprints (not MD5)
- State hash source must be explicitly declared by the caller
- Canonical, deterministic, reproducible state hashes only
"""

import hashlib
import json
import re
import threading
from collections import deque
from typing import Any, Dict, Optional


class ProgressAwareDoomLoopGuard:
    """
    Tracks action+state fingerprints across a sliding window and detects
    when an agent is repeating actions without changing the underlying
    system state (Adaptive Control Error / no-progress doom loop).
    """

    VALID_STATE_SOURCES = frozenset(
        {"file_tree", "db_snapshot", "conversation_digest", "git_tree", "custom"}
    )

    # Only accept lowercase hex SHA-256 hashes (64 chars).
    _SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

    MAX_HISTORY = 20
    NO_PROGRESS_THRESHOLD = 3

    def __init__(self) -> None:
        # Keyed by (agent_id, conversation_id) so conversations are isolated.
        self._histories: Dict[tuple, deque] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_progress(
        self,
        agent_id: str,
        conversation_id: str,
        tool_name: str,
        arguments: dict,
        pre_action_state_hash: str,
        state_source: str,
    ) -> Dict[str, Any]:
        """
        Check whether the proposed action would constitute a no-progress
        doom loop given the current world state.

        Parameters
        ----------
        agent_id : str
            Registered agent identifier.
        conversation_id : str
            Conversation scope for sliding-window isolation.
        tool_name : str
            The action/tool the agent wants to execute.
        arguments : dict
            Deterministic, JSON-serializable action arguments.
        pre_action_state_hash : str
            SHA-256 hex digest representing the world state *before* the
            action runs.  The caller is responsible for computing this
            from a canonical source (git tree hash, DB snapshot, etc.).
        state_source : str
            One of ``VALID_STATE_SOURCES`` — declares how the hash was
            derived so the guard can audit provenance.

        Returns
        -------
        dict
            ``{"verified": bool, "status": str, ...}``
        """
        # ----------------------------------------------------------
        # Input validation — fail closed on bad inputs
        # ----------------------------------------------------------
        error = self._validate_inputs(pre_action_state_hash, state_source)
        if error is not None:
            return error

        # ----------------------------------------------------------
        # Build deterministic fingerprint: action ⊕ world state
        # ----------------------------------------------------------
        try:
            action_payload = json.dumps(
                {"tool": tool_name, "args": self._canonicalize(arguments)},
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            return {
                "verified": False,
                "status": "BLOCKED",
                "error_code": "QWED-AGENT-STATE-004",
                "message": f"Arguments must be deterministic JSON-compatible values: {exc}",
            }
        combined = f"{action_payload}|STATE:{pre_action_state_hash}"
        fingerprint = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        # ----------------------------------------------------------
        # Sliding window: READ-ONLY check (do NOT record yet).
        # The fingerprint is committed only after all downstream
        # checks (budget, risk, verification) pass via commit_progress().
        # ----------------------------------------------------------
        scope_key = (agent_id, conversation_id)

        with self._lock:
            history = self._histories.get(scope_key, deque(maxlen=self.MAX_HISTORY))
            # Count how many times this fingerprint WOULD appear if committed.
            repeat_count = sum(1 for fp in history if fp == fingerprint) + 1

        if repeat_count >= self.NO_PROGRESS_THRESHOLD:
            return {
                "verified": False,
                "status": "HALTED",
                "risk": "NO_PROGRESS_DOOM_LOOP",
                "error_code": "QWED-AGENT-LOOP-004",
                "message": (
                    "Agent is repeating actions without altering the "
                    "underlying system state.  Halted to prevent an "
                    "infinite no-progress loop."
                ),
                "fingerprint": fingerprint,
                "repeat_count": repeat_count,
                "state_source": state_source,
            }

        return {
            "verified": True,
            "status": "PROGRESSING",
            "fingerprint": fingerprint,
            "repeat_count": repeat_count,
            "state_source": state_source,
        }

    def commit_progress(
        self,
        agent_id: str,
        conversation_id: str,
        fingerprint: str,
    ) -> None:
        """
        Record a fingerprint in the sliding window AFTER the action is approved.

        Must only be called when all downstream checks (budget, risk,
        verification) have passed.  This prevents denied actions from
        polluting the history and causing false LOOP-004 triggers.
        """
        scope_key = (agent_id, conversation_id)
        with self._lock:
            history = self._histories.setdefault(
                scope_key, deque(maxlen=self.MAX_HISTORY)
            )
            history.append(fingerprint)

    def reset_conversation(self, agent_id: str, conversation_id: str) -> None:
        """Clear the sliding window for a conversation (e.g. on close)."""
        scope_key = (agent_id, conversation_id)
        with self._lock:
            self._histories.pop(scope_key, None)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_inputs(
        self, state_hash: str, state_source: str
    ) -> Optional[Dict[str, Any]]:
        """Return an error dict if inputs are invalid, else ``None``."""
        if not isinstance(state_hash, str) or not state_hash:
            return {
                "verified": False,
                "status": "BLOCKED",
                "error_code": "QWED-AGENT-STATE-001",
                "message": "pre_action_state_hash is required and must be a non-empty string.",
            }

        if not self._SHA256_PATTERN.match(state_hash):
            return {
                "verified": False,
                "status": "BLOCKED",
                "error_code": "QWED-AGENT-STATE-002",
                "message": (
                    "pre_action_state_hash must be a 64-character lowercase "
                    "hex SHA-256 digest."
                ),
            }

        if not isinstance(state_source, str) or state_source not in self.VALID_STATE_SOURCES:
            return {
                "verified": False,
                "status": "BLOCKED",
                "error_code": "QWED-AGENT-STATE-003",
                "message": (
                    f"state_source must be one of {sorted(self.VALID_STATE_SOURCES)}, "
                    f"got '{state_source}'."
                ),
            }

        return None

    @staticmethod
    def _canonicalize(value: Any) -> Any:
        """Recursively canonicalize a value for deterministic JSON output."""
        if value is None or isinstance(value, (str, bool, int, float)):
            return value
        if isinstance(value, (list, tuple)):
            return [ProgressAwareDoomLoopGuard._canonicalize(v) for v in value]
        if isinstance(value, dict):
            canonicalized = {}
            for k, v in value.items():
                if not isinstance(k, str):
                    raise TypeError(
                        f"Argument dict keys must be strings, got {type(k).__name__}"
                    )
                canonicalized[k] = ProgressAwareDoomLoopGuard._canonicalize(v)
            return {k: canonicalized[k] for k in sorted(canonicalized)}
        raise TypeError(
            f"Unsupported argument type for canonicalization: {type(value).__name__}"
        )
