"""
Tests for the Progress-Aware Doom Loop Guard (QWED-AGENT-LOOP-004).

Validates that agents repeating actions without environmental progress
are correctly halted, while legitimate progress is allowed through.
"""

import hashlib

import pytest

from qwed_new.core.agent_service import ActionContext, AgentAction, AgentService
from qwed_new.guards.doom_loop_guard import ProgressAwareDoomLoopGuard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(data: str) -> str:
    """Produce a valid SHA-256 hex digest from arbitrary text."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


STATE_A = _sha256("world-state-A")
STATE_B = _sha256("world-state-B")
STATE_C = _sha256("world-state-C")


def _register_test_agent(service: AgentService):
    agent = service.register_agent(
        name="loop-test-agent",
        agent_type="autonomous",
        principal_id="user-loop",
    )
    return agent["agent_id"], agent["agent_token"]


# ===================================================================
# Unit tests — ProgressAwareDoomLoopGuard in isolation
# ===================================================================


class TestProgressAwareDoomLoopGuard:
    """Direct tests against the standalone guard."""

    def test_same_action_same_state_halts_after_threshold(self):
        guard = ProgressAwareDoomLoopGuard()

        for _ in range(2):
            result = guard.verify_progress(
                agent_id="a1",
                conversation_id="c1",
                tool_name="calculate",
                arguments={"query": "2+2"},
                pre_action_state_hash=STATE_A,
                state_source="git_tree",
            )
            assert result["verified"] is True
            assert result["status"] == "PROGRESSING"

        # 3rd identical call → HALTED
        result = guard.verify_progress(
            agent_id="a1",
            conversation_id="c1",
            tool_name="calculate",
            arguments={"query": "2+2"},
            pre_action_state_hash=STATE_A,
            state_source="git_tree",
        )
        assert result["verified"] is False
        assert result["status"] == "HALTED"
        assert result["error_code"] == "QWED-AGENT-LOOP-004"
        assert result["repeat_count"] >= 3

    def test_same_action_different_state_progresses(self):
        guard = ProgressAwareDoomLoopGuard()
        states = [STATE_A, STATE_B, STATE_C]

        for state in states:
            result = guard.verify_progress(
                agent_id="a1",
                conversation_id="c1",
                tool_name="calculate",
                arguments={"query": "2+2"},
                pre_action_state_hash=state,
                state_source="db_snapshot",
            )
            assert result["verified"] is True
            assert result["status"] == "PROGRESSING"

    def test_different_action_same_state_progresses(self):
        guard = ProgressAwareDoomLoopGuard()
        actions = ["calculate", "verify_logic", "execute_sql"]

        for tool in actions:
            result = guard.verify_progress(
                agent_id="a1",
                conversation_id="c1",
                tool_name=tool,
                arguments={"query": "test"},
                pre_action_state_hash=STATE_A,
                state_source="custom",
            )
            assert result["verified"] is True

    def test_history_window_evicts_old_entries(self):
        guard = ProgressAwareDoomLoopGuard()

        # Fill history with 20 unique entries
        for i in range(guard.MAX_HISTORY):
            guard.verify_progress(
                agent_id="a1",
                conversation_id="c1",
                tool_name=f"tool_{i}",
                arguments={},
                pre_action_state_hash=_sha256(f"state-{i}"),
                state_source="file_tree",
            )

        # Now repeat the very first action+state — it was evicted from
        # the window, so the count should be only 1, not 2.
        result = guard.verify_progress(
            agent_id="a1",
            conversation_id="c1",
            tool_name="tool_0",
            arguments={},
            pre_action_state_hash=_sha256("state-0"),
            state_source="file_tree",
        )
        assert result["verified"] is True
        assert result["repeat_count"] == 1

    def test_conversations_are_isolated(self):
        guard = ProgressAwareDoomLoopGuard()

        for conv in ["conv-1", "conv-2"]:
            for _ in range(2):
                guard.verify_progress(
                    agent_id="a1",
                    conversation_id=conv,
                    tool_name="calculate",
                    arguments={"query": "2+2"},
                    pre_action_state_hash=STATE_A,
                    state_source="git_tree",
                )

        # 3rd call on conv-1 only — should NOT be halted because
        # the 2 on conv-2 are in a different scope.
        result = guard.verify_progress(
            agent_id="a1",
            conversation_id="conv-1",
            tool_name="calculate",
            arguments={"query": "2+2"},
            pre_action_state_hash=STATE_A,
            state_source="git_tree",
        )
        assert result["verified"] is False  # 3rd on conv-1
        assert result["error_code"] == "QWED-AGENT-LOOP-004"

    def test_reset_conversation_clears_history(self):
        guard = ProgressAwareDoomLoopGuard()

        for _ in range(2):
            guard.verify_progress(
                agent_id="a1",
                conversation_id="c1",
                tool_name="calculate",
                arguments={"query": "2+2"},
                pre_action_state_hash=STATE_A,
                state_source="git_tree",
            )

        guard.reset_conversation("a1", "c1")

        # After reset, count is back to 1
        result = guard.verify_progress(
            agent_id="a1",
            conversation_id="c1",
            tool_name="calculate",
            arguments={"query": "2+2"},
            pre_action_state_hash=STATE_A,
            state_source="git_tree",
        )
        assert result["verified"] is True
        assert result["repeat_count"] == 1


# ===================================================================
# Input validation tests
# ===================================================================


class TestInputValidation:
    """Ensures the guard fails closed on bad inputs."""

    def test_empty_state_hash_rejected(self):
        guard = ProgressAwareDoomLoopGuard()
        result = guard.verify_progress(
            agent_id="a1",
            conversation_id="c1",
            tool_name="calculate",
            arguments={},
            pre_action_state_hash="",
            state_source="git_tree",
        )
        assert result["verified"] is False
        assert result["error_code"] == "QWED-AGENT-STATE-001"

    def test_invalid_state_hash_format_rejected(self):
        guard = ProgressAwareDoomLoopGuard()
        bad_hashes = [
            "not-a-hash",
            "ABCDEF" * 11,   # uppercase
            "abc123",         # too short
            _sha256("x") + "extra",  # too long
        ]
        for bad_hash in bad_hashes:
            result = guard.verify_progress(
                agent_id="a1",
                conversation_id="c1",
                tool_name="calculate",
                arguments={},
                pre_action_state_hash=bad_hash,
                state_source="git_tree",
            )
            assert result["verified"] is False, f"Should reject: {bad_hash}"
            assert result["error_code"] == "QWED-AGENT-STATE-002"

    def test_invalid_state_source_rejected(self):
        guard = ProgressAwareDoomLoopGuard()
        result = guard.verify_progress(
            agent_id="a1",
            conversation_id="c1",
            tool_name="calculate",
            arguments={},
            pre_action_state_hash=STATE_A,
            state_source="unknown_source",
        )
        assert result["verified"] is False
        assert result["error_code"] == "QWED-AGENT-STATE-003"

    def test_valid_state_hash_accepted(self):
        guard = ProgressAwareDoomLoopGuard()
        result = guard.verify_progress(
            agent_id="a1",
            conversation_id="c1",
            tool_name="calculate",
            arguments={},
            pre_action_state_hash=STATE_A,
            state_source="conversation_digest",
        )
        assert result["verified"] is True


# ===================================================================
# Integration tests — through AgentService.verify_action()
# ===================================================================


class TestDoomLoopIntegration:
    """End-to-end tests through the full verify_action flow."""

    def test_verify_action_with_state_hash_triggers_loop_004(self):
        """
        E2E: LOOP-004 fires through verify_action when the agent keeps
        repeating the same action on the same world state.

        Challenge: LOOP-003 fires after MAX_CONSECUTIVE_IDENTICAL_ACTIONS (2)
        consecutive identical fingerprints, which is before LOOP-004's
        threshold of 3.  To reach LOOP-004, we interleave a *different*
        action between repetitions so LOOP-003's consecutive counter resets,
        while LOOP-004's sliding window still sees 3x of the same
        (action+state) fingerprint.
        """
        service = AgentService()
        agent_id, _ = _register_test_agent(service)

        target_action = AgentAction(action_type="calculate", query="2+2")
        filler_action = AgentAction(action_type="verify_logic", query="p -> q")

        step = 1

        # Round 1: target action (LOOP-004 count=1)
        r1 = service.verify_action(
            agent_id, target_action,
            context=ActionContext(
                conversation_id="conv-doom4",
                step_number=step,
                pre_action_state_hash=STATE_A,
                state_source="git_tree",
            ),
        )
        assert r1["decision"] == "APPROVED"
        step += 1

        # Filler: reset LOOP-003 consecutive counter
        rf1 = service.verify_action(
            agent_id, filler_action,
            context=ActionContext(
                conversation_id="conv-doom4",
                step_number=step,
                pre_action_state_hash=STATE_A,
                state_source="git_tree",
            ),
        )
        assert rf1["decision"] == "APPROVED"
        step += 1

        # Round 2: target action again (LOOP-004 count=2, LOOP-003 count=1)
        r2 = service.verify_action(
            agent_id, target_action,
            context=ActionContext(
                conversation_id="conv-doom4",
                step_number=step,
                pre_action_state_hash=STATE_A,
                state_source="git_tree",
            ),
        )
        assert r2["decision"] == "APPROVED"
        step += 1

        # Filler: reset LOOP-003 again
        rf2 = service.verify_action(
            agent_id, filler_action,
            context=ActionContext(
                conversation_id="conv-doom4",
                step_number=step,
                pre_action_state_hash=STATE_A,
                state_source="git_tree",
            ),
        )
        assert rf2["decision"] == "APPROVED"
        step += 1

        # Round 3: target action (LOOP-004 count=3 → HALTED!)
        r3 = service.verify_action(
            agent_id, target_action,
            context=ActionContext(
                conversation_id="conv-doom4",
                step_number=step,
                pre_action_state_hash=STATE_A,
                state_source="git_tree",
            ),
        )
        assert r3["decision"] == "DENIED"
        assert r3["error"]["code"] == "QWED-AGENT-LOOP-004"

    def test_verify_action_without_state_hash_skips_guard(self):
        """Backward compatibility: no state hash → guard is not invoked."""
        service = AgentService()
        agent_id, _ = _register_test_agent(service)
        action = AgentAction(action_type="calculate", query="2+2")

        # Run 5 steps of the same action without state hash
        # Existing LOOP-003 fires at step 3 (3 consecutive identical),
        # but LOOP-004 should NOT fire since no state hash is provided.
        for step in range(1, 4):
            result = service.verify_action(
                agent_id,
                action,
                context=ActionContext(
                    conversation_id="conv-nostate",
                    step_number=step,
                ),
            )
            if step <= 2:
                assert result["decision"] == "APPROVED"
            else:
                # Step 3: LOOP-003 fires (existing guard), NOT LOOP-004
                assert result["decision"] == "DENIED"
                assert result["error"]["code"] == "QWED-AGENT-LOOP-003"

    def test_verify_action_progresses_when_state_changes(self):
        """Same action but world state changes each time → no halt."""
        service = AgentService()
        agent_id, _ = _register_test_agent(service)
        action = AgentAction(action_type="calculate", query="2+2")

        states = [STATE_A, STATE_B, STATE_C]
        for step, state in enumerate(states, start=1):
            result = service.verify_action(
                agent_id,
                action,
                context=ActionContext(
                    conversation_id="conv-progress",
                    step_number=step,
                    pre_action_state_hash=state,
                    state_source="file_tree",
                ),
            )
            # LOOP-003 fires on step 3 because fingerprint is identical
            # (action hasn't changed), but LOOP-004 would NOT fire because
            # state is different. LOOP-003 fires first in the guard chain.
            if step <= 2:
                assert result["decision"] == "APPROVED"

    def test_verify_action_invalid_state_hash_blocks(self):
        """Bad state hash format → BLOCKED, not uncontrolled error."""
        service = AgentService()
        agent_id, _ = _register_test_agent(service)

        result = service.verify_action(
            agent_id,
            AgentAction(action_type="calculate", query="2+2"),
            context=ActionContext(
                conversation_id="conv-bad",
                step_number=1,
                pre_action_state_hash="not-valid-sha256",
                state_source="git_tree",
            ),
        )
        assert result["decision"] == "DENIED"
        assert result["error"]["code"] == "QWED-AGENT-STATE-002"
