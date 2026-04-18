from unittest.mock import MagicMock

from qwed_new.core.tool_approval import ToolApprovalSystem


def _build_session():
    session = MagicMock()
    session.add = MagicMock()
    session.commit = MagicMock()
    session.refresh = MagicMock()
    session.get = MagicMock()
    return session


def test_safe_operation_is_auto_approved():
    approval = ToolApprovalSystem()
    session = _build_session()

    approved, blocked_reason, tool_call = approval.approve_tool_call(
        session=session,
        agent_id=1,
        tool_name="search_web",
        tool_params={"q": "qwed"},
    )

    assert approved is True
    assert blocked_reason is None
    assert tool_call.approved is True
    assert tool_call.approved_by == "automatic"
    session.add.assert_called_once_with(tool_call)
    session.commit.assert_called_once()
    session.refresh.assert_called_once_with(tool_call)


def test_dangerous_operation_requires_manual_approval():
    approval = ToolApprovalSystem()
    session = _build_session()

    approved, blocked_reason, tool_call = approval.approve_tool_call(
        session=session,
        agent_id=1,
        tool_name="delete_database",
        tool_params={"database": "prod"},
    )

    assert approved is False
    assert "requires manual approval" in blocked_reason
    assert tool_call.approved is False
    assert tool_call.approved_by is None


def test_unknown_low_risk_operation_is_blocked():
    approval = ToolApprovalSystem()
    session = _build_session()

    approved, blocked_reason, tool_call = approval.approve_tool_call(
        session=session,
        agent_id=1,
        tool_name="list_dashboards",
        tool_params={"team": "analytics"},
    )

    assert approved is False
    assert "Unknown tool 'list_dashboards' requires explicit allowlisting" in blocked_reason
    assert "risk_score=0.0" in blocked_reason
    assert tool_call.approved is False
    assert tool_call.approved_by is None


def test_unknown_high_risk_operation_is_also_blocked():
    approval = ToolApprovalSystem()
    session = _build_session()

    approved, blocked_reason, tool_call = approval.approve_tool_call(
        session=session,
        agent_id=1,
        tool_name="delete_archive",
        tool_params={"database": "prod", "role": "admin"},
    )

    assert approved is False
    assert "Unknown tool 'delete_archive' requires explicit allowlisting" in blocked_reason
    assert "risk_score=" in blocked_reason
    assert tool_call.risk_score > 0.0


def test_execute_tool_call_rejects_unapproved_calls():
    approval = ToolApprovalSystem()
    session = _build_session()
    tool_call = MagicMock(approved=False, blocked_reason="blocked by policy")
    session.get.return_value = tool_call

    success, error, result = approval.execute_tool_call(session=session, tool_call_id=123)

    assert success is False
    assert error == "Tool call not approved: blocked by policy"
    assert result is None
