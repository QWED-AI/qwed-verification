"""
Tool Approval: Verification system for agent tool/API calls.

This module manages:
- Tool call risk assessment
- Approval logic
- Safe execution
- Dangerous operation blocking
"""

import json
from typing import Dict, Any, Tuple, Optional
from sqlmodel import Session

from qwed_new.core.agent_models import ToolCall
from qwed_new.core.agent_registry import agent_registry

class ToolApprovalSystem:
    """
    Manages approval and execution of tool calls by AI agents.
    Acts as a security gateway for agent actions.
    """
    
    def __init__(self):
        # Define dangerous operations that require explicit approval
        self.dangerous_operations = {
            "delete_database",
            "drop_table",
            "execute_sql_delete",
            "send_money",
            "delete_files",
            "shutdown_server",
            "revoke_access"
        }
        
        # Auto-approve safe operations
        self.safe_operations = {
            "read_database",
            "query_data",
            "send_email",
            "log_message",
            "get_weather",
            "search_web"
        }
    
    def approve_tool_call(
        self,
        session: Session,
        agent_id: int,
        tool_name: str,
        tool_params: Dict[str, Any],
        activity_id: Optional[int] = None
    ) -> Tuple[bool, Optional[str], ToolCall]:
        """
        Evaluate if a tool call should be approved.
        
        Returns:
            (approved: bool, blocked_reason: Optional[str], tool_call: ToolCall)
        """
        # Calculate risk score
        risk_score = self._assess_risk(tool_name, tool_params)
        
        # Create tool call record
        tool_call = ToolCall(
            agent_id=agent_id,
            activity_id=activity_id,
            tool_name=tool_name,
            tool_params=json.dumps(tool_params),
            risk_score=risk_score
        )
        
        # Decision logic
        if tool_name in self.dangerous_operations:
            # Dangerous operation - block or require manual approval
            tool_call.approved = False
            tool_call.blocked_reason = f"Dangerous operation '{tool_name}' requires manual approval"
            tool_call.approved_by = None
            
            session.add(tool_call)
            session.commit()
            session.refresh(tool_call)
            
            return False, tool_call.blocked_reason, tool_call
        
        elif tool_name in self.safe_operations:
            # Safe operation - auto-approve
            tool_call.approved = True
            tool_call.approved_by = "automatic"
            
            session.add(tool_call)
            session.commit()
            session.refresh(tool_call)
            
            return True, None, tool_call
        
        else:
            # Unknown operation - evaluate by risk score
            if risk_score < 0.3:
                # Low risk - approve
                tool_call.approved = True
                tool_call.approved_by = "policy"
                
                session.add(tool_call)
                session.commit()
                session.refresh(tool_call)
                
                return True, None, tool_call
            else:
                # High risk - block
                tool_call.approved = False
                tool_call.blocked_reason = f"High risk score ({risk_score})"
                
                session.add(tool_call)
                session.commit()
                session.refresh(tool_call)
                
                return False, tool_call.blocked_reason, tool_call
    
    def execute_tool_call(
        self,
        session: Session,
        tool_call_id: int
    ) -> Tuple[bool, Optional[str], Optional[Any]]:
        """
        Execute an approved tool call.
        
        Returns:
            (success: bool, error: Optional[str], result: Optional[Any])
        """
        tool_call = session.get(ToolCall, tool_call_id)
        
        if not tool_call:
            return False, "Tool call not found", None
        
        if not tool_call.approved:
            return False, f"Tool call not approved: {tool_call.blocked_reason}", None
        
        # Execute tool (placeholder - would integrate with actual tools)
        try:
            result = self._execute_safe_tool(
                tool_call.tool_name,
                json.loads(tool_call.tool_params)
            )
            
            tool_call.executed = True
            tool_call.result = json.dumps(result)
            session.add(tool_call)
            session.commit()
            
            return True, None, result
            
        except Exception as e:
            tool_call.executed = False
            tool_call.result = f"Error: {str(e)}"
            session.add(tool_call)
            session.commit()
            
            return False, str(e), None
    
    def _assess_risk(self, tool_name: str, tool_params: Dict[str, Any]) -> float:
        """
        Calculate risk score (0.0 = safe, 1.0 = dangerous).
        """
        risk = 0.0
        
        # Tool name risk
        if "delete" in tool_name.lower():
            risk += 0.5
        if "drop" in tool_name.lower():
            risk += 0.5
        if "money" in tool_name.lower() or "payment" in tool_name.lower():
            risk += 0.4
        
        # Parameter risk
        if "database" in str(tool_params).lower():
            risk += 0.2
        if "admin" in str(tool_params).lower():
            risk += 0.2
        
        return min(risk, 1.0)
    
    def _execute_safe_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """
        Execute a tool in a sandboxed environment.
        Placeholder for actual tool execution logic.
        """
        # In production, this would integrate with actual tool implementations
        return {
            "tool": tool_name,
            "status": "simulated_execution",
            "params": params
        }

# Global singleton
tool_approval = ToolApprovalSystem()
