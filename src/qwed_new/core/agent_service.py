"""
QWED Agent Service

Implements the QWED-Agent specification for AI agent verification.
Provides registration, verification, budget management, and audit logging.
"""

import time
import uuid
import hmac
import json
import threading
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List, Set
from enum import Enum

from qwed_new.guards.doom_loop_guard import ProgressAwareDoomLoopGuard


class AgentType(Enum):
    """Agent autonomy levels"""
    SUPERVISED = "supervised"  # Human approval for high-risk
    AUTONOMOUS = "autonomous"  # Self-executing within limits
    TRUSTED = "trusted"        # Full autonomy (enterprise)


class TrustLevel(Enum):
    """Agent trust levels"""
    UNTRUSTED = 0    # No autonomous actions
    SUPERVISED = 1   # Low-risk autonomous
    AUTONOMOUS = 2   # Most actions autonomous
    TRUSTED = 3      # Full autonomy


class AgentDecision(Enum):
    """Verification decision for agent actions"""
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    CORRECTED = "CORRECTED"
    PENDING = "PENDING"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class RiskLevel(Enum):
    """Risk level for actions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AgentPermissions:
    """Permissions for an agent"""
    allowed_engines: List[str] = field(default_factory=lambda: ["math", "logic"])
    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)


@dataclass
class AgentBudget:
    """Budget limits for an agent"""
    max_daily_cost_usd: float = 100.0
    max_per_request_cost_usd: float = 1.0
    max_requests_per_hour: int = 1000
    max_requests_per_day: int = 10000
    max_tokens_per_request: int = 4096
    
    # Current usage (tracked)
    current_daily_cost_usd: float = 0.0
    current_hour_requests: int = 0
    current_day_requests: int = 0
    last_hour_reset: float = field(default_factory=time.time)
    last_day_reset: float = field(default_factory=time.time)


@dataclass
class AgentInfo:
    """Registered agent information"""
    agent_id: str
    agent_token: str
    name: str
    agent_type: AgentType
    principal_id: str
    permissions: AgentPermissions
    budget: AgentBudget
    trust_level: TrustLevel
    status: str = "active"
    created_at: float = field(default_factory=time.time)
    description: Optional[str] = None
    framework: Optional[str] = None
    model: Optional[str] = None


@dataclass
class AgentAction:
    """An action an agent wants to perform"""
    action_type: str  # execute_sql, execute_code, call_api, etc.
    query: Optional[str] = None
    code: Optional[str] = None
    target: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


@dataclass
class ActionContext:
    """Context for an agent action"""
    conversation_id: Optional[str] = None
    step_number: Optional[int] = None
    user_intent: Optional[str] = None
    pre_action_state_hash: Optional[str] = None
    state_source: Optional[str] = None


@dataclass
class VerificationCheck:
    """Result of a single verification check"""
    name: str
    passed: bool
    message: Optional[str] = None


@dataclass
class ActivityLog:
    """Log entry for agent activity"""
    activity_id: str
    agent_id: str
    timestamp: float
    action: AgentAction
    decision: AgentDecision
    risk_level: RiskLevel
    checks_passed: List[str]
    checks_failed: List[str]
    cost_usd: float = 0.0
    tokens_used: int = 0
    attestation_id: Optional[str] = None
    execution_success: Optional[bool] = None
    error: Optional[str] = None


class AgentService:
    """
    Service for managing QWED-verified AI agents.
    
    Implements the QWED-Agent v1.0 specification.
    """
    
    # Tool risk levels
    TOOL_RISK_LEVELS = {
        "database_read": RiskLevel.LOW,
        "database_write": RiskLevel.CRITICAL,
        "send_email": RiskLevel.MEDIUM,
        "execute_code": RiskLevel.CRITICAL,
        "file_read": RiskLevel.LOW,
        "file_write": RiskLevel.HIGH,
        "file_delete": RiskLevel.CRITICAL,
        "api_call": RiskLevel.MEDIUM,
    }
    
    # Action type to engine mapping
    ACTION_ENGINES = {
        "execute_sql": "sql",
        "execute_code": "code",
        "calculate": "math",
        "verify_logic": "logic",
        "verify_fact": "fact",
    }
    MAX_CONVERSATION_STEPS = 50
    MAX_CONSECUTIVE_IDENTICAL_ACTIONS = 2
    RISK_RANKS = {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
    }
    
    def __init__(self):
        self._agents: Dict[str, AgentInfo] = {}
        self._activity_logs: List[ActivityLog] = []
        self._suspended_agents: Set[str] = set()
        self._conversation_state: Dict[tuple[str, str], Dict[str, Any]] = {}
        self._conversation_reservations: Dict[tuple[str, str], Dict[str, Any]] = {}
        self._conversation_state_lock = threading.Lock()
        self._doom_loop_guard = ProgressAwareDoomLoopGuard()
    
    def _generate_agent_id(self) -> str:
        return f"agent_{uuid.uuid4().hex[:12]}"
    
    def _generate_agent_token(self) -> str:
        return f"qwed_agent_{uuid.uuid4().hex}"
    
    def _reset_budget_if_needed(self, budget: AgentBudget) -> None:
        """Reset hourly/daily counters if needed"""
        now = time.time()
        
        # Reset hourly
        if now - budget.last_hour_reset >= 3600:
            budget.current_hour_requests = 0
            budget.last_hour_reset = now
        
        # Reset daily
        if now - budget.last_day_reset >= 86400:
            budget.current_daily_cost_usd = 0.0
            budget.current_day_requests = 0
            budget.last_day_reset = now
    
    def register_agent(
        self,
        name: str,
        agent_type: str,
        principal_id: str,
        permissions: Optional[Dict[str, Any]] = None,
        budget: Optional[Dict[str, Any]] = None,
        trust_level: int = 1,
        description: Optional[str] = None,
        framework: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Register a new agent with QWED.
        
        Returns agent_id and agent_token for authentication.
        """
        agent_id = self._generate_agent_id()
        agent_token = self._generate_agent_token()
        
        # Parse permissions
        perms = AgentPermissions()
        if permissions:
            perms.allowed_engines = permissions.get("allowed_engines", perms.allowed_engines)
            perms.allowed_tools = permissions.get("allowed_tools", perms.allowed_tools)
            perms.blocked_tools = permissions.get("blocked_tools", perms.blocked_tools)
        
        # Parse budget
        bud = AgentBudget()
        if budget:
            bud.max_daily_cost_usd = budget.get("max_daily_cost_usd", bud.max_daily_cost_usd)
            bud.max_per_request_cost_usd = budget.get("max_per_request_cost_usd", bud.max_per_request_cost_usd)
            bud.max_requests_per_hour = budget.get("max_requests_per_hour", bud.max_requests_per_hour)
            bud.max_requests_per_day = budget.get("max_requests_per_day", bud.max_requests_per_day)
        
        agent = AgentInfo(
            agent_id=agent_id,
            agent_token=agent_token,
            name=name,
            agent_type=AgentType(agent_type),
            principal_id=principal_id,
            permissions=perms,
            budget=bud,
            trust_level=TrustLevel(trust_level),
            description=description,
            framework=framework,
            model=model,
        )
        
        self._agents[agent_id] = agent
        
        return {
            "agent_id": agent_id,
            "agent_token": agent_token,
            "status": "active",
            "created_at": datetime.fromtimestamp(agent.created_at).isoformat(),
        }
    
    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Get agent by ID"""
        return self._agents.get(agent_id)
    
    def verify_agent_token(self, agent_id: str, agent_token: str) -> bool:
        """Verify agent authentication"""
        agent = self._agents.get(agent_id)
        return (
            agent is not None
            and hmac.compare_digest(agent.agent_token, agent_token)
        )
    
    def verify_action(
        self,
        agent_id: str,
        action: AgentAction,
        context: ActionContext,
        require_attestation: bool = False,
        risk_threshold: str = "medium",
    ) -> Dict[str, Any]:
        """
        Verify an agent action before execution.
        
        Returns decision and verification details.
        """
        agent = self._agents.get(agent_id)
        if not agent:
            return {
                "decision": AgentDecision.DENIED.value,
                "error": {"code": "QWED-AGENT-001", "message": "Agent not registered"},
            }
        
        if agent_id in self._suspended_agents:
            return {
                "decision": AgentDecision.DENIED.value,
                "error": {"code": "QWED-AGENT-003", "message": "Agent suspended"},
            }

        context_error, context_state = self._enforce_action_context(agent_id, action, context)
        if context_error:
            return {
                "decision": AgentDecision.DENIED.value,
                "error": context_error,
            }
        
        # Reset budget counters if needed
        self._reset_budget_if_needed(agent.budget)
        
        # Check budget
        budget_check = self._check_budget(agent)
        if not budget_check["passed"]:
            self._release_action_context(context_state)
            return {
                "decision": AgentDecision.BUDGET_EXCEEDED.value,
                "error": {
                    "code": budget_check["code"],
                    "message": budget_check["message"],
                    "details": budget_check.get("details", {}),
                },
            }
        
        # Assess risk level
        risk_level = self._assess_risk(action, agent)
        
        # Run verification checks
        checks = self._run_verification_checks(agent, action, risk_level)
        passed = [c.name for c in checks if c.passed]
        failed = [c.name for c in checks if not c.passed]
        
        # Determine decision
        if failed:
            decision = AgentDecision.DENIED
        elif self._risk_exceeds_threshold(risk_level, RiskLevel[risk_threshold.upper()]):
            if agent.trust_level.value < TrustLevel.AUTONOMOUS.value:
                decision = AgentDecision.PENDING
            else:
                decision = AgentDecision.APPROVED
        else:
            decision = AgentDecision.APPROVED
        
        # Commit approved or pending steps so loop/replay tracking cannot be bypassed.
        if decision in {AgentDecision.APPROVED, AgentDecision.PENDING}:
            self._commit_action_context(context, context_state)
        else:
            self._release_action_context(context_state)

        # Update budget tracking
        if decision == AgentDecision.APPROVED:
            estimated_cost = 0.01  # Base cost
            agent.budget.current_daily_cost_usd += estimated_cost
            agent.budget.current_hour_requests += 1
            agent.budget.current_day_requests += 1
        
        # Log activity
        activity_id = f"act_{uuid.uuid4().hex[:12]}"
        log = ActivityLog(
            activity_id=activity_id,
            agent_id=agent_id,
            timestamp=time.time(),
            action=action,
            decision=decision,
            risk_level=risk_level,
            checks_passed=passed,
            checks_failed=failed,
        )
        self._activity_logs.append(log)
        
        response = {
            "decision": decision.value,
            "verification": {
                "status": "VERIFIED" if decision == AgentDecision.APPROVED else "FAILED",
                "engine": self.ACTION_ENGINES.get(action.action_type, "security"),
                "risk_level": risk_level.value,
                "checks_passed": passed,
                "checks_failed": failed,
            },
            "budget_remaining": {
                "daily_cost_usd": agent.budget.max_daily_cost_usd - agent.budget.current_daily_cost_usd,
                "hourly_requests": agent.budget.max_requests_per_hour - agent.budget.current_hour_requests,
            },
        }
        
        return response

    def _enforce_action_context(
        self,
        agent_id: str,
        action: AgentAction,
        context: Optional[ActionContext],
    ) -> tuple[Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
        """Require deterministic action context and detect replay/loop patterns."""
        if context is None or not context.conversation_id or context.step_number is None:
            return ({
                "code": "QWED-AGENT-CTX-001",
                "message": "Action context with conversation_id and step_number is required",
            }, None)

        if context.step_number < 1:
            return ({
                "code": "QWED-AGENT-CTX-002",
                "message": "step_number must be >= 1",
            }, None)

        if context.step_number > self.MAX_CONVERSATION_STEPS:
            return ({
                "code": "QWED-AGENT-LOOP-001",
                "message": "Conversation step limit exceeded",
            }, None)

        state_key = (agent_id, context.conversation_id)
        fingerprint = self._action_fingerprint(action)

        with self._conversation_state_lock:
            reservation = self._conversation_reservations.get(state_key)
            if reservation and context.step_number <= reservation["step_number"]:
                return ({
                    "code": "QWED-AGENT-LOOP-002",
                    "message": "Replay or in-flight action step detected",
                }, None)

            state = self._conversation_state.get(
                state_key,
                {"last_step": 0, "last_fingerprint": None, "repeat_count": 0},
            )

            if context.step_number <= state["last_step"]:
                return ({
                    "code": "QWED-AGENT-LOOP-002",
                    "message": "Replay or out-of-order action step detected",
                }, None)

            repeat_count = (
                state["repeat_count"] + 1
                if fingerprint == state["last_fingerprint"]
                else 1
            )

            if repeat_count > self.MAX_CONSECUTIVE_IDENTICAL_ACTIONS:
                return ({
                    "code": "QWED-AGENT-LOOP-003",
                    "message": "Repetitive action loop detected",
                }, None)

            next_state = {
                "last_step": context.step_number,
                "last_fingerprint": fingerprint,
                "repeat_count": repeat_count,
            }
            reservation_id = uuid.uuid4().hex
            self._conversation_reservations[state_key] = {
                "step_number": context.step_number,
                "reservation_id": reservation_id,
            }

        # --- LOOP-004: Progress-aware no-progress detection ---
        # Only activates when the caller supplies a world-state hash.
        if context.pre_action_state_hash and context.state_source:
            progress = self._doom_loop_guard.verify_progress(
                agent_id=agent_id,
                conversation_id=context.conversation_id,
                tool_name=action.action_type,
                arguments={
                    "query": action.query,
                    "code": action.code,
                    "target": action.target,
                    "parameters": action.parameters,
                },
                pre_action_state_hash=context.pre_action_state_hash,
                state_source=context.state_source,
            )
            if not progress["verified"]:
                # Release reservation — action is denied.
                with self._conversation_state_lock:
                    reservation = self._conversation_reservations.get(state_key)
                    if reservation and reservation["reservation_id"] == reservation_id:
                        self._conversation_reservations.pop(state_key, None)
                return ({
                    "code": progress["error_code"],
                    "message": progress["message"],
                }, None)

        return None, {
            "state_key": state_key,
            "next_state": next_state,
            "reservation_id": reservation_id,
        }

    def _commit_action_context(
        self,
        context: ActionContext,
        context_state: Optional[Dict[str, Any]],
    ) -> None:
        """Persist conversation progress only after the action is approved."""
        if context_state is None:
            return

        state_key = context_state["state_key"]
        next_state = context_state["next_state"]
        reservation_id = context_state["reservation_id"]

        with self._conversation_state_lock:
            reservation = self._conversation_reservations.get(state_key)
            if reservation is None or reservation["reservation_id"] != reservation_id:
                return
            state = self._conversation_state.get(state_key, {"last_step": 0})
            if context.step_number <= state["last_step"]:
                self._conversation_reservations.pop(state_key, None)
                return
            self._conversation_state[state_key] = next_state
            self._conversation_reservations.pop(state_key, None)

    def _release_action_context(self, context_state: Optional[Dict[str, Any]]) -> None:
        """Release an in-flight context reservation when execution does not proceed."""
        if context_state is None:
            return

        state_key = context_state["state_key"]
        reservation_id = context_state["reservation_id"]

        with self._conversation_state_lock:
            reservation = self._conversation_reservations.get(state_key)
            if reservation and reservation["reservation_id"] == reservation_id:
                self._conversation_reservations.pop(state_key, None)

    @staticmethod
    def _action_fingerprint(action: AgentAction) -> str:
        """Create a deterministic fingerprint for loop detection."""
        payload = {
            "action_type": action.action_type,
            "query": action.query,
            "code": action.code,
            "target": action.target,
            "parameters": AgentService._sanitize_fingerprint_value(action.parameters),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _sanitize_fingerprint_value(value: Any) -> Any:
        """Allow only deterministic JSON-compatible values in action fingerprints."""
        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise TypeError("Non-finite floats are not allowed in action parameters")
            return value
        if isinstance(value, list):
            return [AgentService._sanitize_fingerprint_value(item) for item in value]
        if isinstance(value, tuple):
            return [AgentService._sanitize_fingerprint_value(item) for item in value]
        if isinstance(value, dict):
            sanitized: Dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("Action parameter keys must be strings")
                sanitized[key] = AgentService._sanitize_fingerprint_value(item)
            return sanitized
        raise TypeError(f"Unsupported action parameter type: {type(value).__name__}")

    def _risk_exceeds_threshold(self, risk_level: RiskLevel, threshold: RiskLevel) -> bool:
        """Compare risk levels by their enforcement rank, not string value."""
        return self.RISK_RANKS[risk_level] > self.RISK_RANKS[threshold]
    
    def _check_budget(self, agent: AgentInfo) -> Dict[str, Any]:
        """Check if agent is within budget"""
        budget = agent.budget
        
        if budget.current_daily_cost_usd >= budget.max_daily_cost_usd:
            return {
                "passed": False,
                "code": "QWED-AGENT-BUDGET-001",
                "message": "Daily cost limit exceeded",
                "details": {
                    "limit": budget.max_daily_cost_usd,
                    "current": budget.current_daily_cost_usd,
                },
            }
        
        if budget.current_hour_requests >= budget.max_requests_per_hour:
            return {
                "passed": False,
                "code": "QWED-AGENT-BUDGET-002",
                "message": "Hourly rate limit exceeded",
                "details": {
                    "limit": budget.max_requests_per_hour,
                    "current": budget.current_hour_requests,
                },
            }
        
        return {"passed": True}
    
    def _assess_risk(self, action: AgentAction, agent: AgentInfo) -> RiskLevel:
        """Assess risk level of an action"""
        # Check tool-based risk
        if action.action_type in self.TOOL_RISK_LEVELS:
            return self.TOOL_RISK_LEVELS[action.action_type]
        
        # Check for dangerous patterns
        query = action.query or action.code or ""
        
        if any(kw in query.upper() for kw in ["DROP", "DELETE", "TRUNCATE", "UPDATE"]):
            return RiskLevel.CRITICAL
        
        if any(kw in query.lower() for kw in ["eval(", "exec(", "os.system", "subprocess"]):
            return RiskLevel.CRITICAL
        
        return RiskLevel.LOW
    
    def _run_verification_checks(
        self,
        agent: AgentInfo,
        action: AgentAction,
        risk_level: RiskLevel,
    ) -> List[VerificationCheck]:
        """Run verification checks on an action"""
        checks = []
        
        # Check permissions
        engine = self.ACTION_ENGINES.get(action.action_type)
        if engine and engine not in agent.permissions.allowed_engines:
            checks.append(VerificationCheck(
                name="engine_allowed",
                passed=False,
                message=f"Engine '{engine}' not in allowed list",
            ))
        else:
            checks.append(VerificationCheck(name="engine_allowed", passed=True))
        
        # Check blocked tools
        if action.action_type in agent.permissions.blocked_tools:
            checks.append(VerificationCheck(
                name="tool_not_blocked",
                passed=False,
                message=f"Tool '{action.action_type}' is blocked",
            ))
        else:
            checks.append(VerificationCheck(name="tool_not_blocked", passed=True))
        
        # Check trust level vs risk
        if risk_level == RiskLevel.CRITICAL and agent.trust_level.value < TrustLevel.TRUSTED.value:
            checks.append(VerificationCheck(
                name="trust_level_sufficient",
                passed=False,
                message="Critical risk requires TRUSTED level",
            ))
        else:
            checks.append(VerificationCheck(name="trust_level_sufficient", passed=True))
        
        return checks
    
    def get_agent_activity(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get activity log for an agent"""
        logs = [l for l in self._activity_logs if l.agent_id == agent_id]
        logs = logs[-limit:]  # Last N entries
        
        return [
            {
                "activity_id": l.activity_id,
                "timestamp": datetime.fromtimestamp(l.timestamp).isoformat(),
                "action_type": l.action.action_type,
                "decision": l.decision.value,
                "risk_level": l.risk_level.value,
            }
            for l in logs
        ]
    
    def get_agent_budget(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get current budget status for an agent"""
        agent = self._agents.get(agent_id)
        if not agent:
            return None
        
        self._reset_budget_if_needed(agent.budget)
        
        return {
            "cost": {
                "max_daily_usd": agent.budget.max_daily_cost_usd,
                "current_daily_usd": agent.budget.current_daily_cost_usd,
            },
            "requests": {
                "max_per_hour": agent.budget.max_requests_per_hour,
                "current_hour": agent.budget.current_hour_requests,
                "max_per_day": agent.budget.max_requests_per_day,
                "current_day": agent.budget.current_day_requests,
            },
        }
    
    def suspend_agent(self, agent_id: str) -> bool:
        """Suspend an agent"""
        if agent_id in self._agents:
            self._suspended_agents.add(agent_id)
            self._agents[agent_id].status = "suspended"
            return True
        return False
    
    def reactivate_agent(self, agent_id: str) -> bool:
        """Reactivate a suspended agent"""
        if agent_id in self._agents:
            self._suspended_agents.discard(agent_id)
            self._agents[agent_id].status = "active"
            return True
        return False


# Singleton instance
_agent_service: Optional[AgentService] = None


def get_agent_service() -> AgentService:
    """Get the default agent service"""
    global _agent_service
    if _agent_service is None:
        _agent_service = AgentService()
    return _agent_service
