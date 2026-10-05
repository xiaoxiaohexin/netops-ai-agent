"""Structured Repair Plan and Atomic Repair Action Models (R3).

Defines RepairAction and RepairPlan with pre-checks, post-checks, and deterministic
rollback commands, along with bidirectional adapters to legacy RemediationPlan
for 100% backwards compatibility.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field

from langgraph_netagent.models.diagnostic import SeverityLevel
from langgraph_netagent.models.intent import RollbackStep
from langgraph_netagent.models.reasoning import DiagnosticStrategy
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan


class RepairAction(BaseModel):
    """Atomic repair action with deterministic pre/post checks and rollback guarantees."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    action_id: str = Field(default_factory=lambda: f"act-{uuid.uuid4().hex[:6]}", description="Unique action identifier")
    order: int = Field(default=1, description="Execution sequence index")
    target_node: str = Field(..., description="Target node container or hostname (e.g. 'leaf1', 'dc-egress')")
    action_type: str = Field(..., description="Action classification: link_up, route_replace, qdisc_reset, acl_drop, etc.")
    command: str = Field(..., description="Concrete CLI execution command")

    # Pre-check contract
    pre_check_command: Optional[str] = Field(default=None, description="Read-only command executed before applying change")
    expected_pre_condition: Optional[str] = Field(default=None, description="Expected substring or pattern in pre-check output")

    # Post-check contract
    post_check_command: Optional[str] = Field(default=None, description="Read-only command executed immediately after change")
    expected_post_condition: Optional[str] = Field(default=None, description="Expected substring or pattern in post-check output")

    # Rollback contract
    rollback_command: Optional[str] = Field(default=None, description="Exact compensation command to reverse this action")
    timeout_sec: float = Field(default=15.0, description="Command execution timeout in seconds")
    description: str = Field(default="", description="Human-readable description of this action")

    def to_rollback_step(self, step_number: int = 1) -> Optional[RollbackStep]:
        """Convert this action's rollback command to a canonical RollbackStep."""
        if not self.rollback_command:
            return None
        return RollbackStep(
            step_number=step_number,
            command=self.rollback_command,
            target_node=self.target_node,
            description=f"Rollback {self.action_type} on {self.target_node}: {self.rollback_command}",
            payload=self.rollback_command,
        )


class RepairPlan(BaseModel):
    """Structured actionable repair plan with atomic verification contracts and rollback."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    plan_id: str = Field(default_factory=lambda: f"plan-{uuid.uuid4().hex[:6]}", description="Unique plan identifier")
    incident_id: str = Field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:6]}", description="Associated incident ID")
    strategy: DiagnosticStrategy = Field(..., description="Selected diagnostic remediation strategy")
    target_node: Optional[str] = Field(default=None, description="Primary target node being repaired")
    actions: List[RepairAction] = Field(default_factory=list, description="Ordered atomic repair actions")
    justification: str = Field(default="", description="Reasoning and expected impact of this plan")
    expected_diff_resolution: List[str] = Field(default_factory=list, description="Keys/descriptions in StateDiff this plan resolves")
    estimated_risk: SeverityLevel = Field(default=SeverityLevel.LOW, description="Risk assessment")
    requires_approval: bool = Field(default=False, description="Flag indicating if HITL approval is required")
    step_tag: str = Field(default="", description="Monotonic iteration step tag")

    def to_legacy_remediation_plan(self) -> RemediationPlan:
        """Bidirectional adapter converting RepairPlan to legacy RemediationPlan."""
        primary_target = self.target_node or (self.actions[0].target_node if self.actions else "network")
        exec_cmds = [act.command for act in self.actions]

        # Build rollbacks in reverse LIFO order
        rollbacks: List[RollbackStep] = []
        for idx, act in enumerate(reversed(self.actions), start=1):
            rb = act.to_rollback_step(step_number=idx)
            if rb is not None:
                rollbacks.append(rb)

        return RemediationPlan(
            plan_id=self.plan_id,
            action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
            target_entity=primary_target,
            exec_commands=exec_cmds,
            rollback_steps=rollbacks,
            expected_outcome=self.justification or f"Remediate incident via {self.strategy.value}",
            estimated_risk=self.estimated_risk,
            requires_human_approval=self.requires_approval,
        )

    @classmethod
    def from_legacy_remediation_plan(
        cls,
        legacy_plan: RemediationPlan,
        strategy: Optional[DiagnosticStrategy] = None,
        incident_id: Optional[str] = None,
    ) -> RepairPlan:
        """Bidirectional adapter constructing RepairPlan from legacy RemediationPlan."""
        strat = strategy or DiagnosticStrategy.LINK_RECOVERY
        actions: List[RepairAction] = []

        # Map rollback steps by index or reversed
        rollbacks_by_target = {}
        for rb in legacy_plan.rollback_steps:
            cmd = rb.command or rb.payload
            tgt = rb.target_node or legacy_plan.target_entity
            if tgt not in rollbacks_by_target:
                rollbacks_by_target[tgt] = []
            if cmd:
                rollbacks_by_target[tgt].append(cmd)

        for idx, cmd in enumerate(legacy_plan.exec_commands, start=1):
            node = legacy_plan.target_entity
            # Find matching rollback if available
            rb_cmd = None
            if node in rollbacks_by_target and rollbacks_by_target[node]:
                rb_cmd = rollbacks_by_target[node].pop()
            elif legacy_plan.rollback_steps:
                last_rb = legacy_plan.rollback_steps[-1]
                rb_cmd = last_rb.command or last_rb.payload

            # Infer action_type
            act_type = "exec_command"
            if "link set" in cmd and "up" in cmd:
                act_type = "link_up"
            elif "route replace" in cmd or "route add" in cmd:
                act_type = "route_replace"
            elif "qdisc del" in cmd:
                act_type = "qdisc_reset"
            elif "iptables" in cmd and ("DROP" in cmd or "-j DROP" in cmd):
                act_type = "acl_drop"

            actions.append(
                RepairAction(
                    action_id=f"act-{idx}",
                    order=idx,
                    target_node=node,
                    action_type=act_type,
                    command=cmd,
                    rollback_command=rb_cmd,
                )
            )

        return cls(
            plan_id=legacy_plan.plan_id,
            incident_id=incident_id or f"inc-{uuid.uuid4().hex[:6]}",
            strategy=strat,
            target_node=legacy_plan.target_entity,
            actions=actions,
            justification=legacy_plan.expected_outcome,
            estimated_risk=legacy_plan.estimated_risk,
            requires_approval=legacy_plan.requires_human_approval,
        )
