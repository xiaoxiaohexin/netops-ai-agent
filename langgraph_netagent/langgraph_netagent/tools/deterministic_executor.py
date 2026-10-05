"""Transactional Deterministic Executor for Repair Plans (R3).

Executes RepairPlan actions sequentially with strict LabIsolationGuard boundaries,
pre-execution safety validation, pre-check verification, post-check verification,
and automatic reverse-order (LIFO) transactional rollbacks upon failure.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from langgraph_netagent.models.operational import AALToolCall
from langgraph_netagent.models.repair_plan import RepairAction, RepairPlan
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.lab_isolation import LabIsolationGuard, LabIsolationViolationError
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter

logger = logging.getLogger(__name__)


class ExecutionResult(BaseModel):
    """Result of transactional RepairPlan execution."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    success: bool = Field(..., description="True if all actions executed and passed post-checks")
    executed_actions: List[RepairAction] = Field(default_factory=list, description="Actions that were applied before finish or rollback")
    error: Optional[str] = Field(default=None, description="Error message if execution failed")
    rolled_back: bool = Field(default=False, description="True if rollback was triggered and completed")
    action_outputs: List[Dict[str, Any]] = Field(default_factory=list, description="Outputs captured for each action")
    rollback_outputs: List[Dict[str, Any]] = Field(default_factory=list, description="Outputs captured during rollback")


class DeterministicExecutor:
    """Transactionally executes a RepairPlan with pre/post condition assertions and LIFO rollback."""

    def __init__(
        self,
        agent_access_layer: Optional[AgentAccessLayer] = None,
        lab_adapter: Optional[BaseNetworkLabAdapter] = None,
        isolation_guard: Optional[LabIsolationGuard] = None,
        lab_name: str = "clos5",
    ):
        """Initialize DeterministicExecutor.

        Args:
            agent_access_layer: Optional AgentAccessLayer instance.
            lab_adapter: Optional BaseNetworkLabAdapter instance (used if AAL not provided).
            isolation_guard: Optional LabIsolationGuard enforcing container boundaries.
            lab_name: Containerlab lab name (default 'clos5').
        """
        self.lab_name = lab_name
        self.isolation_guard = isolation_guard or LabIsolationGuard(lab_name=lab_name)

        if agent_access_layer is not None:
            self.aal = agent_access_layer
            self.lab_adapter = agent_access_layer.lab_adapter
        elif lab_adapter is not None:
            self.lab_adapter = lab_adapter
            self.aal = AgentAccessLayer(lab_adapter=lab_adapter)
        else:
            default_adapter = MockContainerlabAdapter()
            self.lab_adapter = default_adapter
            self.aal = AgentAccessLayer(lab_adapter=default_adapter)

    def execute_plan(
        self,
        plan: RepairPlan,
        step_tag: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute all actions in a RepairPlan transactionally.

        For each RepairAction:
        1. Lab isolation and AAL safety validation.
        2. Pre-check execution and validation against expected_pre_condition.
        3. Application of main command via AAL.
        4. Post-check execution and validation against expected_post_condition.

        On any failure, execution halts immediately and rolls back all executed actions
        in reverse LIFO order.

        Args:
            plan: The RepairPlan to apply.
            step_tag: Optional monotonic iteration step tag.

        Returns:
            ExecutionResult describing outcome, executed actions, and rollback status.
        """
        tag = step_tag or plan.step_tag or "exec"
        executed_actions: List[RepairAction] = []
        action_outputs: List[Dict[str, Any]] = []

        for idx, action in enumerate(plan.actions, start=1):
            act_tag = f"{tag}_act_{idx}"

            # -----------------------------------------------------------------
            # Step 1: Pre-Execution Isolation & Safety Validation
            # -----------------------------------------------------------------
            try:
                self.isolation_guard.assert_container_isolated(action.target_node)
                self.isolation_guard.assert_command_safety(action.command, container_name=action.target_node)
            except LabIsolationViolationError as exc:
                err_msg = f"Lab isolation boundary violation on action {action.action_id}: {exc}"
                logger.error(err_msg)
                rb_outputs = self._rollback_actions(executed_actions, tag)
                return ExecutionResult(
                    success=False,
                    executed_actions=executed_actions,
                    error=err_msg,
                    rolled_back=True,
                    action_outputs=action_outputs,
                    rollback_outputs=rb_outputs,
                )

            is_safe, safety_err = self.aal.validate_command_safety(action.command, read_only=False)
            if not is_safe:
                err_msg = f"AAL security check rejected command '{action.command}' on {action.target_node}: {safety_err}"
                logger.error(err_msg)
                rb_outputs = self._rollback_actions(executed_actions, tag)
                return ExecutionResult(
                    success=False,
                    executed_actions=executed_actions,
                    error=err_msg,
                    rolled_back=True,
                    action_outputs=action_outputs,
                    rollback_outputs=rb_outputs,
                )

            # -----------------------------------------------------------------
            # Step 2: Pre-Check Condition Validation (if configured)
            # -----------------------------------------------------------------
            if action.pre_check_command:
                try:
                    self.isolation_guard.assert_command_safety(action.pre_check_command, container_name=action.target_node)
                except LabIsolationViolationError as exc:
                    err_msg = f"Lab isolation rejected pre_check_command: {exc}"
                    rb_outputs = self._rollback_actions(executed_actions, tag)
                    return ExecutionResult(
                        success=False,
                        executed_actions=executed_actions,
                        error=err_msg,
                        rolled_back=True,
                        action_outputs=action_outputs,
                        rollback_outputs=rb_outputs,
                    )

                pre_call = AALToolCall(
                    tool_name="pre_check",
                    node_name=action.target_node,
                    command=action.pre_check_command,
                    step_tag=f"{act_tag}_pre",
                    read_only=True,
                    timeout=action.timeout_sec,
                )
                pre_resp = self.aal.execute(pre_call)

                if action.expected_pre_condition:
                    combined_pre_out = (pre_resp.raw_stdout + "\n" + pre_resp.raw_stderr).upper()
                    expected_upper = action.expected_pre_condition.upper()
                    if expected_upper not in combined_pre_out:
                        err_msg = (
                            f"Pre-check assertion failed on {action.target_node} for {action.action_id}: "
                            f"expected '{action.expected_pre_condition}' not found in output: {pre_resp.raw_stdout[:200]}"
                        )
                        logger.warning(err_msg)
                        rb_outputs = self._rollback_actions(executed_actions, tag)
                        return ExecutionResult(
                            success=False,
                            executed_actions=executed_actions,
                            error=err_msg,
                            rolled_back=True,
                            action_outputs=action_outputs,
                            rollback_outputs=rb_outputs,
                        )

            # -----------------------------------------------------------------
            # Step 3: Main Command Application via AAL
            # -----------------------------------------------------------------
            exec_call = AALToolCall(
                tool_name="patch_exec",
                node_name=action.target_node,
                command=action.command,
                step_tag=act_tag,
                read_only=False,
                timeout=action.timeout_sec,
            )
            exec_resp = self.aal.execute(exec_call)
            action_outputs.append({
                "action_id": action.action_id,
                "node": action.target_node,
                "command": action.command,
                "exit_code": exec_resp.exit_code,
                "stdout": exec_resp.raw_stdout,
                "stderr": exec_resp.raw_stderr,
                "success": exec_resp.success,
            })

            if not exec_resp.success or exec_resp.exit_code != 0:
                err_msg = (
                    f"Command execution failed on {action.target_node} for {action.action_id} "
                    f"(exit {exec_resp.exit_code}): {exec_resp.raw_stderr or exec_resp.raw_stdout}"
                )
                logger.error(err_msg)
                rb_outputs = self._rollback_actions(executed_actions, tag)
                return ExecutionResult(
                    success=False,
                    executed_actions=executed_actions,
                    error=err_msg,
                    rolled_back=True,
                    action_outputs=action_outputs,
                    rollback_outputs=rb_outputs,
                )

            # Register as successfully applied and synchronize mock state if applicable
            executed_actions.append(action)
            self._sync_mock_state(action.target_node, action.command)

            # -----------------------------------------------------------------
            # Step 4: Post-Check Condition Validation (if configured)
            # -----------------------------------------------------------------
            if action.post_check_command:
                try:
                    self.isolation_guard.assert_command_safety(action.post_check_command, container_name=action.target_node)
                except LabIsolationViolationError as exc:
                    err_msg = f"Lab isolation rejected post_check_command: {exc}"
                    rb_outputs = self._rollback_actions(executed_actions, tag)
                    return ExecutionResult(
                        success=False,
                        executed_actions=executed_actions,
                        error=err_msg,
                        rolled_back=True,
                        action_outputs=action_outputs,
                        rollback_outputs=rb_outputs,
                    )

                post_call = AALToolCall(
                    tool_name="post_check",
                    node_name=action.target_node,
                    command=action.post_check_command,
                    step_tag=f"{act_tag}_post",
                    read_only=True,
                    timeout=action.timeout_sec,
                )
                post_resp = self.aal.execute(post_call)

                if action.expected_post_condition:
                    combined_post_out = (post_resp.raw_stdout + "\n" + post_resp.raw_stderr).upper()
                    expected_upper = action.expected_post_condition.upper()
                    if expected_upper not in combined_post_out:
                        err_msg = (
                            f"Post-check assertion failed on {action.target_node} for {action.action_id}: "
                            f"expected '{action.expected_post_condition}' not found in output: {post_resp.raw_stdout[:200]}"
                        )
                        logger.warning(err_msg)
                        rb_outputs = self._rollback_actions(executed_actions, tag)
                        return ExecutionResult(
                            success=False,
                            executed_actions=executed_actions,
                            error=err_msg,
                            rolled_back=True,
                            action_outputs=action_outputs,
                            rollback_outputs=rb_outputs,
                        )

        return ExecutionResult(
            success=True,
            executed_actions=executed_actions,
            error=None,
            rolled_back=False,
            action_outputs=action_outputs,
        )

    def rollback_plan(
        self,
        plan: RepairPlan,
        executed_actions: Optional[List[RepairAction]] = None,
        step_tag: Optional[str] = None,
    ) -> bool:
        """Manually trigger rollback for actions in reverse LIFO order.

        Args:
            plan: The RepairPlan whose actions are to be reversed.
            executed_actions: Optional subset of applied actions. If None, rolls back all plan actions.
            step_tag: Optional step tag for audit tracking.

        Returns:
            True if all rollback commands completed successfully.
        """
        actions = executed_actions if executed_actions is not None else plan.actions
        tag = step_tag or plan.step_tag or "manual_rollback"
        outputs = self._rollback_actions(actions, tag)
        return all(out.get("success", False) for out in outputs) if outputs else True

    def _rollback_actions(
        self,
        applied_actions: List[RepairAction],
        step_tag: str,
    ) -> List[Dict[str, Any]]:
        """Roll back applied actions in reverse LIFO order."""
        rollback_outputs: List[Dict[str, Any]] = []

        for idx, action in enumerate(reversed(applied_actions), start=1):
            if not action.rollback_command:
                continue

            try:
                self.isolation_guard.assert_command_safety(action.rollback_command, container_name=action.target_node)
            except Exception as e:
                logger.error("Isolation guard blocked rollback command '%s': %s", action.rollback_command, e)
                continue

            rb_call = AALToolCall(
                tool_name="rollback_exec",
                node_name=action.target_node,
                command=action.rollback_command,
                step_tag=f"{step_tag}_rb_{idx}",
                read_only=False,
                timeout=action.timeout_sec,
            )
            rb_resp = self.aal.execute(rb_call)
            if rb_resp.success:
                self._sync_mock_state(action.target_node, action.rollback_command)

            rollback_outputs.append({
                "action_id": action.action_id,
                "node": action.target_node,
                "rollback_command": action.rollback_command,
                "exit_code": rb_resp.exit_code,
                "stdout": rb_resp.raw_stdout,
                "stderr": rb_resp.raw_stderr,
                "success": rb_resp.success,
            })

        return rollback_outputs

    def _sync_mock_state(self, node: str, command: str) -> None:
        """Synchronize virtual node state if running against MockContainerlabAdapter."""
        mock_eng = getattr(self.lab_adapter, "mock_engine", None)
        if not mock_eng or not hasattr(mock_eng, "graph"):
            return

        graph = mock_eng.graph
        if node in graph.nodes:
            vnode = graph.nodes[node]
            fault_inj = getattr(self.lab_adapter, "fault_injector", None)
            from langgraph_netagent.tools.fault_injector import FaultRule, FaultType

            # 1. Match ip link set dev <iface> up/down
            m_link = re.search(r"ip\s+link\s+set\s+(?:dev\s+)?([a-zA-Z0-9_\-\.]+)\s+(up|down)", command, re.IGNORECASE)
            if m_link:
                if_name = m_link.group(1)
                new_state = m_link.group(2).upper()
                if if_name in vnode.interfaces:
                    vnode.interfaces[if_name].oper_state = new_state
                    vnode.interfaces[if_name].admin_state = new_state

                if fault_inj:
                    if new_state == "UP":
                        fault_inj.on_remediation(command=command, node=node)
                        rules_to_del = [
                            rid for rid, r in getattr(fault_inj, "_rules", {}).items()
                            if r.fault_type == FaultType.INTERFACE_DOWN
                            and r.target_node == node
                            and (not r.target_interface or r.target_interface == if_name)
                        ]
                        for rid in rules_to_del:
                            fault_inj.remove_rule(rid)
                    elif new_state == "DOWN":
                        fault_inj.add_rule(
                            FaultRule(
                                fault_type=FaultType.INTERFACE_DOWN,
                                target_node=node,
                                target_interface=if_name,
                            )
                        )

            # 2. Match ip route add/replace
            m_route = re.search(
                r"ip\s+route\s+(?:replace|add)\s+([0-9\./]+|default)(?:\s+via\s+([0-9\.]+))?(?:\s+dev\s+([a-zA-Z0-9_\-\.]+))?",
                command,
                re.IGNORECASE,
            )
            if m_route:
                from langgraph_netagent.models.telemetry import RouteEntry
                pfx = m_route.group(1)
                gw = m_route.group(2)
                dev = m_route.group(3)
                vnode.add_route(RouteEntry(destination=pfx, next_hop=gw, interface=dev, protocol="static"))
                if fault_inj:
                    fault_inj.on_remediation(command=command, node=node)
                    rules_to_del = [
                        rid for rid, r in getattr(fault_inj, "_rules", {}).items()
                        if r.fault_type == FaultType.MISSING_ROUTE
                        and r.target_node == node
                        and (not r.target_ip_or_prefix or r.target_ip_or_prefix == pfx or (pfx == "default" and r.target_ip_or_prefix in ("default", "0.0.0.0/0")))
                    ]
                    for rid in rules_to_del:
                        fault_inj.remove_rule(rid)

            # 3. Match ip route del
            m_route_del = re.search(r"ip\s+route\s+del\s+([0-9\./]+|default)", command, re.IGNORECASE)
            if m_route_del:
                pfx = m_route_del.group(1)
                vnode.routes = [r for r in vnode.routes if r.destination != pfx]
                if fault_inj:
                    fault_inj.add_rule(
                        FaultRule(
                            fault_type=FaultType.MISSING_ROUTE,
                            target_node=node,
                            target_ip_or_prefix=pfx,
                        )
                    )

            # 4. Match tc qdisc del
            if "tc qdisc del" in command:
                if fault_inj:
                    fault_inj.on_remediation(command=command, node=node)
                    m_tc = re.search(r"tc\s+qdisc\s+del\s+dev\s+([a-zA-Z0-9_\-\.]+)", command, re.IGNORECASE)
                    tc_iface = m_tc.group(1) if m_tc else None
                    rules_to_del = [
                        rid for rid, r in getattr(fault_inj, "_rules", {}).items()
                        if r.fault_type in (FaultType.INTERMITTENT_LOSS, FaultType.BUFFER_OVERLIMIT, FaultType.TRAFFIC_OVERLOAD)
                        and r.target_node == node
                        and (not tc_iface or not r.target_interface or r.target_interface == tc_iface)
                    ]
                    for rid in rules_to_del:
                        fault_inj.remove_rule(rid)
