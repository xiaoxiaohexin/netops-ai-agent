"""Tests for Day-2 Operations Workflow: edges, nodes, and graph compilation."""

from __future__ import annotations
import copy
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pytest
from pydantic import BaseModel

from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan, RollbackStep
from langgraph_netagent.tools.base import (
    BaseNetworkLabAdapter,
    CommandResult,
    DeploymentResult,
    DestructionResult,
    LabInspectionResult,
    LabNodeState,
)
from langgraph_netagent.tools.dry_run import DryRunChecker
from langgraph_netagent.workflow.day2_edges import (
    route_after_approval,
    route_after_dry_run,
    route_after_probe,
    route_after_re_verify,
)
from langgraph_netagent.workflow.day2_state import Day2OpsState, create_day2_initial_state


# ---------------------------------------------------------------------------
# Mock LLM Provider
# ---------------------------------------------------------------------------

class MockChatMessage(BaseModel):
    role: str
    content: str


class MockDay2LLMProvider:
    """Mock LLM that returns pre-built diagnosis + remediation."""

    def __init__(self, target_node: str = "frr1"):
        self.target_node = target_node
        self.call_count = 0

    def generate_structured(self, messages: list, response_schema: type) -> Any:
        self.call_count += 1
        if response_schema == DiagnosticReport:
            return DiagnosticReport(
                telemetry_trigger="Ping failure: pc1 -> 10.2.2.2: 100% loss",
                root_cause=f"Missing static route on {self.target_node}",
                affected_nodes=[self.target_node],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                severity=SeverityLevel.HIGH,
                confidence_score=0.9,
                evidence=["Ping failure: pc1 -> 10.2.2.2: 100% loss"],
            )
        elif response_schema == RemediationPlan:
            return RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity=self.target_node,
                exec_commands=[
                    "vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'",
                ],
                rollback_steps=[
                    RollbackStep(
                        step_order=1,
                        description="Remove added route",
                        action="EXEC_COMMAND",
                        target_node=self.target_node,
                        payload="vtysh -c 'configure terminal' -c 'no ip route 10.2.2.0/24 10.1.12.2'",
                    ),
                ],
                expected_outcome="pc1 can ping pc2 at 10.2.2.2",
                estimated_risk=SeverityLevel.LOW,
            )
        raise ValueError(f"Unexpected schema: {response_schema}")


# ---------------------------------------------------------------------------
# Mock Lab Adapter for Day-2 testing
# ---------------------------------------------------------------------------

class MockDay2LabAdapter(BaseNetworkLabAdapter):
    """Mock adapter that simulates a 4-node Containerlab topology."""

    def __init__(self, healthy: bool = True, fix_after_patch: bool = True):
        self.healthy = healthy
        self.fix_after_patch = fix_after_patch
        self.patched = False
        self.exec_log: List[Dict[str, str]] = []

    def deploy(self, topo_file, reconfigure=True) -> DeploymentResult:
        return DeploymentResult(
            success=True, lab_name="lab", topo_file=str(topo_file),
            nodes_deployed=["pc1", "frr1", "srl1", "pc2"],
        )

    def destroy(self, topo_file=None, lab_name=None, cleanup=True) -> DestructionResult:
        return DestructionResult(success=True, lab_name="lab")

    def inspect(self, topo_file=None, lab_name=None) -> LabInspectionResult:
        nodes = [
            LabNodeState(name="pc1", container_id="clab-lab-pc1", image="alpine", kind="linux", state="running", ipv4_address="172.100.100.2"),
            LabNodeState(name="frr1", container_id="clab-lab-frr1", image="frrouting/frr", kind="linux", state="running", ipv4_address="172.100.100.3"),
            LabNodeState(name="srl1", container_id="clab-lab-srl1", image="ghcr.io/nokia/srlinux", kind="nokia_srlinux", state="running", ipv4_address="172.100.100.4"),
            LabNodeState(name="pc2", container_id="clab-lab-pc2", image="alpine", kind="linux", state="running", ipv4_address="172.100.100.5"),
        ]
        return LabInspectionResult(success=True, lab_name="lab", nodes=nodes)

    def exec_command(self, node_name: str, command: str, timeout: int = 15) -> CommandResult:
        self.exec_log.append({"node": node_name, "command": command})

        # ip addr show responses
        if "ip addr show" in command:
            ip_map = {
                "pc1": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.1.2/24 scope global eth1\n    inet 172.100.100.2/24 scope global eth0",
                "frr1": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.1.1/24 scope global eth1\n3: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.12.1/24 scope global eth2\n    inet 172.100.100.3/24 scope global eth0",
                "srl1": "2: e1-1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.12.2/24 scope global e1-1\n3: e1-2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.2.2.1/24 scope global e1-2\n    inet 172.100.100.4/24 scope global mgmt0",
                "pc2": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.2.2.2/24 scope global eth1\n    inet 172.100.100.5/24 scope global eth0",
            }
            return CommandResult(command=command, exit_code=0, stdout=ip_map.get(node_name, ""), node=node_name)

        # Remediation commands (MUST be checked before generic 'route' handler,
        # since configure commands like 'ip route ...' also contain 'route')
        if "vtysh" in command and "configure" in command:
            self.patched = True
            return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

        # ip route show / vtysh show ip route / sr_cli route table
        if "route" in command.lower():
            if node_name == "pc1":
                return CommandResult(command=command, exit_code=0, stdout="default via 10.1.1.1 dev eth1\n10.1.1.0/24 dev eth1 proto kernel scope link", node=node_name)
            elif node_name == "frr1":
                if self.healthy or self.patched:
                    return CommandResult(command=command, exit_code=0, stdout="C>* 10.1.1.0/24 is directly connected, eth1\nC>* 10.1.12.0/24 is directly connected, eth2\nS>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2", node=node_name)
                else:
                    # Missing route to 10.2.2.0/24
                    return CommandResult(command=command, exit_code=0, stdout="C>* 10.1.1.0/24 is directly connected, eth1\nC>* 10.1.12.0/24 is directly connected, eth2", node=node_name)
            elif node_name == "srl1":
                return CommandResult(command=command, exit_code=0, stdout="10.1.12.0/24 local direct e1-1\n10.2.2.0/24 local direct e1-2\n10.1.1.0/24 static 10.1.12.1 e1-1", node=node_name)
            elif node_name == "pc2":
                return CommandResult(command=command, exit_code=0, stdout="default via 10.2.2.1 dev eth1\n10.2.2.0/24 dev eth1 proto kernel scope link", node=node_name)

        # Running config
        if "running-config" in command or "info flat" in command:
            return CommandResult(command=command, exit_code=0, stdout="! mock running config", node=node_name)

        # Ping responses
        if "ping" in command:
            dst_ip = command.split()[-1]
            # Check if path works
            reachable = self.healthy or (self.patched and self.fix_after_patch)

            if reachable or self._is_adjacent_ping(node_name, dst_ip):
                return CommandResult(
                    command=command, exit_code=0,
                    stdout=f"PING {dst_ip}: 3 packets transmitted, 3 received, 0% packet loss\nrtt min/avg/max/mdev = 0.1/0.2/0.3/0.05 ms",
                    node=node_name,
                )
            else:
                return CommandResult(
                    command=command, exit_code=1,
                    stdout=f"PING {dst_ip}: 3 packets transmitted, 0 received, 100% packet loss",
                    node=node_name,
                )

        return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

    def is_live_ready(self) -> bool:
        return True

    def _is_adjacent_ping(self, src: str, dst_ip: str) -> bool:
        """Check if the ping target is an adjacent node (always reachable)."""
        adjacent = {
            "pc1": ["10.1.1.1"],
            "frr1": ["10.1.1.2", "10.1.12.2"],
            "srl1": ["10.1.12.1", "10.2.2.2"],
            "pc2": ["10.2.2.1"],
        }
        return dst_ip in adjacent.get(src, [])


# ===========================================================================
# Edge Tests
# ===========================================================================

class TestRouteAfterProbe:
    def test_healthy(self):
        state = create_day2_initial_state()
        state["probe_results"] = {"all_passed": True, "failures": []}
        assert route_after_probe(state) == "end_healthy"

    def test_failure(self):
        state = create_day2_initial_state()
        state["probe_results"] = {"all_passed": False, "failures": ["Ping fail"]}
        assert route_after_probe(state) == "hop_pruning"

    def test_none_results(self):
        state = create_day2_initial_state()
        assert route_after_probe(state) == "hop_pruning"


class TestRouteAfterDryRun:
    def test_passed(self):
        state = create_day2_initial_state()
        state["dry_run_passed"] = True
        assert route_after_dry_run(state) == "human_approval"

    def test_failed_retries_remain(self):
        state = create_day2_initial_state(max_retries=3)
        state["dry_run_passed"] = False
        state["retry_count"] = 1
        assert route_after_dry_run(state) == "llm_diagnosis"

    def test_failed_exhausted(self):
        state = create_day2_initial_state(max_retries=3)
        state["dry_run_passed"] = False
        state["retry_count"] = 3
        assert route_after_dry_run(state) == "circuit_breaker"


class TestRouteAfterApproval:
    def test_approved(self):
        state = create_day2_initial_state()
        state["human_approved"] = True
        assert route_after_approval(state) == "hot_patch"

    def test_rejected(self):
        state = create_day2_initial_state()
        state["human_approved"] = False
        assert route_after_approval(state) == "end_rejected"


class TestRouteAfterReVerify:
    def test_fixed(self):
        state = create_day2_initial_state()
        state["re_verify_results"] = {"all_passed": True}
        assert route_after_re_verify(state) == "end_fixed"

    def test_still_failing_retries(self):
        state = create_day2_initial_state(max_retries=3)
        state["re_verify_results"] = {"all_passed": False}
        state["retry_count"] = 1
        assert route_after_re_verify(state) == "llm_diagnosis"

    def test_still_failing_exhausted(self):
        state = create_day2_initial_state(max_retries=3)
        state["re_verify_results"] = {"all_passed": False}
        state["retry_count"] = 3
        assert route_after_re_verify(state) == "circuit_breaker"


# ===========================================================================
# DryRunChecker Tests
# ===========================================================================

class TestDryRunChecker:
    def test_safe_plan_passes(self):
        plan = {
            "target_entity": "frr1",
            "exec_commands": ["vtysh -c 'show ip route'"],
            "rollback_steps": [{"step_order": 1, "description": "undo", "action": "EXEC_COMMAND", "target_node": "frr1"}],
        }
        passed, errors = DryRunChecker.check(plan)
        assert passed is True

    def test_blocked_command(self):
        plan = {
            "target_entity": "frr1",
            "exec_commands": ["rm -rf /etc/frr/*"],
        }
        passed, errors = DryRunChecker.check(plan)
        assert passed is False
        assert any("BLOCKED" in e for e in errors)

    def test_invalid_target(self):
        plan = {
            "target_entity": "nonexistent",
            "exec_commands": [],
        }
        baseline = {"nodes": {"frr1": {"state": "running"}}}
        passed, errors = DryRunChecker.check(plan, baseline=baseline)
        assert passed is False
        assert any("not found" in e for e in errors)

    def test_missing_rollback_warning(self):
        plan = {
            "target_entity": "frr1",
            "exec_commands": ["vtysh -c 'show ip route'"],
        }
        passed, errors = DryRunChecker.check(plan)
        # Missing rollback is a WARNING, not a blocking error
        assert passed is True
        assert any("WARNING" in e for e in errors)

    def test_invalid_ip_in_command(self):
        plan = {
            "target_entity": "frr1",
            "exec_commands": ["ip route add 999.999.999.999/24 via 10.1.1.1"],
            "rollback_steps": [{"step_order": 1, "description": "undo", "action": "EXEC_COMMAND", "target_node": "frr1"}],
        }
        passed, errors = DryRunChecker.check(plan)
        assert passed is False


# ===========================================================================
# Graph Compilation Test
# ===========================================================================

class TestDay2GraphCompilation:
    def test_graph_compiles(self):
        from langgraph_netagent.workflow.day2_graph import build_day2_graph
        llm = MockDay2LLMProvider()
        adapter = MockDay2LabAdapter(healthy=True)
        graph = build_day2_graph(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="lab",
            auto_approve=True,
        )
        assert graph is not None

    def test_healthy_path(self):
        """When network is healthy, workflow should end at 'healthy' status."""
        from langgraph_netagent.workflow.day2_graph import run_day2_workflow
        llm = MockDay2LLMProvider()
        adapter = MockDay2LabAdapter(healthy=True)
        result = run_day2_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="lab",
            auto_approve=True,
        )
        assert result["status"] == "healthy"

    def test_fault_and_heal_path(self):
        """When network has a fault, workflow should diagnose, patch, and verify."""
        from langgraph_netagent.workflow.day2_graph import run_day2_workflow
        llm = MockDay2LLMProvider(target_node="frr1")
        adapter = MockDay2LabAdapter(healthy=False, fix_after_patch=True)
        result = run_day2_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="lab",
            max_retries=3,
            auto_approve=True,
        )
        assert result["status"] == "fixed"
        assert result.get("diagnostic_report") is not None
        assert result.get("remediation_plan") is not None
        # Verify remediation was executed
        assert adapter.patched is True

    def test_rejection_path(self):
        """When operator rejects, workflow should end at 'rejected'."""
        from langgraph_netagent.workflow.day2_graph import run_day2_workflow
        llm = MockDay2LLMProvider()
        adapter = MockDay2LabAdapter(healthy=False, fix_after_patch=True)

        # Create state with explicit rejection
        from langgraph_netagent.workflow.day2_state import create_day2_initial_state
        from langgraph_netagent.workflow.day2_graph import build_day2_graph

        graph = build_day2_graph(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="lab",
            auto_approve=False,  # Manual approval mode
        )
        state = create_day2_initial_state(max_retries=3, auto_approve=False)
        state["human_approved"] = False  # Pre-reject

        result = graph.invoke(state)
        assert result["status"] == "rejected"
