"""Unit and Integration Tests for Agentic Reasoning and Deterministic Execution (R3).

Tests:
1. DiagnosticStrategy taxonomy and deterministic selection from StateDiff.
2. RepairAction and RepairPlan data models and bidirectional legacy adapters.
3. DiagnosticReasoningEngine prompt density (<500B), strategy selection, and deterministic plan generation.
4. DeterministicExecutor transactional execution, pre/post checks, and LIFO rollback upon failure.
5. DeterministicExecutor LabIsolationGuard integration restricting execution to clos5 containers.
6. ProgrammaticVerifier post-repair recovery verification and residual fault detection.
7. End-to-end integration across diagnostic_stage1_node, diagnostic_stage2_node, live_hot_patch_node, and re_verification_node.
"""

from __future__ import annotations

import copy
import pytest
from typing import Any, Dict, List

from langgraph_netagent.models.network_state import (
    InterfaceState,
    NetworkState,
    NodeState,
    QdiscState,
    ReachabilityState,
    RouteState,
    StateDiff,
    compute_state_diff,
)
from langgraph_netagent.models.reasoning import (
    DiagnosticStrategy,
    DiagnosticStrategySelector,
    StrategySelectionResult,
)
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan
from langgraph_netagent.models.repair_plan import RepairAction, RepairPlan
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.deterministic_executor import DeterministicExecutor, ExecutionResult
from langgraph_netagent.tools.lab_isolation import LabIsolationGuard, LabIsolationViolationError
from langgraph_netagent.tools.mock_engine import (
    MockContainerlabAdapter,
    VirtualInterface,
    VirtualNetworkGraph,
    VirtualNode,
)
from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter
from langgraph_netagent.workflow.operational_nodes import create_operational_nodes
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)
from langgraph_netagent.workflow.programmatic_verifier import ProgrammaticVerifier, VerificationResult
from langgraph_netagent.workflow.reasoning_engine import DiagnosticReasoningEngine


# =============================================================================
# Helper Fixtures & Builders
# =============================================================================

def build_healthy_baseline() -> NetworkState:
    """Build a clean healthy baseline NetworkState for clos5."""
    nodes = {
        "leaf1": NodeState(
            node_name="leaf1",
            role="leaf",
            status="healthy",
            interfaces={
                "lo": InterfaceState(name="lo", admin_state="UP", oper_state="UP", ipv4_addresses=["127.0.0.1/8"]),
                "eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP", ipv4_addresses=["172.16.1.1/24"]),
                "eth2": InterfaceState(name="eth2", admin_state="UP", oper_state="UP", ipv4_addresses=["10.0.1.1/30"]),
            },
            routes=[
                RouteState(prefix="172.16.1.0/24", interface="eth1", protocol="connected", active=True),
                RouteState(prefix="172.16.2.0/24", next_hop="10.0.1.2", interface="eth2", protocol="bgp", active=True),
            ],
            qdiscs={
                "eth1": QdiscState(interface="eth1", qdisc_type="fq_codel", loss_percent=0.0, delay_ms=0.0),
            },
        ),
        "leaf2": NodeState(
            node_name="leaf2",
            role="leaf",
            status="healthy",
            interfaces={
                "lo": InterfaceState(name="lo", admin_state="UP", oper_state="UP", ipv4_addresses=["127.0.0.1/8"]),
                "eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP", ipv4_addresses=["172.16.2.1/24"]),
            },
            routes=[
                RouteState(prefix="172.16.2.0/24", interface="eth1", protocol="connected", active=True),
                RouteState(prefix="172.16.1.0/24", next_hop="10.0.1.1", interface="eth2", protocol="bgp", active=True),
            ],
            qdiscs={},
        ),
        "dc-egress": NodeState(
            node_name="dc-egress",
            role="egress",
            status="healthy",
            interfaces={
                "eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP", ipv4_addresses=["172.16.254.1/24"]),
            },
            routes=[
                RouteState(prefix="default", next_hop="192.168.100.1", interface="eth1", protocol="static", active=True),
            ],
            qdiscs={
                "eth1": QdiscState(interface="eth1", qdisc_type="fq_codel", loss_percent=0.0, delay_ms=0.0, dropped_packets=0),
            },
        ),
    }

    reachability = [
        ReachabilityState(source="h1", destination="h2", reachable=True, packet_loss_pct=0.0, latency_ms=1.2),
        ReachabilityState(source="h2", destination="h1", reachable=True, packet_loss_pct=0.0, latency_ms=1.1),
    ]

    return NetworkState(nodes=nodes, reachability_matrix=reachability, healthy=True)


# =============================================================================
# 1. Tests for DiagnosticStrategy Taxonomy & Selection
# =============================================================================

class TestDiagnosticStrategyTaxonomy:
    """Tests for DiagnosticStrategy Enum and DiagnosticStrategySelector."""

    def test_diagnostic_strategy_enum_values(self):
        assert DiagnosticStrategy.LINK_RECOVERY == "link_recovery"
        assert DiagnosticStrategy.ROUTING_REPAIR == "routing_repair"
        assert DiagnosticStrategy.TRAFFIC_FILTERING_ACL == "traffic_filtering_acl"
        assert DiagnosticStrategy.INTERFACE_RESTART == "interface_restart"
        assert DiagnosticStrategy.QDISC_RESET == "qdisc_reset"
        assert DiagnosticStrategy.HEALTHY == "healthy"

    def test_diagnostic_strategy_normalization(self):
        assert DiagnosticStrategy("link_recovery") == DiagnosticStrategy.LINK_RECOVERY
        assert DiagnosticStrategy("LINK_RECOVERY") == DiagnosticStrategy.LINK_RECOVERY
        assert DiagnosticStrategy("routing-repair") == DiagnosticStrategy.ROUTING_REPAIR
        assert DiagnosticStrategy("qdisc_reset") == DiagnosticStrategy.QDISC_RESET
        assert DiagnosticStrategy("traffic-filtering-acl") == DiagnosticStrategy.TRAFFIC_FILTERING_ACL

    def test_select_strategy_healthy(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        diff = compute_state_diff(baseline, current)

        decision = DiagnosticStrategySelector.select(diff)
        assert decision.primary_strategy == DiagnosticStrategy.HEALTHY
        assert decision.secondary_strategy is None
        assert decision.confidence == 1.0

    def test_select_strategy_link_down(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        current.nodes["leaf1"].interfaces["eth1"].oper_state = "DOWN"
        current.nodes["leaf1"].interfaces["eth1"].admin_state = "DOWN"

        diff = compute_state_diff(baseline, current)
        decision = DiagnosticStrategySelector.select(diff)

        assert decision.primary_strategy == DiagnosticStrategy.LINK_RECOVERY
        assert "leaf1" in decision.affected_nodes
        assert "leaf1:eth1" in decision.reasoning

    def test_select_strategy_route_missing(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        # Drop route to 172.16.2.0/24 on leaf1
        current.nodes["leaf1"].routes = [r for r in current.nodes["leaf1"].routes if r.prefix != "172.16.2.0/24"]

        diff = compute_state_diff(baseline, current)
        decision = DiagnosticStrategySelector.select(diff)

        assert decision.primary_strategy == DiagnosticStrategy.ROUTING_REPAIR
        assert "leaf1" in decision.affected_nodes
        assert "172.16.2.0/24" in decision.reasoning

    def test_select_strategy_qdisc_netem(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        current.nodes["leaf1"].qdiscs["eth1"] = QdiscState(
            interface="eth1",
            qdisc_type="netem",
            loss_percent=25.0,
            delay_ms=50.0,
        )

        diff = compute_state_diff(baseline, current)
        decision = DiagnosticStrategySelector.select(diff)

        assert decision.primary_strategy == DiagnosticStrategy.QDISC_RESET
        assert "leaf1" in decision.affected_nodes
        assert "25%" in decision.reasoning or "50ms" in decision.reasoning

    def test_select_strategy_compound_faults(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        # Link down AND missing route
        current.nodes["leaf1"].interfaces["eth1"].oper_state = "DOWN"
        current.nodes["leaf1"].routes = []

        diff = compute_state_diff(baseline, current)
        decision = DiagnosticStrategySelector.select(diff)

        assert decision.primary_strategy == DiagnosticStrategy.LINK_RECOVERY
        assert decision.secondary_strategy == DiagnosticStrategy.ROUTING_REPAIR


# =============================================================================
# 2. Tests for RepairAction, RepairPlan & Legacy Adapters
# =============================================================================

class TestRepairPlanModels:
    """Tests for RepairAction and RepairPlan data structures and compatibility adapters."""

    def test_repair_action_creation(self):
        action = RepairAction(
            action_id="act-1",
            target_node="leaf1",
            action_type="link_up",
            command="ip link set dev eth1 up",
            pre_check_command="ip link show dev eth1",
            expected_pre_condition="DOWN",
            post_check_command="ip link show dev eth1",
            expected_post_condition="UP",
            rollback_command="ip link set dev eth1 down",
        )
        assert action.target_node == "leaf1"
        assert action.action_type == "link_up"
        assert action.rollback_command == "ip link set dev eth1 down"

        rb_step = action.to_rollback_step(step_number=1)
        assert rb_step is not None
        assert rb_step.command == "ip link set dev eth1 down"
        assert rb_step.target_node == "leaf1"

    def test_repair_plan_to_legacy_remediation_plan(self):
        plan = RepairPlan(
            incident_id="inc-test-01",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-2",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth2 up",
                    rollback_command="ip link set dev eth2 down",
                ),
            ],
            justification="Restore fabric links on leaf1",
        )

        legacy = plan.to_legacy_remediation_plan()
        assert isinstance(legacy, RemediationPlan)
        assert legacy.target_entity == "leaf1"
        assert legacy.action_type == RemediationActionType.EXEC_RUNTIME_COMMAND
        assert legacy.exec_commands == ["ip link set dev eth1 up", "ip link set dev eth2 up"]
        # Rollbacks must be in reverse LIFO order
        assert len(legacy.rollback_steps) == 2
        assert legacy.rollback_steps[0].command == "ip link set dev eth2 down"
        assert legacy.rollback_steps[1].command == "ip link set dev eth1 down"

    def test_from_legacy_remediation_plan_bidirectional(self):
        legacy = RemediationPlan(
            plan_id="fix-legacy-01",
            action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
            target_entity="leaf1",
            exec_commands=["ip link set dev eth1 up"],
            rollback_steps=[],
            expected_outcome="Interface recovered",
        )

        converted = RepairPlan.from_legacy_remediation_plan(legacy, strategy=DiagnosticStrategy.LINK_RECOVERY)
        assert converted.plan_id == "fix-legacy-01"
        assert converted.strategy == DiagnosticStrategy.LINK_RECOVERY
        assert converted.target_node == "leaf1"
        assert len(converted.actions) == 1
        assert converted.actions[0].command == "ip link set dev eth1 up"


# =============================================================================
# 3. Tests for DiagnosticReasoningEngine
# =============================================================================

class TestDiagnosticReasoningEngine:
    """Tests for DiagnosticReasoningEngine plan formulation and deterministic fallback."""

    def test_prompt_density_budget(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        current.nodes["leaf1"].interfaces["eth1"].oper_state = "DOWN"
        diff = compute_state_diff(baseline, current)

        engine = DiagnosticReasoningEngine()
        prompt = engine.format_prompt(state_diff=diff)

        # High density markdown verification (<500 bytes and <200 tokens)
        prompt_bytes = len(prompt.encode("utf-8"))
        assert prompt_bytes < 500, f"Prompt byte size exceeded: {prompt_bytes} bytes"
        assert "Links Down: leaf1:eth1" in prompt

    def test_plan_generation_link_down(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        current.nodes["leaf1"].interfaces["eth1"].oper_state = "DOWN"
        diff = compute_state_diff(baseline, current)

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(state_diff=diff)

        assert plan.strategy == DiagnosticStrategy.LINK_RECOVERY
        assert len(plan.actions) >= 1
        first_act = plan.actions[0]
        assert first_act.target_node == "leaf1"
        assert first_act.command == "ip link set dev eth1 up"
        assert first_act.rollback_command == "ip link set dev eth1 down"
        assert first_act.expected_pre_condition == "DOWN"
        assert first_act.expected_post_condition == "UP"

    def test_plan_generation_route_missing(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        current.nodes["leaf1"].routes = [r for r in current.nodes["leaf1"].routes if r.prefix != "172.16.2.0/24"]
        diff = compute_state_diff(baseline, current)

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(state_diff=diff)

        assert plan.strategy == DiagnosticStrategy.ROUTING_REPAIR
        assert len(plan.actions) >= 1
        act = plan.actions[0]
        assert act.target_node == "leaf1"
        assert "ip route replace 172.16.2.0/24" in act.command
        assert "ip route del 172.16.2.0/24" in act.rollback_command

    def test_plan_generation_packet_loss(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        current.nodes["leaf1"].qdiscs["eth1"] = QdiscState(
            interface="eth1",
            qdisc_type="netem",
            loss_percent=30.0,
        )
        diff = compute_state_diff(baseline, current)

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(state_diff=diff)

        assert plan.strategy == DiagnosticStrategy.QDISC_RESET
        assert len(plan.actions) >= 1
        act = plan.actions[0]
        assert act.target_node == "leaf1"
        assert act.command == "tc qdisc del dev eth1 root"
        assert "tc qdisc add dev eth1 root netem" in act.rollback_command

    def test_plan_generation_healthy_returns_empty_plan(self):
        baseline = build_healthy_baseline()
        current = copy.deepcopy(baseline)
        diff = compute_state_diff(baseline, current)

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(state_diff=diff)

        assert plan.strategy == DiagnosticStrategy.HEALTHY
        assert len(plan.actions) == 0


# =============================================================================
# 4. Tests for DeterministicExecutor
# =============================================================================

class TestDeterministicExecutor:
    """Tests for DeterministicExecutor with atomic pre/post assertions and LIFO rollback."""

    def test_successful_execution_with_pre_post_checks(self):
        mock_adapter = MockContainerlabAdapter()
        # Seed leaf1 with eth1 DOWN in mock graph
        vnode = VirtualNode(name="leaf1", kind="linux")
        vnode.add_interface(VirtualInterface(name="eth1", oper_state="DOWN"))
        mock_adapter.mock_engine.graph.nodes["leaf1"] = vnode

        executor = DeterministicExecutor(lab_adapter=mock_adapter)

        plan = RepairPlan(
            incident_id="inc-test-02",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    pre_check_command="ip link show dev eth1",
                    expected_pre_condition="DOWN",
                    post_check_command="ip link show dev eth1",
                    expected_post_condition="UP",
                    rollback_command="ip link set dev eth1 down",
                )
            ],
        )

        result: ExecutionResult = executor.execute_plan(plan)
        assert result.success is True
        assert result.error is None
        assert result.rolled_back is False
        assert len(result.executed_actions) == 1
        # Interface should now be UP in mock graph
        assert vnode.interfaces["eth1"].oper_state == "UP"

    def test_pre_check_failure_triggers_immediate_halt_and_rollback(self):
        mock_adapter = MockContainerlabAdapter()
        # Seed leaf1 with eth1 already UP
        vnode = VirtualNode(name="leaf1", kind="linux")
        vnode.add_interface(VirtualInterface(name="eth1", oper_state="UP"))
        mock_adapter.mock_engine.graph.nodes["leaf1"] = vnode

        executor = DeterministicExecutor(lab_adapter=mock_adapter)

        plan = RepairPlan(
            incident_id="inc-test-03",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    pre_check_command="ip link show dev eth1",
                    expected_pre_condition="DOWN",  # Expect DOWN, but it's UP!
                    rollback_command="ip link set dev eth1 down",
                )
            ],
        )

        result: ExecutionResult = executor.execute_plan(plan)
        assert result.success is False
        assert "Pre-check assertion failed" in result.error
        assert result.rolled_back is True

    def test_command_failure_triggers_lifo_rollback(self):
        mock_adapter = MockContainerlabAdapter()
        # Seed leaf1 with eth1 DOWN and eth2 DOWN
        vnode = VirtualNode(name="leaf1", kind="linux")
        vnode.add_interface(VirtualInterface(name="eth1", oper_state="DOWN"))
        vnode.add_interface(VirtualInterface(name="eth2", oper_state="DOWN"))
        mock_adapter.mock_engine.graph.nodes["leaf1"] = vnode

        executor = DeterministicExecutor(lab_adapter=mock_adapter)

        orig_exec = mock_adapter.exec_command
        def fail_on_act2(node_name: str, command: str, **kwargs: Any) -> CommandResult:
            if "invalid_fake_command_failure" in command:
                return CommandResult(command=command, exit_code=1, stderr="Simulated CLI execution failure", node=node_name)
            return orig_exec(node_name=node_name, command=command, **kwargs)
        mock_adapter.exec_command = fail_on_act2

        # Plan has 2 actions: act 1 succeeds, act 2 executes invalid command
        plan = RepairPlan(
            incident_id="inc-test-04",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-2",
                    target_node="leaf1",
                    action_type="fail_cmd",
                    command="invalid_fake_command_failure",
                    rollback_command="ip link set dev eth2 down",
                ),
            ],
        )

        result: ExecutionResult = executor.execute_plan(plan)
        assert result.success is False
        assert result.rolled_back is True
        # Transactional rollback should have reversed act-1 back to DOWN!
        assert vnode.interfaces["eth1"].oper_state == "DOWN"

    def test_post_check_failure_triggers_rollback(self):
        mock_adapter = MockContainerlabAdapter()
        vnode = VirtualNode(name="leaf1", kind="linux")
        vnode.add_interface(VirtualInterface(name="eth1", oper_state="DOWN"))
        mock_adapter.mock_engine.graph.nodes["leaf1"] = vnode

        executor = DeterministicExecutor(lab_adapter=mock_adapter)

        plan = RepairPlan(
            incident_id="inc-test-05",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    post_check_command="ip link show dev eth1",
                    expected_post_condition="NON_EXISTENT_STATE_XYZ",  # Will fail!
                    rollback_command="ip link set dev eth1 down",
                )
            ],
        )

        result: ExecutionResult = executor.execute_plan(plan)
        assert result.success is False
        assert "Post-check assertion failed" in result.error
        assert result.rolled_back is True
        # Rollback reversed eth1 back to DOWN
        assert vnode.interfaces["eth1"].oper_state == "DOWN"

    def test_lab_isolation_blocks_unauthorized_container(self):
        mock_adapter = MockContainerlabAdapter()
        executor = DeterministicExecutor(lab_adapter=mock_adapter)

        plan = RepairPlan(
            incident_id="inc-test-06",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="unauthorized_host_node",  # Not in clos5!
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="unauthorized_host_node",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                )
            ],
        )

        result = executor.execute_plan(plan)
        assert result.success is False
        assert "Lab isolation boundary violation" in result.error
        assert result.rolled_back is True

    def test_lab_isolation_blocks_host_interface_mutation(self):
        mock_adapter = MockContainerlabAdapter()
        vnode = VirtualNode(name="leaf1", kind="linux")
        mock_adapter.mock_engine.graph.nodes["leaf1"] = vnode
        executor = DeterministicExecutor(lab_adapter=mock_adapter)

        plan = RepairPlan(
            incident_id="inc-test-07",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev docker0 down",  # Prohibited host NIC!
                    rollback_command="ip link set dev docker0 up",
                )
            ],
        )

        result = executor.execute_plan(plan)
        assert result.success is False
        assert "Lab isolation boundary violation" in result.error or "targets protected host interface" in result.error
        assert result.rolled_back is True


# =============================================================================
# 5. Tests for ProgrammaticVerifier
# =============================================================================

class TestProgrammaticVerifier:
    """Tests for ProgrammaticVerifier validating health recovery or detecting residual faults."""

    def test_verifier_passes_when_state_restored(self):
        baseline = build_healthy_baseline()
        post_repair = copy.deepcopy(baseline)

        verifier = ProgrammaticVerifier()
        result: VerificationResult = verifier.verify_repair(baseline=baseline, post_repair=post_repair)

        assert result.passed is True
        assert "PASSED" in result.details
        assert len(result.unresolved_anomalies) == 0

    def test_verifier_fails_when_interface_down_persists(self):
        baseline = build_healthy_baseline()
        post_repair = copy.deepcopy(baseline)
        post_repair.nodes["leaf1"].interfaces["eth1"].oper_state = "DOWN"

        verifier = ProgrammaticVerifier()
        result: VerificationResult = verifier.verify_repair(baseline=baseline, post_repair=post_repair)

        assert result.passed is False
        assert any("leaf1:eth1 remains DOWN" in u for u in result.unresolved_anomalies)

    def test_verifier_fails_when_route_missing_persists(self):
        baseline = build_healthy_baseline()
        post_repair = copy.deepcopy(baseline)
        post_repair.nodes["leaf1"].routes = [r for r in post_repair.nodes["leaf1"].routes if r.prefix != "172.16.2.0/24"]

        verifier = ProgrammaticVerifier()
        result: VerificationResult = verifier.verify_repair(baseline=baseline, post_repair=post_repair)

        assert result.passed is False
        assert any("172.16.2.0/24 on leaf1 remains missing" in u for u in result.unresolved_anomalies)

    def test_verifier_fails_when_packet_loss_persists(self):
        baseline = build_healthy_baseline()
        post_repair = copy.deepcopy(baseline)
        post_repair.nodes["leaf1"].qdiscs["eth1"] = QdiscState(interface="eth1", loss_percent=15.0)

        verifier = ProgrammaticVerifier()
        result: VerificationResult = verifier.verify_repair(baseline=baseline, post_repair=post_repair)

        assert result.passed is False
        assert any("Netem loss remains" in u for u in result.unresolved_anomalies)


# =============================================================================
# 6. End-to-End Operational Workflow Integration
# =============================================================================

class TestOperationalWorkflowIntegration:
    """Tests end-to-end integration across operational nodes in mock mode."""

    def test_stage1_stage2_live_patch_reverify_integration(self):
        mock_adapter = MockContainerlabAdapter()
        # Setup mock topology with leaf1:eth1 DOWN
        vnode1 = VirtualNode(name="leaf1", kind="linux")
        vnode1.add_interface(VirtualInterface(name="eth1", oper_state="DOWN"))
        mock_adapter.mock_engine.graph.nodes["leaf1"] = vnode1

        nodes = create_operational_nodes(
            llm_provider=None,
            lab_adapter=mock_adapter,
            auto_approve=True,
        )

        state = create_operational_initial_state(auto_approve=True)
        state["suspect_devices"] = ["leaf1"]
        state["discrepancies"] = [{"discrepancy_type": "interface_down", "node": "leaf1", "interface": "eth1"}]

        # 1. Execute diagnostic_stage1_node
        s1_out = nodes["diagnostic_stage1"](state)
        assert s1_out["status"] == "stage1_enriched"
        assert "state_diff" in s1_out
        state.update(s1_out)

        # 2. Execute diagnostic_stage2_node
        s2_out = nodes["diagnostic_stage2"](state)
        assert s2_out["status"] == "stage2_plan_generated"
        assert "repair_plan" in s2_out
        assert s2_out["repair_plan"] is not None
        assert s2_out["repair_plan"]["strategy"] == "link_recovery"
        state.update(s2_out)

        # 3. Execute live_hot_patch_node
        patch_out = nodes["live_hot_patch"](state)
        assert patch_out["status"] == "patched"
        assert patch_out["patch_result"]["all_ok"] is True
        # leaf1:eth1 must now be UP in mock engine
        assert vnode1.interfaces["eth1"].oper_state == "UP"
        state.update(patch_out)

        # 4. Execute re_verification_node
        reverify_out = nodes["re_verification"](state)
        assert reverify_out["status"] == "re_verified"
