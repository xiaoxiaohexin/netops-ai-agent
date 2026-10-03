"""Empirical Adversarial Stress Tests for Milestone M3 (Suite 2):
State Machine Closed-Loop Mechanics, Conditional Edge Routing, Circuit Breakers, and SimpleStateGraph Engine.

Authored by challenger_net_m3_2.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock
import pytest

from langgraph_netagent.llm import LLMConfig, MockLLMProvider
from langgraph_netagent.models.diagnostic import (
    DiagnosticReport,
    ErrorCategory,
    SeverityLevel,
)
from langgraph_netagent.models.intent import NetworkIntent, NodeIntent, LinkIntent
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
)
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
)
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, MockEngine
from langgraph_netagent.workflow.edges import (
    route_after_approval,
    route_after_deployment,
    route_after_validation,
    route_after_verification,
)
from langgraph_netagent.workflow.graph import (
    END,
    START,
    CompiledSimpleGraph,
    SimpleMemorySaver,
    SimpleStateGraph,
    build_network_agent_graph,
    run_network_agent_workflow,
)
from langgraph_netagent.workflow.nodes import (
    DiagnosticAndRemediation,
    create_workflow_nodes,
)
from langgraph_netagent.workflow.state import (
    NetworkAgentState,
    create_initial_state,
    create_log_entry,
)


# ==============================================================================
# Helper Factories
# ==============================================================================

def make_invalid_package_bad_name(base: FullTopologyPackage) -> FullTopologyPackage:
    """Create a topology package with an invalid RFC 1123 node name."""
    pkg = base.model_copy(deep=True)
    pkg.topology.topology.nodes["INVALID__NAME!!"] = ContainerlabNodeConfig(
        kind="linux",
        image="alpine:latest",
    )
    return pkg


def make_invalid_package_ip_collision(base: FullTopologyPackage) -> FullTopologyPackage:
    """Create a topology package with colliding IPv4 addresses."""
    pkg = base.model_copy(deep=True)
    pkg.ip_allocations.append(
        IPAllocation(
            node_name="rogue_node",
            interface_name="eth0",
            ipv4_address="10.1.1.2/24",  # collides with pc1
        )
    )
    return pkg


# ==============================================================================
# 1. State Machine Closed-Loop Mechanics Tests
# ==============================================================================

class TestValidationClosedLoopMechanics:
    """Adversarial stress-testing of the Validation Feedback and Retry Loop."""

    def test_validation_retry_loop_recovers_with_feedback(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Stress: Fails validation on attempt 1 (bad name), fails on attempt 2 (IP collision),

        then recovers on attempt 3 with valid package.
        """
        mock_llm.register_canned_response(sample_network_intent)

        # Attempt 1: bad node name
        pkg_fail_1 = make_invalid_package_bad_name(sample_topology_package)
        mock_llm.register_canned_response(pkg_fail_1)

        # Attempt 2: IP collision
        pkg_fail_2 = make_invalid_package_ip_collision(sample_topology_package)
        mock_llm.register_canned_response(pkg_fail_2)

        # Attempt 3: clean topology
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Multi-attempt recovery test", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 2
        assert final_state["validation_result"]["is_valid"] is True
        assert final_state["verification_results"]["all_passed"] is True

        # Verify logs show both failure stages and the successful validation
        val_logs = [log for log in final_state["execution_logs"] if log["stage"] == "offline_validation"]
        assert len(val_logs) == 3
        assert val_logs[0]["level"] == "warning"
        assert val_logs[1]["level"] == "warning"
        assert val_logs[2]["level"] == "info"

    def test_validation_retry_loop_trips_circuit_breaker_on_retry_exhaustion(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Stress: Continuously returns invalid topology packages until max_retries is reached.

        Verify graph stops at circuit_breaker, marks status="circuit_broken", and does NOT deploy.
        """
        mock_llm.register_canned_response(sample_network_intent)

        # Register repeated invalid topology responses
        bad_pkg = make_invalid_package_bad_name(sample_topology_package)
        for _ in range(5):
            mock_llm.register_canned_response(bad_pkg)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Exhaust validation retries", max_retries=2)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] == 2
        assert "Circuit breaker tripped: retry limit exceeded (2/2)" in final_state["error_message"]
        assert final_state["deploy_status"] is None
        assert final_state["verification_results"] is None

        # Verify circuit_breaker log was emitted
        cb_logs = [log for log in final_state["execution_logs"] if log["stage"] == "circuit_breaker"]
        assert len(cb_logs) == 1
        assert cb_logs[0]["level"] == "critical"

    def test_validation_retry_boundary_max_retries_one(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Edge case: max_retries = 1.

        First failure must trip circuit breaker immediately without any loop-back.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(make_invalid_package_bad_name(sample_topology_package))

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Single retry boundary", max_retries=1)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] == 1
        assert "Circuit breaker tripped" in final_state["error_message"]

    def test_validation_retry_missing_raw_topology(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
    ):
        """Stress: raw_topology missing in state when entering offline_validation_node."""
        nodes = create_workflow_nodes(mock_llm, mock_adapter, tmp_path)
        state = create_initial_state("Missing raw topo")
        state["raw_topology"] = None
        state["retry_count"] = 0

        res = nodes["offline_validation"](state)
        assert res["status"] == "validation_failed"
        assert res["retry_count"] == 1
        assert "missing" in res["error_message"].lower()


class TestVerificationSelfHealingClosedLoopMechanics:
    """Adversarial stress-testing of Verification Telemetry Probing and Self-Healing Loops."""

    def test_self_healing_ping_drop_success(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Stress: PING_DROP fault active initially, cleared when on_retry(1) is called.

        Verifies diagnosis_and_healing_node applies patch, redeploys, passes, and exits cleanly.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        heal_plan = sample_remediation_plan.model_copy(deep=True)
        heal_plan.configuration_patch.new_content = (
            "hostname frr1\ninterface eth1\n ip address 10.1.1.1/24\nip route 10.2.2.0/24 10.1.12.2\n"
        )
        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=heal_plan,
        )
        mock_llm.register_canned_response(combo)

        # Inject PING_DROP active until retry 1
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
                active_until_retry=1,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Ping drop healing", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["diagnostic_report"] is not None
        assert final_state["remediation_plan"] is not None
        assert final_state["verification_results"]["all_passed"] is True

        # Check execution stages sequence
        stages = [log["stage"] for log in final_state["execution_logs"]]
        assert "diagnosis_and_healing" in stages
        deploy_indices = [i for i, s in enumerate(stages) if s == "deployment"]
        assert len(deploy_indices) == 2  # Initial deploy + redeploy after healing

    def test_self_healing_missing_route_success(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        full_multi_node_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Stress: MISSING_ROUTE fault cleared after 2 retries in multi-hop topology.

        Graph must loop through diagnosis_and_healing twice, redeploy twice, and verify.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(full_multi_node_package)

        heal_plan = sample_remediation_plan.model_copy(deep=True)
        heal_plan.configuration_patch.file_path = "config/frr/frr.conf"
        heal_plan.configuration_patch.new_content = """hostname frr1
service integrated-vtysh-config
!
interface eth1
 ip address 10.1.1.1/24
!
interface eth2
 ip address 10.1.12.1/24
!
ip route 10.2.2.0/24 10.1.12.2
!
line vty
!
"""
        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=heal_plan,
        )
        mock_llm.register_canned_response(combo)
        mock_llm.register_canned_response(combo)

        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.MISSING_ROUTE,
                target_node="frr1",
                target_ip_or_prefix="10.2.2.0/24",
                active_until_retry=2,
                cleared_on_remediation=False,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Route missing 2 retries", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 2
        assert final_state["verification_results"]["all_passed"] is True

    def test_self_healing_retry_exhaustion_trips_circuit_breaker(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Stress: Permanent ping drop (active_until_retry=999, cleared_on_remediation=False).

        Graph must attempt self-healing until max_retries=2, then route to circuit_breaker.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=sample_remediation_plan,
        )
        for _ in range(5):
            mock_llm.register_canned_response(combo)

        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
                active_until_retry=999,
                cleared_on_remediation=False,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Permanent ping drop", max_retries=2)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] == 2
        assert "Circuit breaker tripped: retry limit exceeded (2/2)" in final_state["error_message"]

    def test_deployment_failure_circuit_breaker_exhaustion(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Stress: Deployment continuously fails.

        Verify circuit breaker trips cleanly and prevents infinite loop.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.DEPLOY_FAILURE,
                target_node=None,
                cleared_on_remediation=False,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Permanent deploy failure", max_retries=2)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] >= 2
        assert "Circuit breaker tripped" in final_state["error_message"]


class TestHumanApprovalInterruptionAndRouting:
    """Adversarial stress-testing of Human Approval interruption and edge cases."""

    def test_human_approval_explicit_rejection_halts_cleanly(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Stress: Operator explicitly rejects deployment (human_approved=False in state).

        Workflow must halt at human_approval -> END with status="rejected", no deployment.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=False,
        )

        initial = create_initial_state("Rejection test", auto_approve=False)
        initial["human_approved"] = False  # Pre-set operator rejection

        final_state = app.invoke(initial)

        assert final_state["status"] == "rejected"
        assert final_state["human_approved"] is False
        assert "rejected" in final_state["error_message"].lower()
        # Ensure deployment was NEVER executed
        assert final_state["deploy_status"] is None
        assert final_state["verification_results"] is None

    def test_human_approval_pause_pending_mode(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Stress: auto_approve=False with human_approved=None (pending operator input).

        Workflow halts at END with status="pending_approval".
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=False,
        )

        initial = create_initial_state("Pending approval pause", auto_approve=False)
        assert initial["human_approved"] is None

        final_state = app.invoke(initial)

        assert final_state["status"] == "pending_approval"
        assert final_state["human_approved"] is None
        assert final_state["deploy_status"] is None

    def test_human_approval_retry_exhaustion_trips_circuit_breaker(self):
        """Edge test: route_after_approval with retry_count >= max_retries and human_approved != True."""
        state = create_initial_state("Approval exhaustion", max_retries=2)
        state["retry_count"] = 2
        state["human_approved"] = False

        dest = route_after_approval(state)
        assert dest == "circuit_breaker"


# ==============================================================================
# 2. SimpleStateGraph Engine Edge Cases Stress Tests
# ==============================================================================

class TestSimpleStateGraphEngineAdversarial:
    """Stress-testing edge cases in the SimpleStateGraph fallback engine."""

    def test_execution_order_invariance_scrambled_nodes(self):
        """Invariance: Adding nodes in reverse or random order does not alter graph execution order."""
        graph = SimpleStateGraph()
        # Add nodes in reverse order
        graph.add_node("step_3", lambda s: {"order": s.get("order", []) + [3]})
        graph.add_node("step_2", lambda s: {"order": s.get("order", []) + [2]})
        graph.add_node("step_1", lambda s: {"order": s.get("order", []) + [1]})

        # Edges strictly define flow: 1 -> 2 -> 3
        graph.add_edge(START, "step_1")
        graph.add_edge("step_1", "step_2")
        graph.add_edge("step_2", "step_3")
        graph.add_edge("step_3", END)

        compiled = graph.compile()
        result = compiled.invoke({"order": []})

        assert result["order"] == [1, 2, 3]

    def test_execution_order_invariance_edges_before_nodes(self):
        """Invariance: Edges and conditional edges registered BEFORE nodes are added."""
        graph = SimpleStateGraph()
        # Add edges first
        graph.add_edge(START, "node_a")
        graph.add_edge("node_a", "node_b")
        graph.add_edge("node_b", END)

        # Add nodes afterward
        graph.add_node("node_a", lambda s: {"trace": s.get("trace", "") + "A"})
        graph.add_node("node_b", lambda s: {"trace": s.get("trace", "") + "B"})

        compiled = graph.compile()
        result = compiled.invoke({"trace": ""})

        assert result["trace"] == "AB"

    def test_execution_order_invariance_set_entry_point_vs_start_edge(self):
        """Invariance: set_entry_point("x") vs add_edge(START, "x") produces identical behavior."""
        # Graph A: set_entry_point
        ga = SimpleStateGraph()
        ga.add_node("n1", lambda s: {"val": 42})
        ga.set_entry_point("n1")
        ga.add_edge("n1", END)
        ca = ga.compile()

        # Graph B: add_edge(START, ...)
        gb = SimpleStateGraph()
        gb.add_node("n1", lambda s: {"val": 42})
        gb.add_edge(START, "n1")
        gb.add_edge("n1", END)
        cb = gb.compile()

        assert ca.invoke({}) == cb.invoke({}) == {"val": 42}

    def test_state_isolation_concurrent_invocations(self):
        """Adversarial concurrency: 20 threads simultaneously invoke the same compiled graph.

        Verify zero state leakage, race conditions, or log crosstalk.
        """
        graph = SimpleStateGraph()
        graph.add_node(
            "worker",
            lambda s: {
                "thread_tag": f"done-{s['tid']}",
                "execution_logs": [create_log_entry("worker", f"Thread {s['tid']} executed")],
            },
        )
        graph.add_edge(START, "worker")
        graph.add_edge("worker", END)

        compiled = graph.compile()

        def run_thread(tid: int):
            init = {
                "tid": tid,
                "thread_tag": "init",
                "execution_logs": [create_log_entry("init", f"Init thread {tid}")],
            }
            res = compiled.invoke(init)
            return tid, res

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(run_thread, i) for i in range(20)]
            results = [f.result() for f in as_completed(futures)]

        for tid, res in results:
            assert res["tid"] == tid
            assert res["thread_tag"] == f"done-{tid}"
            assert len(res["execution_logs"]) == 2
            assert res["execution_logs"][0]["message"] == f"Init thread {tid}"
            assert res["execution_logs"][1]["message"] == f"Thread {tid} executed"

    def test_state_isolation_sequential_runs_on_same_instance(self):
        """Adversarial sequential: 10 runs on single compiled instance with different states."""
        graph = SimpleStateGraph()
        graph.add_node("inc", lambda s: {"counter": s.get("counter", 0) + 1})
        graph.add_edge(START, "inc")
        graph.add_edge("inc", END)

        compiled = graph.compile()

        for i in range(10):
            res = compiled.invoke({"counter": i * 10})
            assert res["counter"] == i * 10 + 1

    def test_checkpointer_snapshot_history_and_isolation(self):
        """Adversarial checkpointer: Test intermediate snapshotting, thread isolation, and retrieval."""
        saver = SimpleMemorySaver()
        graph = SimpleStateGraph()
        graph.add_node("s1", lambda s: {"step": 1, "history": s.get("history", []) + ["s1"]})
        graph.add_node("s2", lambda s: {"step": 2, "history": s.get("history", []) + ["s2"]})
        graph.add_node("s3", lambda s: {"step": 3, "history": s.get("history", []) + ["s3"]})
        graph.add_edge(START, "s1")
        graph.add_edge("s1", "s2")
        graph.add_edge("s2", "s3")
        graph.add_edge("s3", END)

        compiled = graph.compile(checkpointer=saver)

        # Thread Alpha
        cfg_alpha = {"configurable": {"thread_id": "alpha"}}
        res_alpha = compiled.invoke({"history": []}, config=cfg_alpha)
        assert res_alpha["history"] == ["s1", "s2", "s3"]

        # Thread Beta
        cfg_beta = {"configurable": {"thread_id": "beta"}}
        res_beta = compiled.invoke({"history": ["pre"]}, config=cfg_beta)
        assert res_beta["history"] == ["pre", "s1", "s2", "s3"]

        # Verify thread isolation in saver storage
        assert len(saver.storage["alpha"]) == 3  # snapshots after s1, s2, s3
        assert len(saver.storage["beta"]) == 3

        # Verify snapshots capture step progression
        snap_a1 = saver.storage["alpha"][0]
        snap_a2 = saver.storage["alpha"][1]
        snap_a3 = saver.storage["alpha"][2]
        assert snap_a1["step"] == 1
        assert snap_a2["step"] == 2
        assert snap_a3["step"] == 3

        # Verify saver.get returns deepcopy of latest snapshot
        latest_alpha = saver.get(cfg_alpha)
        assert latest_alpha["step"] == 3
        latest_alpha["step"] = 999  # mutate retrieved object
        assert saver.get(cfg_alpha)["step"] == 3  # internal storage unmutated

    def test_checkpointer_state_recovery_and_resume_flow(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Stress: Pause graph at human_approval (auto_approve=False), snapshot to checkpointer,

        recover snapshot via saver.get(config), update human_approved=True, and verify state.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        try:
            from langgraph.checkpoint.memory import MemorySaver as OfficialMemorySaver
            saver = OfficialMemorySaver()
        except ImportError:
            saver = SimpleMemorySaver()
        
        config = {"configurable": {"thread_id": "hitl-session-1"}}

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            checkpointer=saver,
            auto_approve=False,
        )

        initial = create_initial_state("HITL checkpoint test", auto_approve=False)
        paused_state = app.invoke(initial, config=config)

        assert paused_state["status"] == "pending_approval"
        assert paused_state["human_approved"] is None

        # Verify state snapshot in checkpointer
        checkpoint = saver.get(config)
        assert checkpoint is not None
        # Handle Official langgraph Checkpoint vs Custom SimpleMemorySaver
        cp_state = checkpoint.get("channel_values", checkpoint) if isinstance(checkpoint, dict) else getattr(checkpoint, "channel_values", checkpoint)
        assert cp_state["status"] == "pending_approval"
        assert cp_state["validated_topology"] is not None

        # Simulate operator granting approval out-of-band and verifying route resolution
        if isinstance(cp_state, dict):
            cp_state["human_approved"] = True
        else:
            setattr(cp_state, "human_approved", True)
        next_route = route_after_approval(cp_state)
        assert next_route == "deployment"

    def test_dangling_edge_target_behavior(self):
        """Adversarial: Graph has an edge targeting an unregistered node name.

        Verify CompiledSimpleGraph breaks cleanly when node is not found rather than crashing with unhandled exception.
        """
        graph = SimpleStateGraph()
        graph.add_node("start_node", lambda s: {"visited_start": True})
        graph.add_edge(START, "start_node")
        # Edge pointing to non-existent node
        graph.add_edge("start_node", "nonexistent_ghost_node")

        compiled = graph.compile()
        # Invoking should execute start_node then cleanly stop when nonexistent node has no action
        result = compiled.invoke({"init": True})
        assert result.get("visited_start") is True

    def test_unreachable_orphan_node_behavior(self):
        """Adversarial: A node is registered in the graph but no edges point to it.

        Verify orphan node is never executed and does not interfere with the active path.
        """
        graph = SimpleStateGraph()
        graph.add_node("entry", lambda s: {"active": True})
        graph.add_node("orphan", lambda s: {"orphan_executed": True})
        graph.add_edge(START, "entry")
        graph.add_edge("entry", END)

        compiled = graph.compile()
        result = compiled.invoke({})

        assert result.get("active") is True
        assert "orphan_executed" not in result

    def test_runaway_loop_safety_max_steps_guard(self):
        """Adversarial: Infinite circular loop (A -> B -> A -> B ...).

        Verify CompiledSimpleGraph halts when max_steps is reached, avoiding an infinite hang.
        """
        graph = SimpleStateGraph()
        graph.add_node("node_a", lambda s: {"count": s.get("count", 0) + 1})
        graph.add_node("node_b", lambda s: {"count": s.get("count", 0) + 1})
        graph.add_edge(START, "node_a")
        graph.add_edge("node_a", "node_b")
        graph.add_edge("node_b", "node_a")  # Circular back-edge

        compiled = graph.compile()
        compiled.max_steps = 20  # Set tight max_steps guard for test

        result = compiled.invoke({"count": 0})
        # Must terminate at max_steps without infinite hanging
        assert result["count"] == 20

    def test_conditional_edge_unmapped_target_behavior(self):
        """Adversarial: Conditional edge returns an unregistered target not present in path_map or nodes.

        Verify execution safely terminates at the boundary without crashing with an unhandled KeyError.
        """
        graph = SimpleStateGraph()
        graph.add_node("check", lambda s: {"val": 10})
        graph.set_entry_point("check")
        # Route function returns unknown target "unregistered_node"
        graph.add_conditional_edges("check", lambda s: "unregistered_node", {"mapped_key": "some_other_node"})

        compiled = graph.compile()
        result = compiled.invoke({"init": True})
        assert result["val"] == 10

    def test_checkpointer_unknown_thread_and_none_config(self):
        """Adversarial: SimpleMemorySaver queried with unknown thread_id and None configs."""
        saver = SimpleMemorySaver()
        # Query on empty saver
        assert saver.get(None) is None
        assert saver.get({"configurable": {"thread_id": "nonexistent"}}) is None

        # Store with None config (defaults to 'default' thread)
        saver.put(None, {"data": "test_default"})
        assert saver.get(None) == {"data": "test_default"}
        assert saver.get({"configurable": {"thread_id": "default"}}) == {"data": "test_default"}
        assert saver.get({"configurable": {"thread_id": "other"}}) is None

    def test_checkpointer_streaming_snapshots(self):
        """Adversarial: stream() captures intermediate snapshots into checkpointer at each yield."""
        saver = SimpleMemorySaver()
        graph = SimpleStateGraph()
        graph.add_node("n1", lambda s: {"val": 1})
        graph.add_node("n2", lambda s: {"val": 2})
        graph.add_edge(START, "n1")
        graph.add_edge("n1", "n2")
        graph.add_edge("n2", END)

        compiled = graph.compile(checkpointer=saver)
        cfg = {"configurable": {"thread_id": "stream-thread"}}

        yielded_steps = list(compiled.stream({"val": 0}, config=cfg))
        assert len(yielded_steps) == 2
        assert "n1" in yielded_steps[0]
        assert "n2" in yielded_steps[1]

        # Checkpointer must hold 2 snapshots
        snaps = saver.storage["stream-thread"]
        assert len(snaps) == 2
        assert snaps[0]["val"] == 1
        assert snaps[1]["val"] == 2

    def test_deployment_failure_double_increment_progression(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Adversarial analysis: If deployment fails, deployment_node increments retry_count,

        and diagnosis_and_healing_node also increments retry_count upon entering.
        Verify circuit breaker trips within 1 cycle when max_retries=2.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        # Inject permanent deployment failure
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.DEPLOY_FAILURE,
                target_node=None,
                cleared_on_remediation=False,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Deployment failure progression", max_retries=2)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        # Since deployment fails (+1) and diag heals (+1), retry_count reaches >= 2 immediately
        assert final_state["retry_count"] >= 2

    def test_state_reducer_monotonic_log_ordering(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Stress: Verify Annotated[List[LogEntry], operator.add] preserves strict monotonic append

        across all execution stages.
        """
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Log monotonicity test")
        final_state = app.invoke(initial)

        logs = final_state["execution_logs"]
        assert len(logs) >= 5  # init, intent, topo, validation, approval, deploy, verif

        stages = [log["stage"] for log in logs]
        expected_order = [
            "init",
            "intent_parsing",
            "topology_generation",
            "offline_validation",
            "human_approval",
            "deployment",
            "verification_probing",
        ]
        assert stages == expected_order

        # Verify timestamps are monotonically non-decreasing
        timestamps = [log["timestamp"] for log in logs]
        assert timestamps == sorted(timestamps)

