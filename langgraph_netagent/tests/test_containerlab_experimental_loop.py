"""End-to-End Containerlab Experimental Loop Test Suite (Milestone M4).

Validates the complete Phases 2-4 NetOps Assistant lifecycle in the clos5 Containerlab topology:
1. Healthy baseline NetworkState capture.
2. Automated standard fault injection (Link Down, Route Drop, Packet Loss/Buffer Fault).
3. Deterministic StateDiff detection capturing before-and-after anomalies.
4. Agentic reasoning selecting DiagnosticStrategy (LINK_RECOVERY, ROUTING_REPAIR, QDISC_RESET).
5. Transactional deterministic execution applying atomic RepairPlans with pre/post condition assertions.
6. Programmatic post-repair verification confirming 0 remaining anomalies and 100% reachability restoration.
7. Reversible rollback via InjectedFaultToken and fault_context() context manager.
8. Strict LabIsolationGuard boundaries protecting host interfaces and isolating execution to clos5 containers.
9. ExperimentalLoop runner and CLI with --auto-heal support.
"""

from __future__ import annotations

import argparse
import copy
import io
import json
import sys
from typing import Any, Dict, List
from unittest.mock import patch
import pytest

from langgraph_netagent.models.network_state import (
    NetworkState,
    StateDiff,
    compute_state_diff,
)
from langgraph_netagent.models.reasoning import (
    DiagnosticStrategy,
    DiagnosticStrategySelector,
)
from langgraph_netagent.models.repair_plan import RepairAction, RepairPlan
from langgraph_netagent.tools.clab_fault_injector import (
    ContainerlabFaultInjector,
    InjectedFaultToken,
    LatencyFault,
    LinkDownFault,
    PacketLossFault,
    RouteDropFault,
)
from langgraph_netagent.tools.deterministic_executor import (
    DeterministicExecutor,
    ExecutionResult,
)
from langgraph_netagent.tools.experimental_loop import (
    ExperimentalLoop,
    ExperimentResult,
    LifecycleStage,
    build_scenario_from_args,
    main as experimental_loop_main,
)
from langgraph_netagent.tools.fault_injector import FaultType
from langgraph_netagent.tools.lab_isolation import (
    LabIsolationGuard,
    LabIsolationViolationError,
)
from langgraph_netagent.tools.mock_engine import (
    MockContainerlabAdapter,
    RouteEntry,
    VirtualInterface,
    VirtualNode,
)
from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter
from langgraph_netagent.workflow.programmatic_verifier import (
    ProgrammaticVerifier,
    VerificationResult,
)
from langgraph_netagent.workflow.reasoning_engine import DiagnosticReasoningEngine


# ==============================================================================
# Clos5 Lab Fixtures and Topology Setup
# ==============================================================================

def setup_clos5_lab(adapter: MockContainerlabAdapter) -> None:
    """Populate MockContainerlabAdapter with the canonical 18-node clos5 topology.

    Sets up:
    - 4 Leaves (leaf1..4), 4 Spines (spine1..4), 2 Superspines (superspine1..2)
    - 4 Tenant hosts (h1..4) in 172.16.X.0/24 subnets
    - dc-egress (172.16.254.2 / 203.0.113.1) & ext-router (203.0.113.2 / 192.168.100.1)
    - attacker (192.168.100.2) & sflow-rt
    - Interconnecting links, routing tables, and full mutual ping reachability.
    """
    g = adapter.mock_engine.graph
    g.clear()
    adapter.fault_injector.clear_all()

    clos5_nodes = [
        "leaf1", "leaf2", "leaf3", "leaf4",
        "spine1", "spine2", "spine3", "spine4",
        "superspine1", "superspine2",
        "dc-egress", "ext-router", "attacker", "sflow-rt",
        "h1", "h2", "h3", "h4",
    ]

    for name in clos5_nodes:
        kind = "frr" if any(k in name for k in ("leaf", "spine", "superspine")) else "linux"
        vnode = VirtualNode(name=name, kind=kind)
        vnode.add_interface(VirtualInterface("lo", ip_cidr="127.0.0.1/8"))
        g.add_node(vnode)

    # 1. Tenant hosts h1..h4 and Leaves leaf1..4
    for idx in range(1, 5):
        h_name = f"h{idx}"
        l_name = f"leaf{idx}"
        h_ip = f"172.16.{idx}.2"
        l_ip = f"172.16.{idx}.1"

        # Host node
        h_node = g.nodes[h_name]
        h_node.add_interface(VirtualInterface("eth1", ip_cidr=f"{h_ip}/24"))
        h_node.add_route(RouteEntry(destination="default", next_hop=l_ip, interface="eth1", protocol="static"))
        g.register_ip(f"{h_ip}/24", h_name, "eth1")

        # Leaf node
        l_node = g.nodes[l_name]
        l_node.add_interface(VirtualInterface("eth3", ip_cidr=f"{l_ip}/24"))
        l_node.add_interface(VirtualInterface("eth1", ip_cidr=f"10.0.{idx}.1/30"))
        l_node.add_route(RouteEntry(destination=f"172.16.{idx}.0/24", next_hop=None, interface="eth3", protocol="connected"))
        l_node.add_route(RouteEntry(destination="172.16.254.0/24", next_hop="172.16.254.2", interface="eth1", protocol="bgp"))
        l_node.add_route(RouteEntry(destination="203.0.113.0/24", next_hop="172.16.254.2", interface="eth1", protocol="bgp"))
        g.register_ip(f"{l_ip}/24", l_name, "eth3")
        g.register_ip(f"10.0.{idx}.1/30", l_name, "eth1")

        # Link h{idx}:eth1 <-> leaf{idx}:eth3
        g.add_link(h_name, "eth1", l_name, "eth3")

        # Inter-leaf routing so tenant hosts can reach each other
        for target_idx in range(1, 5):
            if target_idx != idx:
                l_node.add_route(RouteEntry(destination=f"172.16.{target_idx}.0/24", next_hop=f"172.16.{target_idx}.1", interface="eth1", protocol="bgp"))

    # 2. dc-egress & ext-router
    dc = g.nodes["dc-egress"]
    dc.add_interface(VirtualInterface("eth1", ip_cidr="172.16.254.2/24"))
    dc.add_interface(VirtualInterface("eth2", ip_cidr="203.0.113.1/24"))
    for idx in range(1, 5):
        dc.add_route(RouteEntry(destination=f"172.16.{idx}.0/24", next_hop=f"172.16.{idx}.1", interface="eth1", protocol="static"))
    dc.add_route(RouteEntry(destination="default", next_hop="203.0.113.2", interface="eth2", protocol="static"))
    g.register_ip("172.16.254.2/24", "dc-egress", "eth1")
    g.register_ip("203.0.113.1/24", "dc-egress", "eth2")

    ext = g.nodes["ext-router"]
    ext.add_interface(VirtualInterface("eth1", ip_cidr="203.0.113.2/24"))
    ext.add_interface(VirtualInterface("eth2", ip_cidr="192.168.100.1/24"))
    ext.add_route(RouteEntry(destination="203.0.113.0/24", next_hop=None, interface="eth1", protocol="connected"))
    ext.add_route(RouteEntry(destination="192.168.100.0/24", next_hop=None, interface="eth2", protocol="connected"))
    ext.add_route(RouteEntry(destination="172.16.0.0/16", next_hop="203.0.113.1", interface="eth1", protocol="static"))
    g.register_ip("203.0.113.2/24", "ext-router", "eth1")
    g.register_ip("192.168.100.1/24", "ext-router", "eth2")

    # 3. Attacker node
    att = g.nodes["attacker"]
    att.add_interface(VirtualInterface("eth1", ip_cidr="192.168.100.2/24"))
    att.add_route(RouteEntry(destination="default", next_hop="192.168.100.1", interface="eth1", protocol="static"))
    g.register_ip("192.168.100.2/24", "attacker", "eth1")

    # Links
    g.add_link("leaf1", "eth1", "dc-egress", "eth1")
    g.add_link("dc-egress", "eth2", "ext-router", "eth1")
    g.add_link("attacker", "eth1", "ext-router", "eth2")


@pytest.fixture
def clos5_mock_adapter() -> MockContainerlabAdapter:
    """Fixture providing a initialized MockContainerlabAdapter for clos5."""
    adapter = MockContainerlabAdapter()
    setup_clos5_lab(adapter)
    return adapter


@pytest.fixture
def clos5_isolation_guard() -> LabIsolationGuard:
    """Fixture providing a LabIsolationGuard scoped to clos5."""
    return LabIsolationGuard(lab_name="clos5")


@pytest.fixture
def clos5_fault_injector(clos5_mock_adapter, clos5_isolation_guard) -> ContainerlabFaultInjector:
    """Fixture providing a ContainerlabFaultInjector scoped to clos5."""
    return ContainerlabFaultInjector(
        adapter=clos5_mock_adapter,
        isolation_guard=clos5_isolation_guard,
        lab_name="clos5",
    )


# ==============================================================================
# 1. Link Down Fault and Automated Self-Healing Tests
# ==============================================================================

class TestClos5LinkDownSelfHealing:
    """Validates Link Down injection, StateDiff detection, reasoning, deterministic fix, and programmatic verification."""

    def test_link_down_detection_diff_and_automated_repair(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
        clos5_fault_injector: ContainerlabFaultInjector,
    ):
        """End-to-End: dropping leaf1:eth3 is detected, diagnosed as LINK_RECOVERY, repaired, and verified."""
        target_nodes = ["h1", "h2", "leaf1", "leaf2", "dc-egress", "ext-router"]

        # Step 1: Capture healthy baseline NetworkState
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        assert baseline.is_healthy() is True
        assert all(r.reachable for r in baseline.reachability_matrix)

        # Step 2: Inject link down fault on leaf1:eth3
        scenario = LinkDownFault(node="leaf1", interface="eth3", description="Take down tenant link on leaf1:eth3")
        token = clos5_fault_injector.inject_fault(scenario)
        assert token.active is True
        assert token.node == "leaf1"
        assert token.injection_command == "ip link set dev eth3 down"
        assert token.rollback_command == "ip link set dev eth3 up"

        # Step 3: Capture post-fault NetworkState and compute StateDiff
        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        state_diff: StateDiff = baseline.diff(post_fault)

        # Assert fault correctly perceived
        assert state_diff.has_anomalies() is True
        assert state_diff.has_link_failure() is True
        assert "leaf1" in state_diff.affected_nodes()
        leaf1_diff = state_diff.interface_diffs.get("leaf1")
        assert leaf1_diff is not None
        assert "eth3" in leaf1_diff.changed
        assert leaf1_diff.changed["eth3"]["oper_state"][1] == "DOWN"

        # Assert reachability broken to h1
        unreachable_pairs = [f"{r.source}->{r.destination}" for r in post_fault.reachability_matrix if not r.reachable]
        assert any("h1" in p for p in unreachable_pairs)

        # Step 4: Agentic reasoning perceives state_diff and generates RepairPlan
        engine = DiagnosticReasoningEngine()
        plan: RepairPlan = engine.analyze_diff_and_plan(state_diff)
        assert plan.strategy == DiagnosticStrategy.LINK_RECOVERY
        assert len(plan.actions) >= 1

        target_action = next((a for a in plan.actions if a.target_node == "leaf1" and "eth3" in a.command), None)
        assert target_action is not None
        assert target_action.action_type == "link_up"
        assert target_action.command == "ip link set dev eth3 up"
        assert target_action.rollback_command == "ip link set dev eth3 down"

        # Step 5: Apply deterministic fix via DeterministicExecutor
        executor = DeterministicExecutor(lab_adapter=clos5_mock_adapter, lab_name="clos5")
        exec_res: ExecutionResult = executor.execute_plan(plan)
        assert exec_res.success is True
        assert exec_res.error is None
        assert exec_res.rolled_back is False

        # Step 6: Programmatic verification confirms 100% recovery
        verifier = ProgrammaticVerifier(lab_adapter=clos5_mock_adapter)
        verif_res: VerificationResult = verifier.capture_and_verify(
            baseline=baseline,
            target_nodes=target_nodes,
            target_fault_diff=state_diff,
        )
        assert verif_res.passed is True
        assert len(verif_res.unresolved_anomalies) == 0
        assert "100% reachability restored" in verif_res.details

    def test_link_down_host_interface_self_healing(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
        clos5_fault_injector: ContainerlabFaultInjector,
    ):
        """End-to-End: dropping h1:eth1 on host is detected, repaired, and verified."""
        target_nodes = ["h1", "h2", "leaf1", "leaf2"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)

        scenario = LinkDownFault(node="h1", interface="eth1")
        clos5_fault_injector.inject_fault(scenario)

        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        diff = baseline.diff(post_fault)
        assert diff.has_link_failure() is True
        assert "h1" in diff.affected_nodes()

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy == DiagnosticStrategy.LINK_RECOVERY

        executor = DeterministicExecutor(lab_adapter=clos5_mock_adapter, lab_name="clos5")
        res = executor.execute_plan(plan)
        assert res.success is True

        verifier = ProgrammaticVerifier(lab_adapter=clos5_mock_adapter)
        verif = verifier.capture_and_verify(baseline=baseline, target_nodes=target_nodes, target_fault_diff=diff)
        assert verif.passed is True
        assert len(verif.unresolved_anomalies) == 0


# ==============================================================================
# 2. Route Drop Fault and Automated Self-Healing Tests
# ==============================================================================

class TestClos5RouteDropSelfHealing:
    """Validates Route Drop injection, StateDiff detection, ROUTING_REPAIR reasoning, and restoration."""

    def test_route_drop_detection_and_automated_repair(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
        clos5_fault_injector: ContainerlabFaultInjector,
    ):
        """End-to-End: deleting default route on h2 is detected, diagnosed, repaired, and verified."""
        target_nodes = ["h1", "h2", "leaf1", "leaf2"]

        # Step 1: Baseline snapshot
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        assert baseline.is_healthy() is True

        # Step 2: Inject route drop fault on h2
        scenario = RouteDropFault(
            node="h2",
            prefix="default",
            via="172.16.2.1",
            dev="eth1",
            description="Drop default gateway route on h2",
        )
        token = clos5_fault_injector.inject_fault(scenario)
        assert token.active is True
        assert token.node == "h2"
        assert token.injection_command == "ip route del default via 172.16.2.1 dev eth1"

        # Step 3: Capture post-fault state and diff
        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        diff = baseline.diff(post_fault)

        assert diff.has_anomalies() is True
        assert diff.has_route_failure() is True
        assert "h2" in diff.affected_nodes()
        h2_rdiff = diff.route_diffs.get("h2")
        assert h2_rdiff is not None
        assert any(r.prefix == "default" for r in h2_rdiff.removed)

        # Reachability to/from h2 should be broken
        unreachable_pairs = [f"{r.source}->{r.destination}" for r in post_fault.reachability_matrix if not r.reachable]
        assert any("h2" in p for p in unreachable_pairs)

        # Step 4: Agentic reasoning selects ROUTING_REPAIR
        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy == DiagnosticStrategy.ROUTING_REPAIR
        assert len(plan.actions) >= 1

        route_act = next((a for a in plan.actions if a.target_node == "h2"), None)
        assert route_act is not None
        assert route_act.action_type == "route_replace"
        assert "ip route replace default via 172.16.2.1" in route_act.command

        # Step 5: Execute deterministic repair
        executor = DeterministicExecutor(lab_adapter=clos5_mock_adapter, lab_name="clos5")
        exec_res = executor.execute_plan(plan)
        assert exec_res.success is True

        # Step 6: Programmatic verification
        verifier = ProgrammaticVerifier(lab_adapter=clos5_mock_adapter)
        verif = verifier.capture_and_verify(baseline=baseline, target_nodes=target_nodes, target_fault_diff=diff)
        assert verif.passed is True
        assert len(verif.unresolved_anomalies) == 0

    def test_route_drop_egress_gateway_healing(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
        clos5_fault_injector: ContainerlabFaultInjector,
    ):
        """End-to-End: route drop on dc-egress default route is detected and repaired."""
        target_nodes = ["h1", "dc-egress", "ext-router"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)

        scenario = RouteDropFault(
            node="dc-egress",
            prefix="default",
            via="203.0.113.2",
            dev="eth2",
        )
        clos5_fault_injector.inject_fault(scenario)

        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        diff = baseline.diff(post_fault)
        assert diff.has_route_failure() is True

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy == DiagnosticStrategy.ROUTING_REPAIR

        executor = DeterministicExecutor(lab_adapter=clos5_mock_adapter, lab_name="clos5")
        res = executor.execute_plan(plan)
        assert res.success is True

        verifier = ProgrammaticVerifier(lab_adapter=clos5_mock_adapter)
        verif = verifier.capture_and_verify(baseline=baseline, target_nodes=target_nodes, target_fault_diff=diff)
        assert verif.passed is True
        assert len(verif.unresolved_anomalies) == 0


# ==============================================================================
# 3. Packet Loss / Buffer Fault and Automated Self-Healing Tests
# ==============================================================================

class TestClos5PacketLossSelfHealing:
    """Validates Packet Loss injection, StateDiff qdisc detection, QDISC_RESET reasoning, and recovery."""

    def test_packet_loss_qdisc_detection_and_automated_repair(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
        clos5_fault_injector: ContainerlabFaultInjector,
    ):
        """End-to-End: injecting netem packet loss on ext-router:eth1 is detected, diagnosed, and repaired."""
        target_nodes = ["dc-egress", "ext-router"]

        # Step 1: Baseline snapshot
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        assert baseline.is_healthy() is True

        # Step 2: Inject PacketLossFault via tc netem
        scenario = PacketLossFault(
            node="ext-router",
            interface="eth1",
            loss_pct=25.0,
            description="Inject 25% netem loss on ext-router:eth1",
        )
        token = clos5_fault_injector.inject_fault(scenario)
        assert token.active is True
        assert token.injection_command == "tc qdisc add dev eth1 root netem loss 25%"
        assert token.rollback_command == "tc qdisc del dev eth1 root"

        # Step 3: Capture post-fault state and diff
        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_mock_adapter, target_nodes=target_nodes)
        diff = baseline.diff(post_fault)

        assert diff.has_anomalies() is True
        assert diff.has_packet_loss() is True
        ext_qdiff = diff.qdisc_diffs.get("ext-router")
        assert ext_qdiff is not None
        assert "eth1" in ext_qdiff.changed
        assert ext_qdiff.changed["eth1"]["loss_percent"][1] == 25.0

        # Step 4: Agentic reasoning selects QDISC_RESET
        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy == DiagnosticStrategy.QDISC_RESET
        assert len(plan.actions) >= 1

        reset_act = next((a for a in plan.actions if a.target_node == "ext-router"), None)
        assert reset_act is not None
        assert reset_act.action_type == "qdisc_reset"
        assert reset_act.command == "tc qdisc del dev eth1 root"

        # Step 5: Execute deterministic repair
        executor = DeterministicExecutor(lab_adapter=clos5_mock_adapter, lab_name="clos5")
        exec_res = executor.execute_plan(plan)
        assert exec_res.success is True

        # Step 6: Programmatic verification
        verifier = ProgrammaticVerifier(lab_adapter=clos5_mock_adapter)
        verif = verifier.capture_and_verify(baseline=baseline, target_nodes=target_nodes, target_fault_diff=diff)
        assert verif.passed is True
        assert len(verif.unresolved_anomalies) == 0


# ==============================================================================
# 4. Full Experimental Loop CLI and Runner Tests
# ==============================================================================

class TestClos5ExperimentalLoopRunner:
    """Validates ExperimentalLoop.run_experiment(scenario, auto_heal=True) and CLI runner."""

    def test_experimental_loop_run_experiment_auto_heal_link_down(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
    ):
        """ExperimentalLoop.run_experiment with auto_heal=True succeeds on LinkDownFault."""
        loop = ExperimentalLoop(
            adapter=clos5_mock_adapter,
            lab_name="clos5",
            target_nodes=["h1", "h2", "leaf1", "leaf2"],
            ping_targets=[("h1", "172.16.2.2"), ("h2", "172.16.1.2")],
        )

        scenario = LinkDownFault(node="leaf1", interface="eth3")
        result: ExperimentResult = loop.run_experiment(scenario=scenario, auto_heal=True)

        assert result.success is True
        assert result.stage == LifecycleStage.VERIFICATION_COMPLETED
        assert result.state_diff is not None
        assert result.state_diff.has_anomalies is True
        assert "leaf1:eth3" in result.state_diff.interfaces_down
        assert result.verification is not None
        assert result.verification.passed is True
        assert result.duration_seconds > 0.0

    def test_experimental_loop_run_experiment_auto_heal_route_drop(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
    ):
        """ExperimentalLoop.run_experiment with auto_heal=True succeeds on RouteDropFault."""
        loop = ExperimentalLoop(
            adapter=clos5_mock_adapter,
            lab_name="clos5",
            target_nodes=["h1", "h2", "leaf1", "leaf2"],
            ping_targets=[("h1", "172.16.2.2")],
        )

        scenario = RouteDropFault(node="h2", prefix="default", via="172.16.2.1", dev="eth1")
        result = loop.run_experiment(scenario=scenario, auto_heal=True)

        assert result.success is True
        assert result.verification.passed is True

    def test_experimental_loop_run_experiment_auto_heal_packet_loss(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
    ):
        """ExperimentalLoop.run_experiment with auto_heal=True succeeds on PacketLossFault."""
        loop = ExperimentalLoop(
            adapter=clos5_mock_adapter,
            lab_name="clos5",
            target_nodes=["ext-router"],
            ping_targets=[],
        )

        scenario = PacketLossFault(node="ext-router", interface="eth1", loss_pct=20.0)
        result = loop.run_experiment(scenario=scenario, auto_heal=True)

        assert result.success is True
        assert result.verification.passed is True

    def test_experimental_loop_cli_argument_parser(self):
        """CLI argument parser correctly constructs standard fault scenarios."""
        # Link down
        parser = argparse.ArgumentParser()
        parser.add_argument("--scenario")
        parser.add_argument("--node")
        parser.add_argument("--interface")
        args = parser.parse_args(["--scenario", "link_down", "--node", "leaf1", "--interface", "eth3"])
        scen = build_scenario_from_args(args)
        assert isinstance(scen, LinkDownFault)
        assert scen.node == "leaf1"
        assert scen.interface == "eth3"

        # Route drop
        parser_rt = argparse.ArgumentParser()
        parser_rt.add_argument("--scenario")
        parser_rt.add_argument("--node")
        parser_rt.add_argument("--prefix")
        parser_rt.add_argument("--via")
        parser_rt.add_argument("--bgp-neighbor")
        parser_rt.add_argument("--bgp-as")
        args_rt = parser_rt.parse_args(["--scenario", "route_drop", "--node", "h2", "--prefix", "default", "--via", "172.16.2.1"])
        scen_rt = build_scenario_from_args(args_rt)
        assert isinstance(scen_rt, RouteDropFault)
        assert scen_rt.prefix == "default"

        # Packet loss
        parser_pl = argparse.ArgumentParser()
        parser_pl.add_argument("--scenario")
        parser_pl.add_argument("--node")
        parser_pl.add_argument("--interface")
        parser_pl.add_argument("--loss", type=float)
        args_pl = parser_pl.parse_args(["--scenario", "packet_loss", "--node", "ext-router", "--interface", "eth1", "--loss", "15"])
        scen_pl = build_scenario_from_args(args_pl)
        assert isinstance(scen_pl, PacketLossFault)
        assert scen_pl.loss_pct == 15.0

    def test_experimental_loop_cli_runner_mock_mode(self, monkeypatch):
        """CLI entrypoint executes cleanly in mock mode with --auto-heal and --json."""
        test_args = [
            "experimental_loop.py",
            "--scenario", "link_down",
            "--node", "leaf1",
            "--interface", "eth3",
            "--mode", "mock",
            "--auto-heal",
            "--json",
        ]
        monkeypatch.setattr(sys, "argv", test_args)

        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output), pytest.raises(SystemExit) as exc_info:
            experimental_loop_main()

        assert exc_info.value.code == 0
        raw_json = captured_output.getvalue()
        assert raw_json.strip().startswith("{")
        parsed = json.loads(raw_json)
        assert parsed["scenario_type"] == "link_down"
        assert parsed["target_node"] == "leaf1"
        assert parsed["success"] is True


# ==============================================================================
# 5. Reversible Rollback and Lab Isolation Tests
# ==============================================================================

class TestClos5ReversibleRollbackAndIsolation:
    """Validates fault_context() safe reversion, LIFO multi-fault rollbacks, and LabIsolationGuard enforcement."""

    def test_fault_context_manager_clean_reversion(
        self,
        clos5_fault_injector: ContainerlabFaultInjector,
        clos5_mock_adapter: MockContainerlabAdapter,
    ):
        """fault_context() context manager guarantees automatic rollback on normal completion."""
        scenario = LinkDownFault(node="leaf1", interface="eth3")

        with clos5_fault_injector.fault_context(scenario) as token:
            assert token.active is True
            assert clos5_fault_injector.active_faults_count == 1
            assert bool(clos5_mock_adapter.fault_injector.is_interface_down("leaf1", "eth3")) is True

        # Upon exit, fault must be completely reverted
        assert token.active is False
        assert clos5_fault_injector.active_faults_count == 0
        assert bool(clos5_mock_adapter.fault_injector.is_interface_down("leaf1", "eth3")) is False

    def test_fault_context_manager_reversion_on_exception(
        self,
        clos5_fault_injector: ContainerlabFaultInjector,
        clos5_mock_adapter: MockContainerlabAdapter,
    ):
        """fault_context() automatically reverts fault even when an exception is raised inside the block."""
        scenario = RouteDropFault(node="h2", prefix="default", via="172.16.2.1")
        captured_token = None

        with pytest.raises(RuntimeError, match="Simulated crash during test"):
            with clos5_fault_injector.fault_context(scenario) as token:
                captured_token = token
                assert token.active is True
                raise RuntimeError("Simulated crash during test")

        assert captured_token is not None
        assert captured_token.active is False
        assert clos5_fault_injector.active_faults_count == 0

    def test_revert_all_lifo_order(
        self,
        clos5_fault_injector: ContainerlabFaultInjector,
    ):
        """Multiple concurrent faults are reverted in reverse LIFO order."""
        t1 = clos5_fault_injector.inject_fault(LinkDownFault(node="leaf1", interface="eth1"))
        t2 = clos5_fault_injector.inject_fault(LinkDownFault(node="leaf2", interface="eth1"))
        t3 = clos5_fault_injector.inject_fault(RouteDropFault(node="h1", prefix="172.16.0.0/16"))

        assert clos5_fault_injector.active_faults_count == 3
        reverted_count = clos5_fault_injector.revert_all()
        assert reverted_count == 3
        assert clos5_fault_injector.active_faults_count == 0
        assert t1.active is False
        assert t2.active is False
        assert t3.active is False

    def test_lab_isolation_guard_blocks_host_interfaces(
        self,
        clos5_isolation_guard: LabIsolationGuard,
    ):
        """LabIsolationGuard strictly blocks mutations targeting host physical or bridge interfaces."""
        prohibited_commands = [
            "ip link set dev eth0 down",
            "ip link set dev docker0 down",
            "ip link set dev br-1a2b down",
            "ip link set dev veth1234 down",
            "ip link set dev vEthernet down",
            "netsh interface set interface Wi-Fi disable",
            "nsenter --target 1 --net ip link set eth0 down",
            "ip netns exec host ip route flush",
        ]

        for cmd in prohibited_commands:
            assert clos5_isolation_guard.validate_command_safety(cmd, container_name="leaf1") is False
            with pytest.raises(LabIsolationViolationError):
                clos5_isolation_guard.assert_command_safety(cmd, container_name="leaf1")

    def test_lab_isolation_guard_blocks_unauthorized_containers(
        self,
        clos5_fault_injector: ContainerlabFaultInjector,
    ):
        """Attempting to inject a fault on non-clos5 containers is blocked by isolation guard."""
        unauthorized_targets = [
            "host",
            "localhost",
            "production-db",
            "clab-otherlab-leaf1",
            "my_external_container",
        ]

        for target in unauthorized_targets:
            scenario = LinkDownFault(node=target, interface="eth1")
            with pytest.raises(LabIsolationViolationError):
                clos5_fault_injector.inject_fault(scenario)

    def test_deterministic_executor_aborts_on_host_boundary_violation(
        self,
        clos5_mock_adapter: MockContainerlabAdapter,
    ):
        """DeterministicExecutor refuses to execute any repair action targeting host interfaces."""
        executor = DeterministicExecutor(lab_adapter=clos5_mock_adapter, lab_name="clos5")

        malicious_plan = RepairPlan(
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-malicious",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev docker0 up",  # Targets host bridge docker0!
                    rollback_command="ip link set dev docker0 down",
                )
            ],
        )

        result = executor.execute_plan(malicious_plan)
        assert result.success is False
        assert "Lab isolation boundary violation" in result.error
        assert result.rolled_back is True
