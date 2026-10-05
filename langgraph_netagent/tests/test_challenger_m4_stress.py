"""Empirical Stress Test Suite for Phases 2-4 (Milestone M4 Challenger).

Author: challenger_m4_1 (Empirical Challenger)
Target: NetOps Assistant Phases 2-4: Containerlab Experimental Loop, NetworkState Model & Agentic Execution

Tests:
1. TestComplexFaultInjectionCombinations:
   - Concurrent multi-node fault injection (Link Down + Route Drop + Packet Loss) and LIFO rollback.
   - Interleaved partial manual rollback followed by revert_all().
2. TestDeterministicStateDiffAccuracy:
   - Fine-grained StateDiff accuracy under simultaneous multi-layer anomalies.
   - StateDiff repeatability and determinism across 50 consecutive comparisons.
   - High-density to_llm_markdown() strict length budget (<= 480 bytes) and content coverage.
3. TestRapidSequentialFaultInjectionAndRecovery:
   - 25 rapid sequential fault injection & recovery cycles with zero state leaks.
   - Rapid fault_context() manager cycling under normal and exception-handling conditions.
4. TestClosedLoopSelfHealingAcrossAllHosts:
   - Multi-fault closed-loop self-healing restoring full 12-pair mesh reachability across h1..h4.
   - Simultaneous quad-host link-down self-healing across h1..h4.
5. TestAdversarialBoundaryAndNegativeConditions:
   - LabIsolationGuard host boundary enforcement and container name validation.
   - Transactional LIFO rollback on pre-check condition assertion failure.
   - Transactional LIFO rollback on post-check condition assertion failure.
   - Idempotent reasoning and execution on an already healthy network fabric.
"""

from __future__ import annotations

import copy
import json
import pytest
from typing import Any, Dict, List, Tuple

from langgraph_netagent.models.network_state import (
    InterfaceDiff,
    InterfaceState,
    NetworkState,
    QdiscDiff,
    ReachabilityDiff,
    RouteDiff,
    RouteState,
    StateDiff,
    compute_state_diff,
)
from langgraph_netagent.models.reasoning import (
    DiagnosticStrategy,
    DiagnosticStrategySelector,
)
from langgraph_netagent.models.repair_plan import RepairAction, RepairPlan
from langgraph_netagent.tools.aal import AgentAccessLayer
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
from langgraph_netagent.tools.lab_isolation import (
    LabIsolationGuard,
    LabIsolationViolationError,
)
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter
from langgraph_netagent.tools.probes import PingProbe
from langgraph_netagent.workflow.programmatic_verifier import (
    ProgrammaticVerifier,
    VerificationResult,
)
from langgraph_netagent.workflow.reasoning_engine import DiagnosticReasoningEngine
from tests.test_containerlab_experimental_loop import setup_clos5_lab


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def clos5_adapter() -> MockContainerlabAdapter:
    """Provides a cleanly initialized MockContainerlabAdapter for clos5."""
    adapter = MockContainerlabAdapter()
    setup_clos5_lab(adapter)
    return adapter


@pytest.fixture
def clos5_guard() -> LabIsolationGuard:
    """Provides a LabIsolationGuard scoped to clos5."""
    return LabIsolationGuard(lab_name="clos5")


@pytest.fixture
def clos5_injector(clos5_adapter: MockContainerlabAdapter, clos5_guard: LabIsolationGuard) -> ContainerlabFaultInjector:
    """Provides a ContainerlabFaultInjector scoped to clos5."""
    return ContainerlabFaultInjector(
        adapter=clos5_adapter,
        isolation_guard=clos5_guard,
        lab_name="clos5",
    )


# ==============================================================================
# Suite 1: Complex Multi-Fault Injection Combinations
# ==============================================================================

class TestComplexFaultInjectionCombinations:
    """Adversarially challenges simultaneous multi-node and multi-layer fault injections."""

    def test_concurrent_multi_node_fault_injection_and_lifo_rollback(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """Inject 4 concurrent faults across multiple clos5 nodes, verifying LIFO reversal."""
        eval_nodes = ["h1", "h2", "h3", "h4", "leaf1", "leaf2", "leaf4", "dc-egress"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)
        assert baseline.is_healthy() is True

        # Inject 4 distinct faults concurrently
        f1 = clos5_injector.inject_fault(LinkDownFault(node="leaf1", interface="eth3", description="h1 link down"))
        f2 = clos5_injector.inject_fault(LinkDownFault(node="leaf2", interface="eth3", description="h2 link down"))
        f3 = clos5_injector.inject_fault(RouteDropFault(node="dc-egress", prefix="172.16.3.0/24", description="h3 route drop"))
        f4 = clos5_injector.inject_fault(PacketLossFault(node="leaf4", interface="eth3", loss_pct=40.0, description="h4 netem loss"))

        assert clos5_injector.active_faults_count == 4
        active_tokens = clos5_injector.get_active_tokens()
        assert len(active_tokens) == 4
        token_ids = [t.token_id for t in active_tokens]
        assert len(set(token_ids)) == 4  # All distinct

        # Post-fault snapshot shows anomalies
        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)
        diff = baseline.diff(post_fault)
        assert diff.has_anomalies() is True
        assert diff.has_link_failure() is True
        assert diff.has_route_failure() is True
        assert diff.has_packet_loss() is True

        # Revert all in LIFO order
        reverted_count = clos5_injector.revert_all()
        assert reverted_count == 4
        assert clos5_injector.active_faults_count == 0
        assert len(clos5_injector.get_active_tokens()) == 0

        # Post-revert snapshot must match baseline exactly
        post_revert = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)
        post_diff = baseline.diff(post_revert)
        assert post_diff.has_anomalies() is False
        assert post_revert.is_healthy() is True

    def test_interleaved_partial_rollback_then_revert_all(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """Revert middle fault token manually, then verify revert_all() cleans remaining stack cleanly."""
        t1 = clos5_injector.inject_fault(LinkDownFault(node="leaf1", interface="eth3"))
        t2 = clos5_injector.inject_fault(RouteDropFault(node="dc-egress", prefix="172.16.2.0/24"))
        t3 = clos5_injector.inject_fault(PacketLossFault(node="leaf3", interface="eth3", loss_pct=30.0))

        assert clos5_injector.active_faults_count == 3

        # Manually revert middle token t2
        reverted_t2 = clos5_injector.revert_fault(t2)
        assert reverted_t2 is True
        assert t2.active is False
        assert clos5_injector.active_faults_count == 2

        # Calling revert_all() should revert remaining 2 tokens (t3 then t1) without crashing
        remaining_reverted = clos5_injector.revert_all()
        assert remaining_reverted == 2
        assert clos5_injector.active_faults_count == 0


# ==============================================================================
# Suite 2: Deterministic StateDiff Accuracy
# ==============================================================================

class TestDeterministicStateDiffAccuracy:
    """Validates StateDiff precision, determinism, and LLM serialization budget."""

    def test_deterministic_diff_under_simultaneous_multi_layer_anomalies(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """StateDiff must accurately classify and isolate simultaneous link, route, and qdisc deltas."""
        eval_nodes = ["h1", "h2", "h3", "h4", "leaf1", "leaf2", "leaf4", "dc-egress"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)

        clos5_injector.inject_fault(LinkDownFault(node="leaf1", interface="eth3"))
        clos5_injector.inject_fault(RouteDropFault(node="dc-egress", prefix="172.16.3.0/24"))
        clos5_injector.inject_fault(PacketLossFault(node="leaf4", interface="eth3", loss_pct=35.0))

        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)
        diff = baseline.diff(post_fault)

        # 1. Interface delta check
        assert "leaf1" in diff.interface_diffs
        assert "eth3" in diff.interface_diffs["leaf1"].changed
        assert diff.interface_diffs["leaf1"].changed["eth3"]["oper_state"] == ("UP", "DOWN")

        # 2. Route delta check
        assert "dc-egress" in diff.route_diffs
        removed_prefixes = [r.prefix for r in diff.route_diffs["dc-egress"].removed]
        assert "172.16.3.0/24" in removed_prefixes

        # 3. Qdisc delta check
        assert "leaf4" in diff.qdisc_diffs
        assert "eth3" in diff.qdisc_diffs["leaf4"].changed
        assert diff.qdisc_diffs["leaf4"].changed["eth3"]["loss_percent"] == (0.0, 35.0)

        # 4. Reachability delta check
        unreachable_pairs = [f"{s}->{d}" for s, d in diff.reachability_diffs.newly_unreachable]
        assert any("h1" in p for p in unreachable_pairs)
        assert any("172.16.3.2" in p or "h3" in p for p in unreachable_pairs)

        # 5. Affected nodes check
        affected = diff.affected_nodes()
        for expected in ("leaf1", "dc-egress", "leaf4", "h1"):
            assert expected in affected

        clos5_injector.revert_all()

    def test_state_diff_repeatable_determinism_50_iterations(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """Calling baseline.diff(post_fault) 50 consecutive times produces bitwise identical models."""
        eval_nodes = ["h1", "h2", "leaf1", "leaf2"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)
        clos5_injector.inject_fault(LinkDownFault(node="leaf1", interface="eth3"))
        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)

        first_diff = baseline.diff(post_fault)
        first_dump = first_diff.model_dump()
        first_markdown = first_diff.to_llm_markdown()

        for _ in range(50):
            repeated_diff = baseline.diff(post_fault)
            assert repeated_diff.model_dump() == first_dump
            assert repeated_diff.to_llm_markdown() == first_markdown

        clos5_injector.revert_all()

    def test_to_llm_markdown_truncation_and_content_density(self):
        """to_llm_markdown() strictly honors <= 480 byte budget and serializes all fault categories."""
        idiffs = {
            f"leaf{i}": InterfaceDiff(
                node=f"leaf{i}",
                changed={f"eth{j}": {"oper_state": ("UP", "DOWN")} for j in range(1, 4)},
            )
            for i in range(1, 5)
        }
        rdiffs = {
            f"spine{i}": RouteDiff(
                node=f"spine{i}",
                removed=[RouteState(prefix=f"172.16.{j}.0/24") for j in range(1, 5)],
            )
            for i in range(1, 5)
        }
        qdiffs = {
            f"leaf{i}": QdiscDiff(
                node=f"leaf{i}",
                changed={f"eth{j}": {"dropped_packets": (0, 500)} for j in range(1, 3)},
            )
            for i in range(1, 5)
        }
        reach = ReachabilityDiff(
            newly_unreachable=[(f"h{i}", f"h{j}") for i in range(1, 5) for j in range(1, 5) if i != j],
            loss_changes={f"h{i}->h{j}": (0.0, 50.0) for i in range(1, 5) for j in range(1, 5) if i != j},
        )

        massive_diff = StateDiff(
            interface_diffs=idiffs,
            route_diffs=rdiffs,
            qdisc_diffs=qdiffs,
            reachability_diffs=reach,
        )

        md = massive_diff.to_llm_markdown()
        byte_len = len(md.encode("utf-8"))

        assert byte_len <= 480, f"Markdown exceeded token budget: {byte_len} bytes"
        assert md.endswith("... [truncated]")
        assert "### State Diff" in md


# ==============================================================================
# Suite 3: Rapid Sequential Fault Injection and Recovery Cycles
# ==============================================================================

class TestRapidSequentialFaultInjectionAndRecovery:
    """Stress-tests the fault injector and mock engine across repeated rapid cycles."""

    def test_rapid_sequential_fault_cycles_25_iterations(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """Execute 25 back-to-back injection and recovery cycles with zero state leaks."""
        eval_nodes = ["h1", "h2", "h3", "h4", "leaf1", "leaf2", "leaf3", "leaf4", "dc-egress"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)

        scenarios = [
            LinkDownFault(node="leaf1", interface="eth3"),
            RouteDropFault(node="leaf2", prefix="172.16.3.0/24"),
            PacketLossFault(node="leaf3", interface="eth3", loss_pct=25.0),
            LinkDownFault(node="leaf4", interface="eth3"),
            LinkDownFault(node="h1", interface="eth1"),
            RouteDropFault(node="dc-egress", prefix="172.16.4.0/24"),
            PacketLossFault(node="leaf2", interface="eth3", loss_pct=40.0),
        ]

        for cycle in range(25):
            scenario = scenarios[cycle % len(scenarios)]
            token = clos5_injector.inject_fault(scenario)
            assert token.active is True
            assert clos5_injector.active_faults_count == 1

            post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)
            diff = baseline.diff(post_fault)
            assert diff.has_anomalies() is True, f"Cycle {cycle}: anomaly not detected for {scenario.scenario_type}"

            reverted = clos5_injector.revert_fault(token)
            assert reverted is True
            assert clos5_injector.active_faults_count == 0

        # After 25 cycles, verify clean state return
        post_all = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=eval_nodes)
        diff_all = baseline.diff(post_all)
        assert diff_all.has_anomalies() is False
        assert post_all.is_healthy() is True

    def test_rapid_fault_context_cycles_with_exceptions(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """Verify fault_context() guarantees clean recovery across 15 cycles even under exceptions."""
        for cycle in range(15):
            scenario = LinkDownFault(node="leaf1", interface="eth3")
            with pytest.raises(RuntimeError):
                with clos5_injector.fault_context(scenario) as token:
                    assert token.active is True
                    assert clos5_injector.active_faults_count == 1
                    raise RuntimeError("Simulated transient runtime exception in user code")

            # Must be cleanly rolled back after exception
            assert clos5_injector.active_faults_count == 0

        # Verify interface is UP
        vnode = clos5_adapter.mock_engine.graph.nodes["leaf1"]
        assert vnode.interfaces["eth3"].oper_state == "UP"


# ==============================================================================
# Suite 4: Closed-Loop Self-Healing Across All Hosts (h1..h4)
# ==============================================================================

class TestClosedLoopSelfHealingAcrossAllHosts:
    """Stress-tests autonomous self-healing and reachability restoration across all 4 hosts."""

    def test_closed_loop_multi_fault_self_healing_all_hosts_mesh(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """Concurrent faults affecting h1..h4 are iteratively healed in <= 3 rounds to 100% full mesh."""
        target_nodes = ["h1", "h2", "h3", "h4", "leaf1", "leaf2", "leaf3", "leaf4"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=target_nodes)
        assert baseline.is_healthy() is True

        # Inject 3 concurrent faults affecting distinct host paths:
        # 1. leaf1:eth3 DOWN -> isolates h1
        # 2. leaf2 route to 172.16.3.0/24 dropped -> breaks h2 -> h3
        # 3. leaf4:eth3 packet loss 50% -> degrades h4
        clos5_injector.inject_fault(LinkDownFault(node="leaf1", interface="eth3"))
        clos5_injector.inject_fault(RouteDropFault(node="leaf2", prefix="172.16.3.0/24"))
        clos5_injector.inject_fault(PacketLossFault(node="leaf4", interface="eth3", loss_pct=50.0))

        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=target_nodes)
        initial_diff = baseline.diff(post_fault)
        assert initial_diff.has_anomalies() is True

        # Autonomous closed-loop healing
        engine = DiagnosticReasoningEngine()
        executor = DeterministicExecutor(lab_adapter=clos5_adapter, lab_name="clos5")
        rounds_executed = 0
        max_rounds = 5

        for round_idx in range(1, max_rounds + 1):
            curr_snap = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=target_nodes)
            curr_diff = baseline.diff(curr_snap)
            if not curr_diff.has_anomalies():
                break

            rounds_executed += 1
            plan = engine.analyze_diff_and_plan(curr_diff)
            assert plan.actions, f"Round {round_idx}: empty plan generated while anomalies remain"
            exec_res = executor.execute_plan(plan)
            assert exec_res.success is True, f"Round {round_idx}: execution failed: {exec_res.error}"

        assert rounds_executed == 3  # Exactly 3 rounds: link -> route -> qdisc

        # Post-repair programmatic verification
        final_snap = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=target_nodes)
        verifier = ProgrammaticVerifier(lab_adapter=clos5_adapter)
        v_res: VerificationResult = verifier.verify_repair(
            baseline=baseline,
            post_repair=final_snap,
            target_fault_diff=initial_diff,
        )
        assert v_res.passed is True
        assert len(v_res.unresolved_anomalies) == 0

        # Programmatically verify full 12-pair mesh reachability between h1..h4
        host_nodes = ["h1", "h2", "h3", "h4"]
        for src in host_nodes:
            for dst in host_nodes:
                if src != dst:
                    dst_ip = f"172.16.{dst[1]}.2"
                    ping_res = PingProbe.run(adapter=clos5_adapter, src_node=src, dst_ip=dst_ip, count=2)
                    assert ping_res.is_reachable is True, f"Unreachable: {src} -> {dst} ({dst_ip})"

    def test_simultaneous_quad_host_link_down_self_healing(
        self,
        clos5_adapter: MockContainerlabAdapter,
        clos5_injector: ContainerlabFaultInjector,
    ):
        """Simultaneous link-down on all 4 tenant hosts (h1..h4) resolved in a single atomic plan."""
        target_nodes = ["h1", "h2", "h3", "h4"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=target_nodes)

        # Drop eth1 on all 4 hosts simultaneously
        for h in target_nodes:
            clos5_injector.inject_fault(LinkDownFault(node=h, interface="eth1"))

        post_fault = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=target_nodes)
        diff = baseline.diff(post_fault)
        assert diff.has_link_failure() is True
        assert set(diff.affected_nodes()) == set(target_nodes)

        # Formulate atomic plan
        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy == DiagnosticStrategy.LINK_RECOVERY
        assert len(plan.actions) == 4

        # Apply deterministic fix
        executor = DeterministicExecutor(lab_adapter=clos5_adapter, lab_name="clos5")
        res = executor.execute_plan(plan)
        assert res.success is True
        assert len(res.executed_actions) == 4

        # Verify 100% recovery
        verifier = ProgrammaticVerifier(lab_adapter=clos5_adapter)
        verif = verifier.capture_and_verify(baseline=baseline, target_nodes=target_nodes, target_fault_diff=diff)
        assert verif.passed is True
        assert len(verif.unresolved_anomalies) == 0


# ==============================================================================
# Suite 5: Adversarial Boundary & Negative Conditions
# ==============================================================================

class TestAdversarialBoundaryAndNegativeConditions:
    """Tests security boundaries, transactional rollbacks, and idempotency."""

    def test_lab_isolation_guard_host_safety_and_container_name_validation(
        self,
        clos5_guard: LabIsolationGuard,
        clos5_adapter: MockContainerlabAdapter,
    ):
        """LabIsolationGuard and AAL block host interfaces, dangerous escapes, and non-clos5 containers."""
        # 1. Host interfaces must be blocked by LabIsolationGuard
        for host_nic_cmd in [
            "ip link set dev docker0 down",
            "ip link set dev eth0 down",
            "ip link set dev veth1234 down",
            "tc qdisc add dev br-fa1234 root netem loss 10%",
            "netsh interface set interface \"vEthernet\" disable",
        ]:
            with pytest.raises(LabIsolationViolationError):
                clos5_guard.assert_command_safety(host_nic_cmd, container_name="leaf1")

        # 2. Namespace escapes and destructive system calls blocked by LabIsolationGuard
        for escape_cmd in [
            "nsenter -t 1 -n ip link",
            "cat /proc/1/ns/net",
            "reboot",
            "shutdown now",
        ]:
            with pytest.raises(LabIsolationViolationError):
                clos5_guard.assert_command_safety(escape_cmd, container_name="leaf1")

        # 3. Non-clos5 containers must be blocked
        for invalid_container in ["host-machine", "clab-otherlab-node1", "my-vm", "127.0.0.1"]:
            with pytest.raises(LabIsolationViolationError):
                clos5_guard.assert_container_isolated(invalid_container)

        # 4. Dangerous firewall table flush blocked by AgentAccessLayer
        aal = AgentAccessLayer(lab_adapter=clos5_adapter)
        is_safe, err_msg = aal.validate_command_safety("iptables -F", read_only=False)
        assert is_safe is False
        assert "Firewall table/chain flush is blocked" in (err_msg or "")

    def test_deterministic_executor_transactional_lifo_rollback_on_pre_check_failure(
        self,
        clos5_adapter: MockContainerlabAdapter,
    ):
        """Pre-check failure on action 2 halts execution and rolls back action 1 in LIFO order."""
        clos5_adapter.exec_command("leaf1", "ip link set dev eth3 down")

        plan = RepairPlan(
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    order=1,
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth3 up",
                    rollback_command="ip link set dev eth3 down",
                ),
                RepairAction(
                    action_id="act-2",
                    order=2,
                    target_node="leaf2",
                    action_type="link_up",
                    command="ip link set dev eth3 up",
                    pre_check_command="ip link show dev eth3",
                    expected_pre_condition="NON_EXISTENT_STATE_XYZ",
                    rollback_command="ip link set dev eth3 down",
                ),
            ],
        )

        executor = DeterministicExecutor(lab_adapter=clos5_adapter, lab_name="clos5")
        res = executor.execute_plan(plan)

        assert res.success is False
        assert res.rolled_back is True
        assert len(res.executed_actions) == 1
        assert "Pre-check assertion failed" in (res.error or "")

        # Verify leaf1:eth3 was rolled back to DOWN
        vnode = clos5_adapter.mock_engine.graph.nodes["leaf1"]
        assert vnode.interfaces["eth3"].oper_state == "DOWN"

    def test_deterministic_executor_transactional_lifo_rollback_on_post_check_failure(
        self,
        clos5_adapter: MockContainerlabAdapter,
    ):
        """Post-check assertion failure on action 2 rolls back action 2 and action 1 in reverse order."""
        clos5_adapter.exec_command("leaf1", "ip link set dev eth3 down")

        plan = RepairPlan(
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    order=1,
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth3 up",
                    rollback_command="ip link set dev eth3 down",
                ),
                RepairAction(
                    action_id="act-2",
                    order=2,
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    post_check_command="ip link show dev eth1",
                    expected_post_condition="UNATTAINABLE_POST_CONDITION",
                    rollback_command="ip link set dev eth1 down",
                ),
            ],
        )

        executor = DeterministicExecutor(lab_adapter=clos5_adapter, lab_name="clos5")
        res = executor.execute_plan(plan)

        assert res.success is False
        assert res.rolled_back is True
        assert len(res.executed_actions) == 2
        assert "Post-check assertion failed" in (res.error or "")

        # leaf1:eth3 rolled back to DOWN
        vnode = clos5_adapter.mock_engine.graph.nodes["leaf1"]
        assert vnode.interfaces["eth3"].oper_state == "DOWN"

    def test_idempotent_healing_on_healthy_network(
        self,
        clos5_adapter: MockContainerlabAdapter,
    ):
        """When network is healthy, reasoning engine returns empty plan without mutating state."""
        target_nodes = ["h1", "h2", "leaf1", "leaf2"]
        baseline = NetworkStateSnapshotter.snapshot(adapter=clos5_adapter, target_nodes=target_nodes)
        diff = baseline.diff(baseline)
        assert diff.has_anomalies() is False

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy == DiagnosticStrategy.HEALTHY
        assert len(plan.actions) == 0

        executor = DeterministicExecutor(lab_adapter=clos5_adapter, lab_name="clos5")
        res = executor.execute_plan(plan)
        assert res.success is True
        assert len(res.executed_actions) == 0
        assert res.rolled_back is False
