"""Containerlab Experimental Loop Runner.

Coordinates the end-to-end experimental lifecycle:
1. Baseline Capture: Record healthy baseline interface states, routes, and ping reachability.
2. Fault Injection: Inject standard network faults via ContainerlabFaultInjector.
3. State Diff Detection: Compare post-fault state against baseline to detect anomalies.
4. Agent Remediation: Trigger agent / remediation logic to formulate and apply fixes.
5. Post-Repair Programmatic Verification: Validate that diff is cleared and reachability is 100% restored.

Provides clean programmatic APIs and CLI entrypoint.
"""

from __future__ import annotations

import argparse
from enum import Enum
import json
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import uuid

from pydantic import BaseModel, ConfigDict, Field

from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.clab_fault_injector import (
    ContainerlabFaultInjector,
    FaultScenario,
    InjectedFaultToken,
    LatencyFault,
    LinkDownFault,
    PacketLossFault,
    RouteDropFault,
)
from langgraph_netagent.tools.lab_isolation import LabIsolationGuard
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.probes import InterfaceProbe, PingProbe, QdiscProbe, RouteTableProbe


class LifecycleStage(str, Enum):
    """Stages of the experimental lifecycle."""
    IDLE = "idle"
    BASELINE_CAPTURED = "baseline_captured"
    FAULT_INJECTED = "fault_injected"
    DIFF_DETECTED = "diff_detected"
    REMEDIATION_APPLIED = "remediation_applied"
    VERIFICATION_COMPLETED = "verification_completed"
    FAILED = "failed"


class InterfaceSnapshot(BaseModel):
    """Snapshot of interface status on a node."""
    name: str
    admin_state: str = "UP"
    oper_state: str = "UP"
    ip_addresses: List[str] = Field(default_factory=list)


class ExperimentalNetworkSnapshot(BaseModel):
    """Captured state snapshot of network nodes, routes, and connectivity."""
    model_config = ConfigDict(populate_by_name=True)

    timestamp: float = Field(default_factory=time.time)
    interfaces: Dict[str, List[InterfaceSnapshot]] = Field(default_factory=dict)  # node -> list[iface]
    routes: Dict[str, List[str]] = Field(default_factory=dict)  # node -> list[destination prefixes]
    reachability: Dict[str, bool] = Field(default_factory=dict)  # "src->dst" -> is_reachable
    qdiscs: Dict[str, List[str]] = Field(default_factory=dict)  # node -> list[qdisc descriptions]


class ExperimentalStateDiff(BaseModel):
    """Structured delta between baseline and current network state."""
    model_config = ConfigDict(populate_by_name=True)

    interfaces_down: List[str] = Field(default_factory=list, description="Interfaces transitioned from UP to DOWN (node:iface)")
    routes_missing: List[str] = Field(default_factory=list, description="Routes present in baseline but missing now (node:prefix)")
    reachability_failures: List[str] = Field(default_factory=list, description="Probes reachable in baseline but failing now")
    qdisc_anomalies: List[str] = Field(default_factory=list, description="Unexpected qdiscs present on nodes")
    is_anomaly_detected: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def has_anomalies(self) -> bool:
        return (
            bool(self.interfaces_down)
            or bool(self.routes_missing)
            or bool(self.reachability_failures)
            or bool(self.qdisc_anomalies)
        )


class VerificationOutcome(BaseModel):
    """Outcome of post-repair verification."""
    passed: bool
    details: List[str] = Field(default_factory=list)
    remaining_anomalies: Optional[ExperimentalStateDiff] = None


class ExperimentResult(BaseModel):
    """End-to-end outcome of an experimental loop execution."""
    model_config = ConfigDict(populate_by_name=True)

    experiment_id: str = Field(default_factory=lambda: f"exp-{uuid.uuid4().hex[:8]}")
    scenario_type: str
    target_node: str
    stage: LifecycleStage
    success: bool
    baseline_healthy: bool
    fault_token: Optional[InjectedFaultToken] = None
    state_diff: Optional[ExperimentalStateDiff] = None
    remediation_result: Optional[Dict[str, Any]] = None
    verification: Optional[VerificationOutcome] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None


class ExperimentalLoop:
    """Coordinates the experimental loop lifecycle for Containerlab."""

    # Default probe matrix for clos5 topology
    DEFAULT_PING_TARGETS: List[Tuple[str, str]] = [
        ("h1", "172.16.2.2"),     # h1 -> h2
        ("h1", "172.16.3.2"),     # h1 -> h3
        ("h2", "172.16.4.2"),     # h2 -> h4
        ("attacker", "203.0.113.10"),  # attacker -> h1 VIP
    ]

    DEFAULT_TARGET_NODES: List[str] = [
        "leaf1", "leaf2", "leaf3", "leaf4",
        "spine1", "spine2", "spine3", "spine4",
        "h1", "h2", "h3", "h4",
        "dc-egress", "ext-router", "attacker",
    ]

    def __init__(
        self,
        adapter: Optional[BaseNetworkLabAdapter] = None,
        fault_injector: Optional[ContainerlabFaultInjector] = None,
        isolation_guard: Optional[LabIsolationGuard] = None,
        lab_name: str = "clos5",
        target_nodes: Optional[List[str]] = None,
        ping_targets: Optional[List[Tuple[str, str]]] = None,
    ):
        """Initialize ExperimentalLoop.

        Args:
            adapter: Lab adapter (LiveContainerlabAdapter or MockContainerlabAdapter).
            fault_injector: ContainerlabFaultInjector instance.
            isolation_guard: LabIsolationGuard instance.
            lab_name: Topology name (default 'clos5').
            target_nodes: Nodes to include in state capture.
            ping_targets: List of (source_node, target_ip) tuples to probe.
        """
        self.lab_name = lab_name
        self.isolation_guard = isolation_guard or LabIsolationGuard(lab_name=lab_name)
        self.adapter = adapter or MockContainerlabAdapter()
        self.fault_injector = fault_injector or ContainerlabFaultInjector(
            adapter=self.adapter,
            isolation_guard=self.isolation_guard,
            lab_name=lab_name,
        )
        self.target_nodes = target_nodes or list(self.DEFAULT_TARGET_NODES)
        self.ping_targets = ping_targets or list(self.DEFAULT_PING_TARGETS)

    def capture_snapshot(
        self,
        nodes: Optional[List[str]] = None,
        ping_pairs: Optional[List[Tuple[str, str]]] = None,
    ) -> ExperimentalNetworkSnapshot:
        """Capture a point-in-time network state snapshot across target nodes.

        Args:
            nodes: Optional subset of nodes to inspect.
            ping_pairs: Optional subset of ping pairs to test.

        Returns:
            ExperimentalNetworkSnapshot instance.
        """
        eval_nodes = nodes or self.target_nodes
        eval_pings = ping_pairs if ping_pairs is not None else self.ping_targets

        iface_map: Dict[str, List[InterfaceSnapshot]] = {}
        route_map: Dict[str, List[str]] = {}
        qdisc_map: Dict[str, List[str]] = {}
        reachability_map: Dict[str, bool] = {}

        # 1. Capture interface states and qdiscs
        for node in eval_nodes:
            self.fault_injector._ensure_mock_node(node)
            try:
                ifaces = InterfaceProbe.run(adapter=self.adapter, node=node)
                iface_map[node] = [
                    InterfaceSnapshot(
                        name=ifc.interface_name,
                        admin_state=ifc.admin_state,
                        oper_state=ifc.oper_state,
                        ip_addresses=[ip.split("/")[0] for ip in ifc.ip_addresses if ip],
                    )
                    for ifc in ifaces
                ]
            except Exception:
                iface_map[node] = []

            # Capture route prefixes
            try:
                kind = "frr" if ("leaf" in node or "spine" in node) else "linux"
                rt = RouteTableProbe.run(adapter=self.adapter, node=node, device_kind=kind)
                route_map[node] = [r.prefix for r in rt.routes if r.prefix]
            except Exception:
                route_map[node] = []

            # Capture qdiscs
            try:
                qdiscs = QdiscProbe.run(adapter=self.adapter, node=node)
                qdisc_map[node] = [f"{q.interface} {q.qdisc_type}" for q in qdiscs if q.qdisc_type != "noqueue"]
            except Exception:
                qdisc_map[node] = []

        # 2. Capture reachability
        for src, dst in eval_pings:
            pair_key = f"{src}->{dst}"
            try:
                ping_res = PingProbe.run(adapter=self.adapter, src_node=src, dst_ip=dst, count=2, timeout=2)
                reachability_map[pair_key] = ping_res.is_reachable
            except Exception:
                reachability_map[pair_key] = False

        return ExperimentalNetworkSnapshot(
            interfaces=iface_map,
            routes=route_map,
            reachability=reachability_map,
            qdiscs=qdisc_map,
        )

    def detect_state_diff(
        self,
        baseline: ExperimentalNetworkSnapshot,
        current: ExperimentalNetworkSnapshot,
    ) -> ExperimentalStateDiff:
        """Compute structured difference between baseline and current state.

        Args:
            baseline: Baseline healthy snapshot.
            current: Current (e.g. post-fault) snapshot.

        Returns:
            ExperimentalStateDiff object highlighting anomalies.
        """
        interfaces_down: List[str] = []
        routes_missing: List[str] = []
        reachability_failures: List[str] = []
        qdisc_anomalies: List[str] = []

        # Compare interfaces
        for node, base_ifaces in baseline.interfaces.items():
            curr_ifaces = {i.name: i for i in current.interfaces.get(node, [])}
            for b_ifc in base_ifaces:
                if b_ifc.oper_state.upper() == "UP":
                    c_ifc = curr_ifaces.get(b_ifc.name)
                    if c_ifc and c_ifc.oper_state.upper() != "UP":
                        interfaces_down.append(f"{node}:{b_ifc.name}")

        # Compare routes
        for node, base_routes in baseline.routes.items():
            curr_routes = set(current.routes.get(node, []))
            for b_pfx in base_routes:
                if b_pfx not in curr_routes and b_pfx not in ("default", "0.0.0.0/0", "127.0.0.0/8"):
                    routes_missing.append(f"{node}:{b_pfx}")

        # Compare reachability
        for probe_key, base_reachable in baseline.reachability.items():
            if base_reachable:
                curr_reachable = current.reachability.get(probe_key, False)
                if not curr_reachable:
                    reachability_failures.append(probe_key)

        # Compare qdiscs
        for node, curr_qs in current.qdiscs.items():
            base_qs = set(baseline.qdiscs.get(node, []))
            for q in curr_qs:
                if "netem" in q or (q not in base_qs and "tbf" in q):
                    qdisc_anomalies.append(f"{node}:{q}")

        is_anomaly = bool(interfaces_down or routes_missing or reachability_failures or qdisc_anomalies)

        return ExperimentalStateDiff(
            interfaces_down=interfaces_down,
            routes_missing=routes_missing,
            reachability_failures=reachability_failures,
            qdisc_anomalies=qdisc_anomalies,
            is_anomaly_detected=is_anomaly,
            details={
                "baseline_timestamp": baseline.timestamp,
                "current_timestamp": current.timestamp,
            },
        )

    def verify_post_repair(
        self,
        baseline: ExperimentalNetworkSnapshot,
        post_repair: ExperimentalNetworkSnapshot,
    ) -> VerificationOutcome:
        """Verify that post-repair state matches baseline health.

        Args:
            baseline: Initial healthy snapshot.
            post_repair: Snapshot captured after applying remediation.

        Returns:
            VerificationOutcome with pass/fail and descriptive details.
        """
        diff = self.detect_state_diff(baseline=baseline, current=post_repair)
        details: List[str] = []

        if not diff.has_anomalies:
            details.append("100% reachability and topology state restored to baseline health.")
            return VerificationOutcome(passed=True, details=details, remaining_anomalies=diff)

        if diff.interfaces_down:
            details.append(f"Interfaces still DOWN: {', '.join(diff.interfaces_down)}")
        if diff.routes_missing:
            details.append(f"Routes still missing: {', '.join(diff.routes_missing)}")
        if diff.reachability_failures:
            details.append(f"Reachability still broken: {', '.join(diff.reachability_failures)}")
        if diff.qdisc_anomalies:
            details.append(f"Lingering qdiscs: {', '.join(diff.qdisc_anomalies)}")

        return VerificationOutcome(passed=False, details=details, remaining_anomalies=diff)

    def run_experiment(
        self,
        scenario: FaultScenario,
        agent_handler: Optional[Callable[[ExperimentalStateDiff, BaseNetworkLabAdapter], Any]] = None,
        auto_rollback_on_failure: bool = True,
        auto_heal: bool = False,
    ) -> ExperimentResult:
        """Execute the end-to-end experimental loop.

        Lifecycle:
        1. Capture baseline snapshot
        2. Inject fault scenario
        3. Detect state diff
        4. Apply agent remediation (or revert token if handler omitted)
        5. Verify recovery
        6. Clean up

        Args:
            scenario: The fault scenario to inject.
            agent_handler: Optional callback receiving (state_diff, adapter) to perform repair.
                           If None, automatic token rollback or agentic auto_heal is used.
            auto_rollback_on_failure: Whether to invoke revert_all() if verification fails.
            auto_heal: When True, uses DiagnosticReasoningEngine and DeterministicExecutor
                       to formulate and apply deterministic repairs automatically.

        Returns:
            ExperimentResult detailing the experiment execution and verification.
        """
        start_time = time.time()
        stage = LifecycleStage.IDLE
        token: Optional[InjectedFaultToken] = None
        state_diff: Optional[ExperimentalStateDiff] = None
        remediation_res: Optional[Dict[str, Any]] = None

        try:
            # 1. Baseline Capture
            baseline_snap = self.capture_snapshot()
            net_baseline_snap = None
            if auto_heal:
                from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter
                net_baseline_snap = NetworkStateSnapshotter.snapshot(adapter=self.adapter, target_nodes=self.target_nodes, lab_name=self.lab_name)
            stage = LifecycleStage.BASELINE_CAPTURED

            # 2. Fault Injection
            token = self.fault_injector.inject_fault(scenario)
            stage = LifecycleStage.FAULT_INJECTED

            # 3. State Diff Detection
            post_fault_snap = self.capture_snapshot()
            net_post_fault_snap = None
            if auto_heal:
                from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter
                net_post_fault_snap = NetworkStateSnapshotter.snapshot(adapter=self.adapter, target_nodes=self.target_nodes, lab_name=self.lab_name)
            state_diff = self.detect_state_diff(baseline=baseline_snap, current=post_fault_snap)
            stage = LifecycleStage.DIFF_DETECTED

            # 4. Agent Remediation
            if agent_handler is not None:
                remediation_res = {"handler_output": agent_handler(state_diff, self.adapter)}
            elif auto_heal:
                from langgraph_netagent.workflow.reasoning_engine import DiagnosticReasoningEngine
                from langgraph_netagent.tools.deterministic_executor import DeterministicExecutor

                structured_diff = net_baseline_snap.diff(net_post_fault_snap) if net_baseline_snap and net_post_fault_snap else None

                engine = DiagnosticReasoningEngine()
                plan = engine.analyze_diff_and_plan(structured_diff) if structured_diff else None

                if plan and plan.actions:
                    executor = DeterministicExecutor(lab_adapter=self.adapter, isolation_guard=self.isolation_guard, lab_name=self.lab_name)
                    exec_res = executor.execute_plan(plan)
                    remediation_res = {
                        "auto_heal": True,
                        "plan_strategy": plan.strategy.value,
                        "actions": [a.command for a in plan.actions],
                        "execution_success": exec_res.success,
                    }
                    if exec_res.success and token:
                        token.active = False
                else:
                    reverted = self.fault_injector.revert_fault(token)
                    remediation_res = {"token_reverted": reverted}
            else:
                # Default remediation: execute exact symmetric token rollback
                reverted = self.fault_injector.revert_fault(token)
                remediation_res = {"token_reverted": reverted}

            stage = LifecycleStage.REMEDIATION_APPLIED

            # 5. Post-Repair Programmatic Verification
            post_repair_snap = self.capture_snapshot()
            verification = self.verify_post_repair(baseline=baseline_snap, post_repair=post_repair_snap)
            stage = LifecycleStage.VERIFICATION_COMPLETED

            success = verification.passed

            if not success and auto_rollback_on_failure:
                self.fault_injector.revert_all()

            duration = time.time() - start_time
            return ExperimentResult(
                scenario_type=scenario.scenario_type,
                target_node=scenario.node,
                stage=stage,
                success=success,
                baseline_healthy=True,
                fault_token=token,
                state_diff=state_diff,
                remediation_result=remediation_res,
                verification=verification,
                duration_seconds=duration,
            )

        except Exception as exc:
            if auto_rollback_on_failure:
                self.fault_injector.revert_all()

            duration = time.time() - start_time
            return ExperimentResult(
                scenario_type=scenario.scenario_type,
                target_node=scenario.node,
                stage=LifecycleStage.FAILED,
                success=False,
                baseline_healthy=True,
                fault_token=token,
                state_diff=state_diff,
                remediation_result=remediation_res,
                duration_seconds=duration,
                error_message=str(exc),
            )


def build_scenario_from_args(args: argparse.Namespace) -> FaultScenario:
    """Helper to parse CLI arguments into a concrete FaultScenario."""
    stype = args.scenario.lower()
    if stype == "link_down":
        if not args.interface:
            raise ValueError("--interface is required for link_down scenario")
        return LinkDownFault(node=args.node, interface=args.interface)
    elif stype == "route_drop":
        return RouteDropFault(
            node=args.node,
            prefix=args.prefix or "",
            via=args.via,
            bgp_neighbor=args.bgp_neighbor,
            bgp_as=args.bgp_as,
        )
    elif stype == "packet_loss":
        if not args.interface:
            raise ValueError("--interface is required for packet_loss scenario")
        loss = float(args.loss) if args.loss is not None else 15.0
        return PacketLossFault(node=args.node, interface=args.interface, loss_pct=loss)
    elif stype == "latency":
        if not args.interface:
            raise ValueError("--interface is required for latency scenario")
        delay = float(args.delay) if args.delay is not None else 50.0
        jitter = float(args.jitter) if args.jitter is not None else None
        return LatencyFault(node=args.node, interface=args.interface, delay_ms=delay, jitter_ms=jitter)
    else:
        raise ValueError(f"Unknown scenario type '{args.scenario}'")


def main() -> None:
    """CLI entrypoint for running Containerlab experimental loop."""
    parser = argparse.ArgumentParser(description="Containerlab Experimental Loop Runner")
    parser.add_argument("--lab-name", default="clos5", help="Target topology name")
    parser.add_argument(
        "--scenario",
        required=True,
        choices=["link_down", "route_drop", "packet_loss", "latency"],
        help="Fault scenario category",
    )
    parser.add_argument("--node", required=True, help="Target logical node (e.g. leaf1)")
    parser.add_argument("--interface", help="Target interface (e.g. eth1)")
    parser.add_argument("--prefix", help="Route prefix (for route_drop)")
    parser.add_argument("--via", help="Next hop IP for route_drop restoration")
    parser.add_argument("--bgp-neighbor", help="BGP neighbor interface for FRR")
    parser.add_argument("--bgp-as", type=int, help="BGP Autonomous System number")
    parser.add_argument("--loss", type=float, default=20.0, help="Packet loss percentage")
    parser.add_argument("--delay", type=float, default=50.0, help="Latency in milliseconds")
    parser.add_argument("--jitter", type=float, help="Jitter in milliseconds")
    parser.add_argument("--mode", choices=["mock", "live"], default="mock", help="Execution mode")
    parser.add_argument("--json", action="store_true", help="Output JSON result")
    parser.add_argument("--auto-heal", action="store_true", help="Enable automated agentic self-healing")

    args = parser.parse_args()

    # Select adapter
    if args.mode == "live":
        from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter
        adapter = LiveContainerlabAdapter(lab_name=args.lab_name)
    else:
        adapter = MockContainerlabAdapter()

    scenario = build_scenario_from_args(args)
    loop = ExperimentalLoop(adapter=adapter, lab_name=args.lab_name)

    result = loop.run_experiment(scenario=scenario, auto_heal=args.auto_heal)

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        status_sym = "✅ PASS" if result.success else "❌ FAIL"
        print(f"\n[{status_sym}] Experiment {result.experiment_id}: {result.scenario_type} on {result.target_node}")
        print(f"Stage: {result.stage.value}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        if result.state_diff and result.state_diff.has_anomalies:
            print("Detected Anomalies:")
            if result.state_diff.interfaces_down:
                print(f"  Interfaces Down: {result.state_diff.interfaces_down}")
            if result.state_diff.routes_missing:
                print(f"  Routes Missing: {result.state_diff.routes_missing}")
            if result.state_diff.reachability_failures:
                print(f"  Reachability Broken: {result.state_diff.reachability_failures}")
        if result.verification:
            print(f"Verification: {'PASSED' if result.verification.passed else 'FAILED'}")
            for d in result.verification.details:
                print(f"  - {d}")

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
