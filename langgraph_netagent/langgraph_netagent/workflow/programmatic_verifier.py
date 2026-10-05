"""Programmatic Verifier for Post-Repair Validation (R3).

Implements ProgrammaticVerifier that compares baseline vs post-repair NetworkState,
computes remaining StateDiff, and programmatically asserts:
1. All previously broken interfaces are now UP.
2. All previously missing routes are restored.
3. Reachability matrix is restored (100% ping pass).
4. Packet loss rate is 0% with no queue netem impairments.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from langgraph_netagent.models.network_state import (
    NetworkState,
    StateDiff,
    compute_state_diff,
)
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter

logger = logging.getLogger(__name__)


class VerificationResult(BaseModel):
    """Result of programmatic post-repair verification."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    passed: bool = Field(..., description="True if all anomalies were resolved and network is healthy")
    remaining_diff: StateDiff = Field(..., description="Remaining state difference against baseline")
    details: str = Field(default="", description="Detailed summary of verification findings")
    resolved_anomalies: List[str] = Field(default_factory=list, description="Anomalies confirmed resolved")
    unresolved_anomalies: List[str] = Field(default_factory=list, description="Anomalies that persist after repair")


class ProgrammaticVerifier:
    """Programmatically verifies network recovery against baseline state."""

    def __init__(
        self,
        snapshotter: Optional[NetworkStateSnapshotter] = None,
        lab_adapter: Optional[BaseNetworkLabAdapter] = None,
    ):
        self.lab_adapter = lab_adapter
        if snapshotter:
            self.snapshotter = snapshotter
        elif lab_adapter:
            self.snapshotter = NetworkStateSnapshotter(lab_adapter=lab_adapter)
        else:
            self.snapshotter = None

    def capture_and_verify(
        self,
        baseline: NetworkState,
        target_fault_diff: Optional[StateDiff] = None,
        target_nodes: Optional[List[str]] = None,
    ) -> VerificationResult:
        """Capture a fresh post-repair NetworkState and verify against baseline.

        Args:
            baseline: The healthy baseline NetworkState.
            target_fault_diff: Optional StateDiff representing the injected fault.
            target_nodes: Optional list of nodes to snapshot.

        Returns:
            VerificationResult.
        """
        if not self.snapshotter:
            raise RuntimeError("ProgrammaticVerifier requires a snapshotter or lab_adapter to capture live states.")

        post_repair = self.snapshotter.capture_snapshot(target_nodes=target_nodes)
        return self.verify_repair(
            baseline=baseline,
            post_repair=post_repair,
            target_fault_diff=target_fault_diff,
        )

    def verify_repair(
        self,
        baseline: NetworkState,
        post_repair: NetworkState,
        target_fault_diff: Optional[StateDiff] = None,
    ) -> VerificationResult:
        """Assert that network has recovered to healthy baseline state.

        Checks:
        1. All interfaces previously down are UP.
        2. All routes previously missing are restored.
        3. Reachability matrix is restored (all reachable, 0% loss).
        4. Packet loss rate is 0% (no netem loss or queue buffer drops).

        Args:
            baseline: The original healthy baseline NetworkState.
            post_repair: The post-repair snapshot.
            target_fault_diff: Optional StateDiff representing the fault being repaired.

        Returns:
            VerificationResult.
        """
        remaining_diff: StateDiff = compute_state_diff(baseline=baseline, current=post_repair)

        resolved: List[str] = []
        unresolved: List[str] = []

        # ---------------------------------------------------------------------
        # 1. Verify Interface States (All broken links restored to UP)
        # ---------------------------------------------------------------------
        broken_interfaces_found = False
        for node, idiff in remaining_diff.interface_diffs.items():
            for if_name, changes in idiff.changed.items():
                if "oper_state" in changes:
                    _was, now = changes["oper_state"]
                    if now in ("DOWN", "NO-CARRIER"):
                        unresolved.append(f"Interface {node}:{if_name} remains DOWN")
                        broken_interfaces_found = True
                if "admin_state" in changes and changes["admin_state"][1] == "DOWN":
                    unresolved.append(f"Interface {node}:{if_name} remains admin DOWN")
                    broken_interfaces_found = True
            for ifc in idiff.removed:
                unresolved.append(f"Interface {node}:{ifc.name} is missing")
                broken_interfaces_found = True

        if not broken_interfaces_found and target_fault_diff and target_fault_diff.has_link_failure():
            resolved.append("All previously broken interfaces are UP")

        # ---------------------------------------------------------------------
        # 2. Verify Routing Tables (All missing routes restored)
        # ---------------------------------------------------------------------
        missing_routes_found = False
        for node, rdiff in remaining_diff.route_diffs.items():
            for r in rdiff.removed:
                unresolved.append(f"Route {r.prefix} on {node} remains missing")
                missing_routes_found = True
            for pfx, changes in rdiff.changed.items():
                if "active" in changes and not changes["active"][1]:
                    unresolved.append(f"Route {pfx} on {node} remains inactive")
                    missing_routes_found = True

        if not missing_routes_found and target_fault_diff and target_fault_diff.has_route_failure():
            resolved.append("All previously missing routes are present and active")

        # ---------------------------------------------------------------------
        # 3. Verify Reachability Matrix (100% ping pass between key nodes)
        # ---------------------------------------------------------------------
        unreachable_pairs = []
        for r in post_repair.reachability_matrix:
            if not r.reachable or r.packet_loss_pct > 0.0:
                unreachable_pairs.append(f"{r.source}->{r.destination} (loss {r.packet_loss_pct}%)")

        if unreachable_pairs:
            for p in unreachable_pairs:
                unresolved.append(f"Unreachable probe: {p}")
        else:
            if post_repair.reachability_matrix:
                resolved.append("Reachability matrix restored (100% ping pass)")

        # ---------------------------------------------------------------------
        # 4. Verify Packet Loss & Qdisc Netem
        # ---------------------------------------------------------------------
        qdisc_issues_found = False
        for node, qdiff in remaining_diff.qdisc_diffs.items():
            for ifc, changes in qdiff.changed.items():
                if "loss_percent" in changes and changes["loss_percent"][1] > 0.0:
                    unresolved.append(f"Netem loss remains on {node}:{ifc} ({changes['loss_percent'][1]}%)")
                    qdisc_issues_found = True
                if "delay_ms" in changes and changes["delay_ms"][1] > 0.0:
                    unresolved.append(f"Netem delay remains on {node}:{ifc} ({changes['delay_ms'][1]}ms)")
                    qdisc_issues_found = True

        if not qdisc_issues_found and target_fault_diff and target_fault_diff.has_packet_loss():
            resolved.append("Queue disciplines reset: 0% netem loss and delay")

        # ---------------------------------------------------------------------
        # Overall Assessment
        # ---------------------------------------------------------------------
        passed = (len(unresolved) == 0)

        if passed:
            details = "Programmatic verification PASSED: 100% reachability restored, 0% packet loss, all interfaces UP, all routes present."
        else:
            details = f"Programmatic verification FAILED: {len(unresolved)} issue(s) remaining: {'; '.join(unresolved)}"

        return VerificationResult(
            passed=passed,
            remaining_diff=remaining_diff,
            details=details,
            resolved_anomalies=resolved,
            unresolved_anomalies=unresolved,
        )
