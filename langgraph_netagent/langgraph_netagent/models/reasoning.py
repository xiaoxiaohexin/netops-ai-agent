"""Diagnostic Reasoning Models and Strategy Taxonomy (R3).

Defines the formal DiagnosticStrategy taxonomy and the deterministic
DiagnosticStrategySelector that maps StateDiff deltas to primary and secondary
diagnostic strategies.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field

from langgraph_netagent.models.network_state import StateDiff


class DiagnosticStrategy(str, Enum):
    """Categorized diagnostic remediation strategy."""
    LINK_RECOVERY = "link_recovery"             # Bouncing / enabling failed interfaces (ip link set dev <iface> up)
    ROUTING_REPAIR = "routing_repair"           # Re-injecting missing routes / restarting BGP sessions
    TRAFFIC_FILTERING_ACL = "traffic_filtering_acl"  # Blocking DDoS/attacker traffic, rate limiting, dropping overload
    INTERFACE_RESTART = "interface_restart"     # Restarting interfaces with MTU / queue errors or flapping
    QDISC_RESET = "qdisc_reset"                 # Clearing bad qdisc netem rules causing packet loss/latency
    HEALTHY = "healthy"                         # Network is in healthy state; no remediation needed

    @classmethod
    def _missing_(cls, value: object) -> Optional[DiagnosticStrategy]:
        if isinstance(value, str):
            clean = value.strip().lower().replace("-", "_").replace(" ", "_")
            for member in cls:
                if member.value == clean or member.name.lower() == clean:
                    return member
            if "link" in clean or "interface_up" in clean:
                return cls.LINK_RECOVERY
            if "route" in clean or "bgp" in clean:
                return cls.ROUTING_REPAIR
            if "filter" in clean or "acl" in clean or "drop" in clean or "overload" in clean:
                return cls.TRAFFIC_FILTERING_ACL
            if "restart" in clean or "bounce" in clean:
                return cls.INTERFACE_RESTART
            if "qdisc" in clean or "netem" in clean or "loss" in clean:
                return cls.QDISC_RESET
            if "health" in clean or "ok" in clean:
                return cls.HEALTHY
        return None


class StrategySelectionResult(BaseModel):
    """Result of deterministic strategy selection from StateDiff."""
    model_config = ConfigDict(populate_by_name=True)

    primary_strategy: DiagnosticStrategy = Field(..., description="Primary diagnostic remediation strategy")
    secondary_strategy: Optional[DiagnosticStrategy] = Field(default=None, description="Optional secondary fallback strategy")
    reasoning: str = Field(default="", description="Deterministic explanation of why this strategy was selected")
    affected_nodes: List[str] = Field(default_factory=list, description="List of nodes targeted for remediation")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Selection confidence score")

    @property
    def strategy(self) -> DiagnosticStrategy:
        """Alias for primary_strategy."""
        return self.primary_strategy


# Alias for compatibility
DiagnosticStrategyDecision = StrategySelectionResult


class DiagnosticStrategySelector:
    """Analyzes StateDiff to deterministically select primary and secondary DiagnosticStrategy."""

    @classmethod
    def select(cls, state_diff: Optional[StateDiff]) -> StrategySelectionResult:
        """Select primary and secondary DiagnosticStrategy from a StateDiff.

        Args:
            state_diff: The StateDiff instance comparing baseline vs current state.

        Returns:
            StrategySelectionResult containing primary_strategy, secondary_strategy, and reasoning.
        """
        if state_diff is None or not state_diff.has_anomalies():
            return StrategySelectionResult(
                primary_strategy=DiagnosticStrategy.HEALTHY,
                secondary_strategy=None,
                reasoning="No anomalies detected in StateDiff. Network state is healthy.",
                affected_nodes=[],
                confidence=1.0,
            )

        affected = state_diff.affected_nodes()
        primary: Optional[DiagnosticStrategy] = None
        secondary: Optional[DiagnosticStrategy] = None
        reasons: List[str] = []

        # 1. Check for physical/virtual link failures (oper_state == DOWN or interface removed)
        has_link_down = state_diff.has_link_failure()
        down_ifaces: List[str] = []
        if has_link_down:
            for node, idiff in state_diff.interface_diffs.items():
                for if_name, changes in idiff.changed.items():
                    if "oper_state" in changes and changes["oper_state"][1] in ("DOWN", "NO-CARRIER"):
                        down_ifaces.append(f"{node}:{if_name}")
                for ifc in idiff.removed:
                    down_ifaces.append(f"{node}:{ifc.name}")
            reasons.append(f"Interface down detected on: {', '.join(down_ifaces)}")

        # 2. Check for route drops or withdrawals
        has_route_down = state_diff.has_route_failure()
        dropped_routes: List[str] = []
        if has_route_down:
            for node, rdiff in state_diff.route_diffs.items():
                for r in rdiff.removed:
                    dropped_routes.append(f"{node} missing {r.prefix}")
                for pfx, changes in rdiff.changed.items():
                    if "active" in changes and not changes["active"][1]:
                        dropped_routes.append(f"{node} inactive {pfx}")
            reasons.append(f"Route failure detected: {', '.join(dropped_routes)}")

        # 3. Check for qdisc netem loss or delay
        has_netem_loss = False
        has_qdisc_overlimits = False
        qdisc_issues: List[str] = []
        for node, qdiff in state_diff.qdisc_diffs.items():
            for ifc, changes in qdiff.changed.items():
                if "loss_percent" in changes and changes["loss_percent"][1] > 0:
                    has_netem_loss = True
                    qdisc_issues.append(f"{node}:{ifc} netem loss {changes['loss_percent'][1]:g}%")
                if "delay_ms" in changes and changes["delay_ms"][1] > 0:
                    has_netem_loss = True
                    qdisc_issues.append(f"{node}:{ifc} netem delay {changes['delay_ms'][1]:g}ms")
                if "overlimits" in changes and changes["overlimits"][1] > changes["overlimits"][0]:
                    has_qdisc_overlimits = True
                    qdisc_issues.append(f"{node}:{ifc} queue overlimits")
                if "dropped_packets" in changes and changes["dropped_packets"][1] > changes["dropped_packets"][0]:
                    has_qdisc_overlimits = True
                    qdisc_issues.append(f"{node}:{ifc} buffer dropped packets")

        if qdisc_issues:
            reasons.extend(qdisc_issues)

        # 4. Check for interface packet drops or hardware errors
        has_interface_errors = False
        for node, idiff in state_diff.interface_diffs.items():
            for ifc, changes in idiff.changed.items():
                for metric in ("rx_dropped", "tx_dropped", "rx_errors", "tx_errors"):
                    if metric in changes and changes[metric][1] > changes[metric][0]:
                        has_interface_errors = True
                        reasons.append(f"{node}:{ifc} {metric} increased ({changes[metric][0]} -> {changes[metric][1]})")

        # 5. Prioritize primary and secondary strategies
        if has_link_down:
            primary = DiagnosticStrategy.LINK_RECOVERY
            if has_route_down:
                secondary = DiagnosticStrategy.ROUTING_REPAIR
            elif has_netem_loss:
                secondary = DiagnosticStrategy.QDISC_RESET
            elif has_interface_errors:
                secondary = DiagnosticStrategy.INTERFACE_RESTART
        elif has_route_down:
            primary = DiagnosticStrategy.ROUTING_REPAIR
            if has_netem_loss:
                secondary = DiagnosticStrategy.QDISC_RESET
            elif has_qdisc_overlimits:
                secondary = DiagnosticStrategy.TRAFFIC_FILTERING_ACL
        elif has_netem_loss:
            primary = DiagnosticStrategy.QDISC_RESET
            if has_qdisc_overlimits:
                secondary = DiagnosticStrategy.TRAFFIC_FILTERING_ACL
            elif has_interface_errors:
                secondary = DiagnosticStrategy.INTERFACE_RESTART
        elif has_qdisc_overlimits or (state_diff.reachability_diffs.loss_changes and not has_link_down and not has_route_down and not has_netem_loss):
            # If buffer overlimits or loss without netem/link/route down -> traffic filtering / ACL
            primary = DiagnosticStrategy.TRAFFIC_FILTERING_ACL
            secondary = DiagnosticStrategy.QDISC_RESET
        elif has_interface_errors:
            primary = DiagnosticStrategy.INTERFACE_RESTART
            secondary = DiagnosticStrategy.LINK_RECOVERY
        else:
            # Fallback based on reachability failures
            if state_diff.reachability_diffs.newly_unreachable or state_diff.reachability_diffs.loss_changes:
                primary = DiagnosticStrategy.ROUTING_REPAIR
                secondary = DiagnosticStrategy.LINK_RECOVERY
            else:
                primary = DiagnosticStrategy.HEALTHY
                secondary = None

        full_reason = "; ".join(reasons) if reasons else f"Selected based on StateDiff anomalies (primary: {primary.value})"

        return StrategySelectionResult(
            primary_strategy=primary,
            secondary_strategy=secondary,
            reasoning=full_reason,
            affected_nodes=affected,
            confidence=0.95 if secondary else 1.0,
        )

    def select_strategy(self, state_diff: Optional[StateDiff]) -> DiagnosticStrategy:
        """Convenience method returning just the primary DiagnosticStrategy."""
        return self.select(state_diff).primary_strategy

    def select_strategies(self, state_diff: Optional[StateDiff]) -> Tuple[DiagnosticStrategy, Optional[DiagnosticStrategy]]:
        """Convenience method returning (primary_strategy, secondary_strategy)."""
        res = self.select(state_diff)
        return (res.primary_strategy, res.secondary_strategy)
