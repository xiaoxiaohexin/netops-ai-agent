"""Structured NetworkState Model and State Diff Engine (R2).

Provides Pydantic v2 models representing the operational state of a network fabric
(interfaces, routes, qdiscs, reachability) and a deterministic diff engine
that serializes state differences into concise markdown summaries for LLM reasoning.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Literal, Optional, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# =============================================================================
# 1. Component State Models
# =============================================================================

class InterfaceState(BaseModel):
    """Normalized operational state of a single network interface."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str = Field(..., description="Interface name (e.g. 'eth1')")
    admin_state: Literal["UP", "DOWN"] = Field(default="UP", description="Administrative state")
    oper_state: Literal["UP", "DOWN"] = Field(default="UP", description="Operational state")
    ipv4_addresses: List[str] = Field(default_factory=list, description="Assigned IPv4 CIDRs")
    mtu: int = Field(default=1500, description="Interface MTU")
    rx_bytes: int = Field(default=0, ge=0)
    tx_bytes: int = Field(default=0, ge=0)
    rx_dropped: int = Field(default=0, ge=0)
    tx_dropped: int = Field(default=0, ge=0)
    rx_errors: int = Field(default=0, ge=0)
    tx_errors: int = Field(default=0, ge=0)

    @field_validator("admin_state", "oper_state", mode="before")
    @classmethod
    def normalize_state(cls, v: Any) -> str:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            if v_upper in ("UP", "LOWER_UP", "RUNNING", "TRUE"):
                return "UP"
            elif v_upper in ("DOWN", "NO-CARRIER", "LOWER_DOWN", "OFF", "FALSE"):
                return "DOWN"
            return "DOWN" if "DOWN" in v_upper else "UP"
        return "UP" if v else "DOWN"

    @property
    def is_healthy(self) -> bool:
        """True if interface is UP and experiencing no packet drops or errors."""
        return (
            self.admin_state == "UP"
            and self.oper_state == "UP"
            and self.rx_dropped == 0
            and self.tx_dropped == 0
            and self.rx_errors == 0
            and self.tx_errors == 0
        )


class RouteState(BaseModel):
    """Normalized route entry in a node's routing table (FIB/RIB)."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    prefix: str = Field(..., description="Destination CIDR prefix or 'default'")
    next_hop: Optional[str] = Field(default=None, description="Next hop gateway IP")
    interface: Optional[str] = Field(default=None, description="Outgoing interface name")
    protocol: str = Field(default="static", description="Routing protocol: static, kernel, bgp, ospf")
    metric: Optional[int] = Field(default=None, description="Metric / administrative distance")
    active: bool = Field(default=True, description="True if route is active in FIB")

    @model_validator(mode="before")
    @classmethod
    def populate_prefix_from_destination(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "prefix" not in data and "destination" in data:
                data["prefix"] = data["destination"]
        return data

    @property
    def destination(self) -> str:
        return self.prefix


class QdiscState(BaseModel):
    """Traffic control queue discipline and buffer telemetry for an interface."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    interface: str = Field(..., description="Interface name")
    qdisc_type: str = Field(default="fq_codel", description="Qdisc algorithm: netem, tbf, fq_codel")
    loss_percent: float = Field(default=0.0, ge=0.0, le=100.0, description="Injected packet loss percentage")
    delay_ms: float = Field(default=0.0, ge=0.0, description="Injected queue latency in ms")
    dropped_packets: int = Field(default=0, ge=0, description="Buffer overflow / queue drop count")
    overlimits: int = Field(default=0, ge=0, description="Rate limit throttle occurrences")

    @model_validator(mode="before")
    @classmethod
    def populate_dropped(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "dropped_packets" not in data and "dropped" in data:
                data["dropped_packets"] = data["dropped"]
        return data

    @property
    def dropped(self) -> int:
        return self.dropped_packets


class ReachabilityState(BaseModel):
    """End-to-end probing telemetry between two endpoints."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    source: str = Field(..., description="Source node name")
    destination: str = Field(..., description="Destination node name or target IP")
    reachable: bool = Field(..., description="True if target received packets and has 0% loss")
    latency_ms: Optional[float] = Field(default=None, ge=0.0, description="Average RTT in ms")
    packet_loss_pct: float = Field(default=0.0, ge=0.0, le=100.0, description="Packet loss percentage")

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "source" not in data and "src_node" in data:
                data["source"] = data["src_node"]
            if "destination" not in data:
                if "dst_node" in data and data["dst_node"]:
                    data["destination"] = data["dst_node"]
                elif "dst_ip" in data:
                    data["destination"] = data["dst_ip"]
            if "reachable" not in data and "is_reachable" in data:
                data["reachable"] = data["is_reachable"]
            if "latency_ms" not in data and "rtt_avg_ms" in data:
                data["latency_ms"] = data["rtt_avg_ms"]
            if "packet_loss_pct" not in data and "loss_pct" in data:
                data["packet_loss_pct"] = data["loss_pct"]
        return data

    @property
    def is_reachable(self) -> bool:
        return self.reachable

    @property
    def loss_pct(self) -> float:
        return self.packet_loss_pct

    @property
    def rtt_avg_ms(self) -> Optional[float]:
        return self.latency_ms


class NodeState(BaseModel):
    """Comprehensive state snapshot of a network node."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    node_name: str = Field(..., description="Node name / hostname")
    role: str = Field(default="router", description="Node role: leaf, spine, superspine, host, egress, router")
    status: str = Field(default="healthy", description="Status: healthy, degraded, isolated, unreachable")
    interfaces: Dict[str, InterfaceState] = Field(default_factory=dict, description="Interfaces keyed by interface name")
    routes: List[RouteState] = Field(default_factory=list, description="Routing table entries")
    qdiscs: Dict[str, QdiscState] = Field(default_factory=dict, description="Qdiscs keyed by interface name")

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "node_name" not in data and "name" in data:
                data["node_name"] = data["name"]
            if "routes" in data and isinstance(data["routes"], dict):
                route_list = []
                for pfx, r_val in data["routes"].items():
                    if isinstance(r_val, dict):
                        if "prefix" not in r_val:
                            r_val["prefix"] = pfx
                        route_list.append(r_val)
                    else:
                        route_list.append(r_val)
                data["routes"] = route_list
        return data

    @property
    def name(self) -> str:
        return self.node_name

    def has_route_to(self, destination: str) -> bool:
        """Check if node has route entry covering the given prefix."""
        for r in self.routes:
            if r.prefix == destination or (r.prefix in ("default", "0.0.0.0/0") and r.active):
                return True
        return False


class NetworkState(BaseModel):
    """Immutable point-in-time snapshot of the entire network fabric."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    timestamp: float = Field(default_factory=time.time, description="Epoch timestamp of snapshot capture")
    lab_name: str = Field(default="clos5", description="Containerlab or environment name")
    nodes: Dict[str, NodeState] = Field(default_factory=dict, description="Nodes keyed by node name")
    reachability_matrix: List[ReachabilityState] = Field(default_factory=list, description="Probed reachability matrix")
    healthy: bool = Field(default=True, description="Overall network health flag")

    def is_healthy(self) -> bool:
        return self.healthy

    def diff(self, current: NetworkState) -> StateDiff:
        """Compute the deterministic state difference against current snapshot."""
        return compute_state_diff(baseline=self, current=current)


# =============================================================================
# 2. StateDiff Component & Aggregate Models
# =============================================================================

class InterfaceDiff(BaseModel):
    """Difference in interface state between two snapshots."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    node: Optional[str] = None
    added: List[InterfaceState] = Field(default_factory=list)
    removed: List[InterfaceState] = Field(default_factory=list)
    changed: Dict[str, Dict[str, Tuple[Any, Any]]] = Field(
        default_factory=dict,
        description="interface_name -> {attr_name: (old_value, new_value)}",
    )


class RouteDiff(BaseModel):
    """Difference in routing table between two snapshots."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    node: Optional[str] = None
    added: List[RouteState] = Field(default_factory=list)
    removed: List[RouteState] = Field(default_factory=list)
    changed: Dict[str, Dict[str, Tuple[Any, Any]]] = Field(
        default_factory=dict,
        description="prefix -> {attr_name: (old_value, new_value)}",
    )


class QdiscDiff(BaseModel):
    """Difference in queue buffer and traffic control between two snapshots."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    node: Optional[str] = None
    changed: Dict[str, Dict[str, Tuple[Any, Any]]] = Field(
        default_factory=dict,
        description="interface_name -> {metric_name: (old_value, new_value)}",
    )


class ReachabilityDiff(BaseModel):
    """Difference in end-to-end reachability and telemetry between two snapshots."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    newly_unreachable: List[Tuple[str, str]] = Field(default_factory=list)
    newly_reachable: List[Tuple[str, str]] = Field(default_factory=list)
    latency_changes: Dict[str, Tuple[float, float]] = Field(
        default_factory=dict,
        description="src->dst -> (old_lat_ms, new_lat_ms)",
    )
    loss_changes: Dict[str, Tuple[float, float]] = Field(
        default_factory=dict,
        description="src->dst -> (old_loss_pct, new_loss_pct)",
    )


class StateDiff(BaseModel):
    """Consolidated semantic difference between baseline and current NetworkState snapshots."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    interface_diffs: Dict[str, InterfaceDiff] = Field(
        default_factory=dict,
        description="node_name -> InterfaceDiff",
    )
    route_diffs: Dict[str, RouteDiff] = Field(
        default_factory=dict,
        description="node_name -> RouteDiff",
    )
    qdisc_diffs: Dict[str, QdiscDiff] = Field(
        default_factory=dict,
        description="node_name -> QdiscDiff",
    )
    reachability_diffs: ReachabilityDiff = Field(
        default_factory=ReachabilityDiff,
        description="Fabric reachability delta",
    )

    def has_anomalies(self) -> bool:
        """True if any anomaly (link down, route missing, packet loss, queue drop) is present."""
        if self.has_link_failure():
            return True
        if self.has_route_failure():
            return True
        if self.has_packet_loss():
            return True
        if self.reachability_diffs.newly_unreachable:
            return True
        for qd in self.qdisc_diffs.values():
            if qd.changed:
                return True
        for idiff in self.interface_diffs.values():
            if idiff.removed:
                return True
            for ch in idiff.changed.values():
                for metric in ("rx_dropped", "tx_dropped", "rx_errors", "tx_errors"):
                    if metric in ch:
                        old_v, new_v = ch[metric]
                        if new_v > old_v:
                            return True
        return False

    def has_link_failure(self) -> bool:
        """True if any interface went DOWN or was removed."""
        for idiff in self.interface_diffs.values():
            if idiff.removed:
                return True
            for _if_name, changes in idiff.changed.items():
                if "oper_state" in changes:
                    _was, now = changes["oper_state"]
                    if now in ("DOWN", "NO-CARRIER"):
                        return True
                if "admin_state" in changes:
                    _was, now = changes["admin_state"]
                    if now == "DOWN":
                        return True
        return False

    def has_route_failure(self) -> bool:
        """True if any route was removed/withdrawn or marked inactive."""
        for rdiff in self.route_diffs.values():
            if rdiff.removed:
                return True
            for _pfx, changes in rdiff.changed.items():
                if "active" in changes:
                    _was, now = changes["active"]
                    if not now:
                        return True
        return False

    def has_packet_loss(self) -> bool:
        """True if reachability probes or queue buffers report packet drops or loss increases."""
        if self.reachability_diffs.newly_unreachable:
            return True
        for _pair, (prev_loss, curr_loss) in self.reachability_diffs.loss_changes.items():
            if curr_loss > prev_loss or curr_loss > 0.0:
                return True
        for qdiff in self.qdisc_diffs.values():
            for _ifc, changes in qdiff.changed.items():
                for metric in ("dropped_packets", "overlimits", "loss_percent"):
                    if metric in changes:
                        prev_val, curr_val = changes[metric]
                        if curr_val > prev_val:
                            return True
        for idiff in self.interface_diffs.values():
            for _ifc, changes in idiff.changed.items():
                for drop_metric in ("rx_dropped", "tx_dropped"):
                    if drop_metric in changes:
                        prev_val, curr_val = changes[drop_metric]
                        if curr_val > prev_val:
                            return True
        return False

    def affected_nodes(self) -> List[str]:
        """Return sorted unique list of node names affected by any state delta."""
        nodes = set()
        for node, idiff in self.interface_diffs.items():
            if idiff.added or idiff.removed or idiff.changed:
                nodes.add(node)
        for node, rdiff in self.route_diffs.items():
            if rdiff.added or rdiff.removed or rdiff.changed:
                nodes.add(node)
        for node, qdiff in self.qdisc_diffs.items():
            if qdiff.changed:
                nodes.add(node)
        for src, dst in self.reachability_diffs.newly_unreachable:
            nodes.add(src)
            nodes.add(dst)
        for src, dst in self.reachability_diffs.newly_reachable:
            nodes.add(src)
            nodes.add(dst)
        for pair_str in self.reachability_diffs.loss_changes.keys():
            for p in pair_str.split("->"):
                clean = p.strip()
                if clean:
                    nodes.add(clean)
        for pair_str in self.reachability_diffs.latency_changes.keys():
            for p in pair_str.split("->"):
                clean = p.strip()
                if clean:
                    nodes.add(clean)
        return sorted(n for n in nodes if n)

    def to_llm_markdown(self) -> str:
        """Serializes concise (<500B / <200 tokens) markdown summary for LLM context,
        highlighting broken interfaces, missing routes, and reachability drops."""
        if not self.has_anomalies():
            return "### State Diff\n- Status: OK (No anomalies)"

        lines = ["### State Diff"]

        # 1. Broken interfaces
        broken_ifaces = []
        for node, idiff in self.interface_diffs.items():
            for if_name, changes in idiff.changed.items():
                if "oper_state" in changes:
                    was, now = changes["oper_state"]
                    if now in ("DOWN", "NO-CARRIER"):
                        broken_ifaces.append(f"{node}:{if_name} ({was}->{now})")
            for ifc in idiff.removed:
                broken_ifaces.append(f"{node}:{ifc.name} (REMOVED)")
        if broken_ifaces:
            lines.append(f"- Links Down: {', '.join(broken_ifaces)}")

        # 2. Missing routes
        missing_routes = []
        for node, rdiff in self.route_diffs.items():
            for r in rdiff.removed:
                missing_routes.append(f"{node} missing {r.prefix}")
            for pfx, changes in rdiff.changed.items():
                if "active" in changes and not changes["active"][1]:
                    missing_routes.append(f"{node} inactive {pfx}")
        if missing_routes:
            lines.append(f"- Missing Routes: {', '.join(missing_routes)}")

        # 3. Reachability drops
        if self.reachability_diffs.newly_unreachable:
            drops = [f"{s}->{d}" for s, d in self.reachability_diffs.newly_unreachable]
            lines.append(f"- Unreachable: {', '.join(drops)}")

        # 4. Packet loss
        loss_items = []
        for pair, (prev, curr) in self.reachability_diffs.loss_changes.items():
            if curr > prev:
                loss_items.append(f"{pair} ({prev:.0f}%->{curr:.0f}%)")
        if loss_items:
            lines.append(f"- Packet Loss: {', '.join(loss_items)}")

        # 5. Queue Drops
        qdisc_issues = []
        for node, qdiff in self.qdisc_diffs.items():
            for ifc, changes in qdiff.changed.items():
                if "dropped_packets" in changes and changes["dropped_packets"][1] > changes["dropped_packets"][0]:
                    d = changes["dropped_packets"][1] - changes["dropped_packets"][0]
                    qdisc_issues.append(f"{node}:{ifc} (+{d} drops)")
                elif "overlimits" in changes and changes["overlimits"][1] > changes["overlimits"][0]:
                    o = changes["overlimits"][1] - changes["overlimits"][0]
                    qdisc_issues.append(f"{node}:{ifc} (+{o} overlimits)")
        if qdisc_issues:
            lines.append(f"- Queue Drops: {', '.join(qdisc_issues)}")

        result = "\n".join(lines)
        encoded = result.encode("utf-8")
        if len(encoded) > 480:
            result = result[:450] + "\n... [truncated]"
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return self.model_dump()


# =============================================================================
# 3. Deterministic StateDiff Computation Engine
# =============================================================================

def compute_state_diff(baseline: NetworkState, current: NetworkState) -> StateDiff:
    """Computes deterministic diff between baseline and current snapshots."""
    interface_diffs: Dict[str, InterfaceDiff] = {}
    route_diffs: Dict[str, RouteDiff] = {}
    qdisc_diffs: Dict[str, QdiscDiff] = {}

    all_node_names = set(baseline.nodes.keys()) | set(current.nodes.keys())

    for node_name in all_node_names:
        b_node = baseline.nodes.get(node_name)
        c_node = current.nodes.get(node_name)

        # 1. Compare Interfaces
        b_ifaces = b_node.interfaces if b_node else {}
        c_ifaces = c_node.interfaces if c_node else {}
        all_iface_names = set(b_ifaces.keys()) | set(c_ifaces.keys())

        added_ifaces: List[InterfaceState] = []
        removed_ifaces: List[InterfaceState] = []
        changed_ifaces: Dict[str, Dict[str, Tuple[Any, Any]]] = {}

        for if_name in all_iface_names:
            b_if = b_ifaces.get(if_name)
            c_if = c_ifaces.get(if_name)
            if not b_if and c_if:
                added_ifaces.append(c_if)
            elif b_if and not c_if:
                removed_ifaces.append(b_if)
            elif b_if and c_if:
                ch: Dict[str, Tuple[Any, Any]] = {}
                if b_if.admin_state != c_if.admin_state:
                    ch["admin_state"] = (b_if.admin_state, c_if.admin_state)
                if b_if.oper_state != c_if.oper_state:
                    ch["oper_state"] = (b_if.oper_state, c_if.oper_state)
                if b_if.ipv4_addresses != c_if.ipv4_addresses:
                    ch["ipv4_addresses"] = (b_if.ipv4_addresses, c_if.ipv4_addresses)
                if b_if.mtu != c_if.mtu:
                    ch["mtu"] = (b_if.mtu, c_if.mtu)
                if b_if.rx_dropped != c_if.rx_dropped:
                    ch["rx_dropped"] = (b_if.rx_dropped, c_if.rx_dropped)
                if b_if.tx_dropped != c_if.tx_dropped:
                    ch["tx_dropped"] = (b_if.tx_dropped, c_if.tx_dropped)
                if b_if.rx_errors != c_if.rx_errors:
                    ch["rx_errors"] = (b_if.rx_errors, c_if.rx_errors)
                if b_if.tx_errors != c_if.tx_errors:
                    ch["tx_errors"] = (b_if.tx_errors, c_if.tx_errors)
                if ch:
                    changed_ifaces[if_name] = ch

        if added_ifaces or removed_ifaces or changed_ifaces:
            interface_diffs[node_name] = InterfaceDiff(
                node=node_name,
                added=added_ifaces,
                removed=removed_ifaces,
                changed=changed_ifaces,
            )

        # 2. Compare Routes
        b_routes_list = b_node.routes if b_node else []
        c_routes_list = c_node.routes if c_node else []
        b_routes_map = {r.prefix: r for r in b_routes_list}
        c_routes_map = {r.prefix: r for r in c_routes_list}
        all_prefixes = set(b_routes_map.keys()) | set(c_routes_map.keys())

        added_routes: List[RouteState] = []
        removed_routes: List[RouteState] = []
        changed_routes: Dict[str, Dict[str, Tuple[Any, Any]]] = {}

        for pfx in all_prefixes:
            b_rt = b_routes_map.get(pfx)
            c_rt = c_routes_map.get(pfx)
            if not b_rt and c_rt:
                added_routes.append(c_rt)
            elif b_rt and not c_rt:
                removed_routes.append(b_rt)
            elif b_rt and c_rt:
                r_ch: Dict[str, Tuple[Any, Any]] = {}
                if b_rt.next_hop != c_rt.next_hop:
                    r_ch["next_hop"] = (b_rt.next_hop, c_rt.next_hop)
                if b_rt.interface != c_rt.interface:
                    r_ch["interface"] = (b_rt.interface, c_rt.interface)
                if b_rt.protocol != c_rt.protocol:
                    r_ch["protocol"] = (b_rt.protocol, c_rt.protocol)
                if b_rt.metric != c_rt.metric:
                    r_ch["metric"] = (b_rt.metric, c_rt.metric)
                if b_rt.active != c_rt.active:
                    r_ch["active"] = (b_rt.active, c_rt.active)
                if r_ch:
                    changed_routes[pfx] = r_ch

        if added_routes or removed_routes or changed_routes:
            route_diffs[node_name] = RouteDiff(
                node=node_name,
                added=added_routes,
                removed=removed_routes,
                changed=changed_routes,
            )

        # 3. Compare Qdiscs
        b_qdiscs = b_node.qdiscs if b_node else {}
        c_qdiscs = c_node.qdiscs if c_node else {}
        all_qdisc_ifaces = set(b_qdiscs.keys()) | set(c_qdiscs.keys())

        changed_qdiscs: Dict[str, Dict[str, Tuple[Any, Any]]] = {}
        for q_if in all_qdisc_ifaces:
            b_qd = b_qdiscs.get(q_if)
            c_qd = c_qdiscs.get(q_if)
            q_ch: Dict[str, Tuple[Any, Any]] = {}
            if b_qd and c_qd:
                if b_qd.loss_percent != c_qd.loss_percent:
                    q_ch["loss_percent"] = (b_qd.loss_percent, c_qd.loss_percent)
                if b_qd.delay_ms != c_qd.delay_ms:
                    q_ch["delay_ms"] = (b_qd.delay_ms, c_qd.delay_ms)
                if b_qd.dropped_packets != c_qd.dropped_packets:
                    q_ch["dropped_packets"] = (b_qd.dropped_packets, c_qd.dropped_packets)
                if b_qd.overlimits != c_qd.overlimits:
                    q_ch["overlimits"] = (b_qd.overlimits, c_qd.overlimits)
            elif not b_qd and c_qd:
                if c_qd.dropped_packets > 0:
                    q_ch["dropped_packets"] = (0, c_qd.dropped_packets)
                if c_qd.overlimits > 0:
                    q_ch["overlimits"] = (0, c_qd.overlimits)
                if c_qd.loss_percent > 0:
                    q_ch["loss_percent"] = (0.0, c_qd.loss_percent)
                if c_qd.delay_ms > 0:
                    q_ch["delay_ms"] = (0.0, c_qd.delay_ms)
            if q_ch:
                changed_qdiscs[q_if] = q_ch

        if changed_qdiscs:
            qdisc_diffs[node_name] = QdiscDiff(
                node=node_name,
                changed=changed_qdiscs,
            )

    # 4. Compare Reachability Matrix
    b_reach = {(r.source, r.destination): r for r in baseline.reachability_matrix}
    c_reach = {(r.source, r.destination): r for r in current.reachability_matrix}

    newly_unreachable: List[Tuple[str, str]] = []
    newly_reachable: List[Tuple[str, str]] = []
    latency_changes: Dict[str, Tuple[float, float]] = {}
    loss_changes: Dict[str, Tuple[float, float]] = {}

    all_pairs = set(b_reach.keys()) | set(c_reach.keys())
    for pair in sorted(all_pairs):
        b_r = b_reach.get(pair)
        c_r = c_reach.get(pair)
        pair_str = f"{pair[0]}->{pair[1]}"

        if b_r and c_r:
            if b_r.reachable and not c_r.reachable:
                newly_unreachable.append(pair)
            elif not b_r.reachable and c_r.reachable:
                newly_reachable.append(pair)

            if b_r.packet_loss_pct != c_r.packet_loss_pct:
                loss_changes[pair_str] = (b_r.packet_loss_pct, c_r.packet_loss_pct)

            b_lat = b_r.latency_ms
            c_lat = c_r.latency_ms
            if b_lat is not None and c_lat is not None:
                if abs(b_lat - c_lat) > 0.05:
                    latency_changes[pair_str] = (b_lat, c_lat)
            elif b_lat != c_lat:
                latency_changes[pair_str] = (
                    b_lat if b_lat is not None else 0.0,
                    c_lat if c_lat is not None else 0.0,
                )
        elif not b_r and c_r:
            if not c_r.reachable:
                newly_unreachable.append(pair)
            elif c_r.packet_loss_pct > 0:
                loss_changes[pair_str] = (0.0, c_r.packet_loss_pct)
        elif b_r and not c_r:
            if b_r.reachable:
                newly_unreachable.append(pair)

    reachability_diff = ReachabilityDiff(
        newly_unreachable=newly_unreachable,
        newly_reachable=newly_reachable,
        latency_changes=latency_changes,
        loss_changes=loss_changes,
    )

    return StateDiff(
        interface_diffs=interface_diffs,
        route_diffs=route_diffs,
        qdisc_diffs=qdisc_diffs,
        reachability_diffs=reachability_diff,
    )
