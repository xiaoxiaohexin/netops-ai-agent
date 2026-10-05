"""NetworkState Snapshotter for Live and Mock Containerlab Environments (R2).

Queries network devices (Linux, FRRouting, and containerized endpoints) via
BaseNetworkLabAdapter, supporting JSON-first inspection with robust CLI text fallback,
and populates the structured NetworkState model with reachability matrix telemetry.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from langgraph_netagent.models.network_state import (
    InterfaceState,
    NetworkState,
    NodeState,
    QdiscState,
    ReachabilityState,
    RouteState,
)
from langgraph_netagent.tools.base import BaseNetworkLabAdapter

logger = logging.getLogger(__name__)


class NetworkStateSnapshotter:
    """Takes structured NetworkState snapshots of running or mock Containerlab topologies."""

    DEFAULT_KNOWN_IPS: Dict[str, str] = {
        "h1": "172.16.1.2",
        "h2": "172.16.2.2",
        "h3": "172.16.3.2",
        "h4": "172.16.4.2",
        "dc-egress": "172.16.254.1",
        "ext-router": "192.168.100.1",
    }

    KEY_NODES: List[str] = ["h1", "h2", "h3", "h4", "dc-egress", "ext-router"]

    def __init__(
        self,
        lab_adapter: BaseNetworkLabAdapter,
        topology: Optional[Any] = None,
        lab_name: str = "clos5",
    ):
        self.lab_adapter = lab_adapter
        self.topology = topology
        self.lab_name = lab_name

    @classmethod
    def snapshot(
        cls,
        adapter: BaseNetworkLabAdapter,
        target_nodes: Optional[List[str]] = None,
        topology: Optional[Any] = None,
        lab_name: str = "clos5",
    ) -> NetworkState:
        """Convenience classmethod to capture a snapshot in a single call."""
        snapshotter = cls(lab_adapter=adapter, topology=topology, lab_name=lab_name)
        return snapshotter.capture_snapshot(target_nodes=target_nodes)

    def capture_snapshot(
        self,
        target_nodes: Optional[List[str]] = None,
    ) -> NetworkState:
        """Capture complete NetworkState snapshot across target or discovered nodes."""
        nodes_to_query = self._discover_nodes(target_nodes=target_nodes)
        nodes_dict: Dict[str, NodeState] = {}
        node_ip_map: Dict[str, str] = {}

        # 1. Query each node for interfaces, stats, routes, and qdiscs
        for node_name in nodes_to_query:
            role = self._determine_node_role(node_name)

            # Interfaces & hardware/kernel stats
            ifaces = self._collect_interfaces(node_name)
            stats = self._collect_interface_stats(node_name)

            # Merge stats into interfaces
            for if_name, ifc in ifaces.items():
                if if_name in stats:
                    st = stats[if_name]
                    ifc.rx_bytes = st.get("rx_bytes", 0)
                    ifc.tx_bytes = st.get("tx_bytes", 0)
                    ifc.rx_dropped = st.get("rx_dropped", 0)
                    ifc.tx_dropped = st.get("tx_dropped", 0)
                    ifc.rx_errors = st.get("rx_errors", 0)
                    ifc.tx_errors = st.get("tx_errors", 0)

            # Cache discovered IP for reachability matrix
            primary_ip = self._extract_primary_ip(node_name, ifaces)
            if primary_ip:
                node_ip_map[node_name] = primary_ip

            # Routes
            routes = self._collect_routes(node_name)

            # Qdiscs
            qdiscs = self._collect_qdiscs(node_name)

            # Node health status
            node_status = "healthy"
            for ifc in ifaces.values():
                if ifc.name != "lo" and not ifc.is_healthy:
                    node_status = "degraded"
                    break

            nodes_dict[node_name] = NodeState(
                node_name=node_name,
                role=role,
                status=node_status,
                interfaces=ifaces,
                routes=routes,
                qdiscs=qdiscs,
            )

        # 2. Probe Reachability Matrix
        reachability_matrix = self._probe_reachability_matrix(
            nodes_to_query=nodes_to_query,
            node_ip_map=node_ip_map,
        )

        # 3. Assess overall network health
        all_reachable = all(r.reachable for r in reachability_matrix) if reachability_matrix else True
        all_ifaces_healthy = all(
            ifc.is_healthy
            for n in nodes_dict.values()
            for ifc in n.interfaces.values()
            if ifc.name != "lo"
        )
        no_qdisc_drops = not any(
            qd.dropped_packets > 0 or qd.overlimits > 0 or qd.loss_percent > 0
            for n in nodes_dict.values()
            for qd in n.qdiscs.values()
        )
        overall_healthy = all_reachable and all_ifaces_healthy and no_qdisc_drops

        return NetworkState(
            timestamp=time.time(),
            lab_name=self.lab_name,
            nodes=nodes_dict,
            reachability_matrix=reachability_matrix,
            healthy=overall_healthy,
        )

    # =========================================================================
    # Internal Node Discovery & Role Helpers
    # =========================================================================

    def _discover_nodes(self, target_nodes: Optional[List[str]] = None) -> List[str]:
        """Resolve list of nodes to inspect."""
        if target_nodes:
            return target_nodes

        # 1. From MockContainerlabAdapter
        if hasattr(self.lab_adapter, "mock_engine") and hasattr(self.lab_adapter.mock_engine, "graph"):
            graph_nodes = list(self.lab_adapter.mock_engine.graph.nodes.keys())
            if graph_nodes:
                return graph_nodes

        # 2. From Adapter inspect()
        try:
            insp = self.lab_adapter.inspect()
            if insp and insp.nodes:
                return [n.name for n in insp.nodes]
        except Exception as e:
            logger.debug("inspect() failed during node discovery: %s", e)

        # 3. From DiscoveredTopology
        if self.topology and hasattr(self.topology, "nodes"):
            return list(self.topology.nodes.keys())

        # 4. Fallback to standard clos5 nodes
        candidate_nodes = [
            "h1", "h2", "h3", "h4",
            "dc-egress", "ext-router",
            "leaf1", "leaf2", "leaf3", "leaf4",
            "spine1", "spine2", "spine3", "spine4",
            "superspine1", "superspine2",
        ]
        active_nodes = []
        for n in candidate_nodes:
            res = self.lab_adapter.exec_command(node_name=n, command="true", timeout=2)
            if res.exit_code == 0:
                active_nodes.append(n)

        return active_nodes if active_nodes else candidate_nodes

    def _determine_node_role(self, node_name: str) -> str:
        """Infer node role from name or topology."""
        if self.topology and hasattr(self.topology, "nodes") and node_name in self.topology.nodes:
            return getattr(self.topology.nodes[node_name], "role", "router")

        lower = node_name.lower()
        if lower.startswith("leaf"):
            return "leaf"
        if lower.startswith("spine"):
            return "spine"
        if lower.startswith("superspine"):
            return "superspine"
        if "egress" in lower or "dc-egress" in lower:
            return "egress"
        if "ext" in lower or "router" in lower:
            return "router"
        if lower.startswith("h") or lower.startswith("pc") or lower.startswith("host"):
            return "host"
        if "attacker" in lower:
            return "attacker"
        return "router"

    def _extract_primary_ip(self, node_name: str, ifaces: Dict[str, InterfaceState]) -> Optional[str]:
        """Extract first non-loopback IP or known fallback IP."""
        for if_name, ifc in ifaces.items():
            if if_name != "lo" and ifc.ipv4_addresses:
                return ifc.ipv4_addresses[0].split("/")[0]
        return self.DEFAULT_KNOWN_IPS.get(node_name)

    # =========================================================================
    # Interface & Link Statistics Collection
    # =========================================================================

    def _collect_interfaces(self, node_name: str) -> Dict[str, InterfaceState]:
        """Collect interface states using ip -j addr show with fallback to text."""
        # 1. Attempt JSON
        res_json = self.lab_adapter.exec_command(node_name=node_name, command="ip -j addr show", timeout=5)
        if res_json.exit_code == 0 and res_json.stdout.strip().startswith(("[", "{")):
            try:
                return self._parse_ip_addr_json(res_json.stdout)
            except Exception as e:
                logger.debug("Failed parsing JSON ip addr on %s: %s", node_name, e)

        # 2. Fallback to CLI text output
        res_text = self.lab_adapter.exec_command(node_name=node_name, command="ip addr show", timeout=5)
        raw = res_text.stdout if res_text.stdout else res_json.stdout
        return self._parse_ip_addr_text(raw)

    def _parse_ip_addr_json(self, raw_json: str) -> Dict[str, InterfaceState]:
        """Parse Linux 'ip -j addr show' JSON output."""
        data = json.loads(raw_json)
        if isinstance(data, dict):
            data = [data]

        ifaces: Dict[str, InterfaceState] = {}
        for item in data:
            ifname = str(item.get("ifname", "")).split("@")[0]
            if not ifname:
                continue

            flags = item.get("flags", [])
            admin = "UP" if "UP" in flags else "DOWN"
            oper_raw = str(item.get("operstate", "UP")).upper()
            oper = "UP" if oper_raw in ("UP", "LOWER_UP") else ("DOWN" if oper_raw in ("DOWN", "NO-CARRIER") else oper_raw)
            mtu = int(item.get("mtu", 1500))

            ipv4s = []
            for addr in item.get("addr_info", []):
                if addr.get("family") == "inet" and "local" in addr:
                    pfxlen = addr.get("prefixlen", 32)
                    ipv4s.append(f"{addr['local']}/{pfxlen}")

            ifaces[ifname] = InterfaceState(
                name=ifname,
                admin_state=admin,
                oper_state=oper,
                ipv4_addresses=ipv4s,
                mtu=mtu,
            )

        return ifaces

    def _parse_ip_addr_text(self, raw_text: str) -> Dict[str, InterfaceState]:
        """Parse Linux 'ip addr show' standard CLI text output."""
        ifaces: Dict[str, InterfaceState] = {}
        current_iface: Optional[dict] = None

        for line in raw_text.splitlines():
            # Match interface header: 2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ... state UP
            m_header = re.search(
                r"^\d+:\s+([a-zA-Z0-9_\-\.@]+):\s+<([^>]+)>\s+mtu\s+(\d+).*?state\s+([a-zA-Z0-9_\-]+)",
                line,
            )
            if m_header:
                if current_iface:
                    ifaces[current_iface["name"]] = InterfaceState(**current_iface)

                if_name = m_header.group(1).split("@")[0]
                flags = m_header.group(2)
                mtu = int(m_header.group(3))
                state = m_header.group(4).upper()

                admin = "UP" if "UP" in flags else "DOWN"
                oper = "UP" if state in ("UP", "LOWER_UP") or ("UP" in flags and state != "DOWN") else "DOWN"

                current_iface = {
                    "name": if_name,
                    "admin_state": admin,
                    "oper_state": oper,
                    "mtu": mtu,
                    "ipv4_addresses": [],
                }
                continue

            # Fallback header match without explicit state: 2: eth1: <BROADCAST,MULTICAST> mtu 1500
            m_alt = re.search(r"^\d+:\s+([a-zA-Z0-9_\-\.@]+):\s+<([^>]+)>\s+mtu\s+(\d+)", line)
            if m_alt and not m_header:
                if current_iface:
                    ifaces[current_iface["name"]] = InterfaceState(**current_iface)
                if_name = m_alt.group(1).split("@")[0]
                flags = m_alt.group(2)
                mtu = int(m_alt.group(3))
                admin = "UP" if "UP" in flags else "DOWN"
                oper = "UP" if "LOWER_UP" in flags or "UP" in flags else "DOWN"
                current_iface = {
                    "name": if_name,
                    "admin_state": admin,
                    "oper_state": oper,
                    "mtu": mtu,
                    "ipv4_addresses": [],
                }
                continue

            if not current_iface:
                continue

            # Match IPv4 addresses: inet 172.16.1.1/24 scope global eth1
            m_inet = re.search(r"\binet\s+([0-9\./]+)", line)
            if m_inet:
                current_iface["ipv4_addresses"].append(m_inet.group(1))

        if current_iface:
            ifaces[current_iface["name"]] = InterfaceState(**current_iface)

        return ifaces

    def _collect_interface_stats(self, node_name: str) -> Dict[str, Dict[str, int]]:
        """Collect packet/byte statistics using ip -s link show."""
        res = self.lab_adapter.exec_command(node_name=node_name, command="ip -s link show", timeout=5)
        raw = res.stdout if res.stdout else ""
        stats_map: Dict[str, Dict[str, int]] = {}

        blocks = re.split(r"(?m)^(?=\d+:\s+)", raw.strip())
        for block in blocks:
            clean = block.strip()
            if not clean:
                continue

            lines = clean.splitlines()
            m_iface = re.search(r"^\d+:\s+([a-zA-Z0-9_\-\.@]+):", lines[0])
            if not m_iface:
                continue
            iface_name = m_iface.group(1).split("@")[0]

            stat = {
                "rx_bytes": 0, "rx_packets": 0, "rx_errors": 0, "rx_dropped": 0,
                "tx_bytes": 0, "tx_packets": 0, "tx_errors": 0, "tx_dropped": 0,
            }

            for i, line in enumerate(lines):
                line_upper = line.strip().upper()
                if line_upper.startswith("RX:") and i + 1 < len(lines):
                    nums = [int(n) for n in re.findall(r"\d+", lines[i + 1])]
                    if len(nums) >= 4:
                        stat["rx_bytes"] = nums[0]
                        stat["rx_packets"] = nums[1]
                        stat["rx_errors"] = nums[2]
                        stat["rx_dropped"] = nums[3]
                elif line_upper.startswith("TX:") and i + 1 < len(lines):
                    nums = [int(n) for n in re.findall(r"\d+", lines[i + 1])]
                    if len(nums) >= 4:
                        stat["tx_bytes"] = nums[0]
                        stat["tx_packets"] = nums[1]
                        stat["tx_errors"] = nums[2]
                        stat["tx_dropped"] = nums[3]

            stats_map[iface_name] = stat

        return stats_map

    # =========================================================================
    # Routing Table Collection
    # =========================================================================

    def _collect_routes(self, node_name: str) -> List[RouteState]:
        """Collect routes using vtysh JSON / ip route JSON with fallback to text."""
        # 1. Try FRRouting vtysh JSON
        res_vtysh_json = self.lab_adapter.exec_command(
            node_name=node_name,
            command="vtysh -c 'show ip route json'",
            timeout=5,
        )
        if res_vtysh_json.exit_code == 0 and res_vtysh_json.stdout.strip().startswith("{"):
            try:
                return self._parse_frr_routes_json(res_vtysh_json.stdout)
            except Exception as e:
                logger.debug("Failed parsing FRR JSON route table on %s: %s", node_name, e)

        # 2. Try Linux ip -j route show
        res_ip_json = self.lab_adapter.exec_command(node_name=node_name, command="ip -j route show", timeout=5)
        if res_ip_json.exit_code == 0 and res_ip_json.stdout.strip().startswith(("[", "{")):
            try:
                return self._parse_ip_route_json(res_ip_json.stdout)
            except Exception as e:
                logger.debug("Failed parsing Linux JSON route table on %s: %s", node_name, e)

        # 3. Fallback to CLI text (vtysh or ip route)
        res_vtysh_text = self.lab_adapter.exec_command(
            node_name=node_name,
            command="vtysh -c 'show ip route'",
            timeout=5,
        )
        if res_vtysh_text.exit_code == 0 and "via" in res_vtysh_text.stdout:
            return self._parse_frr_routes_text(res_vtysh_text.stdout)

        res_ip_text = self.lab_adapter.exec_command(node_name=node_name, command="ip route show", timeout=5)
        raw = res_ip_text.stdout if res_ip_text.stdout else res_ip_json.stdout
        return self._parse_linux_routes_text(raw)

    def _parse_frr_routes_json(self, raw_json: str) -> List[RouteState]:
        """Parse FRR 'show ip route json' output."""
        data = json.loads(raw_json)
        routes: List[RouteState] = []
        for prefix, entries in data.items():
            if isinstance(entries, list):
                for entry in entries:
                    proto = entry.get("protocol", "static")
                    nexthops = entry.get("nexthops", [])
                    if nexthops:
                        for nh in nexthops:
                            routes.append(
                                RouteState(
                                    prefix=prefix,
                                    next_hop=nh.get("ip"),
                                    interface=nh.get("interfaceName"),
                                    protocol=proto,
                                    active=nh.get("active", True),
                                )
                            )
                    else:
                        routes.append(
                            RouteState(
                                prefix=prefix,
                                next_hop=None,
                                interface=None,
                                protocol=proto,
                                active=True,
                            )
                        )
        return routes

    def _parse_ip_route_json(self, raw_json: str) -> List[RouteState]:
        """Parse Linux 'ip -j route show' output."""
        data = json.loads(raw_json)
        if isinstance(data, dict):
            data = [data]

        routes: List[RouteState] = []
        for item in data:
            prefix = item.get("dst") or "default"
            gw = item.get("gateway")
            dev = item.get("dev")
            proto = item.get("protocol", "static")
            metric = item.get("metric")

            routes.append(
                RouteState(
                    prefix=prefix,
                    next_hop=gw,
                    interface=dev,
                    protocol=proto,
                    metric=metric,
                    active=True,
                )
            )
        return routes

    def _parse_frr_routes_text(self, raw_text: str) -> List[RouteState]:
        """Parse FRR 'show ip route' CLI text output."""
        routes: List[RouteState] = []
        for line in raw_text.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("Codes:"):
                continue

            # S>* 172.16.2.0/24 [1/0] via 172.16.254.2, eth1
            m_via = re.search(
                r"^([A-Z\*\> ]+)\s+([0-9\./]+|default)(?:\s+\[\d+/\d+\])?\s+via\s+([0-9\.]+)(?:,\s*([a-zA-Z0-9_\-\.]+))?",
                clean,
            )
            if m_via:
                code = m_via.group(1).strip()
                pfx = m_via.group(2)
                gw = m_via.group(3)
                dev = m_via.group(4)
                proto = "bgp" if "B" in code else ("ospf" if "O" in code else "static")
                routes.append(RouteState(prefix=pfx, next_hop=gw, interface=dev, protocol=proto, active=True))
                continue

            # C>* 172.16.1.0/24 is directly connected, eth1
            m_conn = re.search(
                r"^([A-Z\*\> ]+)\s+([0-9\./]+|default)\s+is directly connected(?:,\s*([a-zA-Z0-9_\-\.]+))?",
                clean,
            )
            if m_conn:
                pfx = m_conn.group(2)
                dev = m_conn.group(3)
                routes.append(RouteState(prefix=pfx, next_hop=None, interface=dev, protocol="connected", active=True))

        return routes

    def _parse_linux_routes_text(self, raw_text: str) -> List[RouteState]:
        """Parse Linux 'ip route show' standard CLI text output."""
        routes: List[RouteState] = []
        for line in raw_text.splitlines():
            clean = line.strip()
            if not clean:
                continue

            # default via 172.16.254.1 dev eth1 ...
            m_def = re.search(r"^default\s+via\s+([0-9\.]+)(?:\s+dev\s+(\S+))?", clean)
            if m_def:
                routes.append(
                    RouteState(
                        prefix="default",
                        next_hop=m_def.group(1),
                        interface=m_def.group(2),
                        protocol="static",
                        active=True,
                    )
                )
                continue

            # 172.16.1.0/24 dev eth1 proto kernel scope link src 172.16.1.1
            # 172.16.2.0/24 via 172.16.254.2 dev eth2 proto static
            m_sub = re.search(
                r"^([0-9\./]+)(?:\s+via\s+([0-9\.]+))?(?:\s+dev\s+(\S+))?(?:\s+proto\s+(\S+))?",
                clean,
            )
            if m_sub:
                pfx = m_sub.group(1)
                gw = m_sub.group(2)
                dev = m_sub.group(3)
                proto = m_sub.group(4) or ("static" if gw else "kernel")
                routes.append(
                    RouteState(
                        prefix=pfx,
                        next_hop=gw,
                        interface=dev,
                        protocol=proto,
                        active=True,
                    )
                )

        return routes

    # =========================================================================
    # Qdisc & Traffic Control Collection
    # =========================================================================

    def _collect_qdiscs(self, node_name: str) -> Dict[str, QdiscState]:
        """Collect traffic control qdisc queue metrics using tc -s qdisc show."""
        res = self.lab_adapter.exec_command(node_name=node_name, command="tc -s qdisc show", timeout=5)
        raw = res.stdout if res.stdout else ""
        qdiscs: Dict[str, QdiscState] = {}

        blocks = re.split(r"(?m)^(?=qdisc\s+)", raw.strip())
        for block in blocks:
            clean = block.strip()
            if not clean or not clean.startswith("qdisc"):
                continue

            lines = clean.splitlines()
            first_line = lines[0]

            m_type = re.match(r"^qdisc\s+([a-zA-Z0-9_\-]+)", first_line)
            if not m_type:
                continue
            q_type = m_type.group(1)

            m_dev = re.search(r"\bdev\s+([a-zA-Z0-9_\-\.]+)", first_line)
            iface = m_dev.group(1) if m_dev else "eth1"

            # Parse loss and delay if netem
            loss_pct = 0.0
            delay_ms = 0.0
            m_loss = re.search(r"\bloss\s+([0-9\.]+)%", clean)
            if m_loss:
                loss_pct = float(m_loss.group(1))

            m_delay = re.search(r"\bdelay\s+([0-9\.]+)ms", clean)
            if m_delay:
                delay_ms = float(m_delay.group(1))

            # Parse dropped & overlimits
            m_drop = re.search(r"dropped\s+(\d+)", clean, re.IGNORECASE)
            dropped = int(m_drop.group(1)) if m_drop else 0

            m_over = re.search(r"overlimits\s+(\d+)", clean, re.IGNORECASE)
            overlimits = int(m_over.group(1)) if m_over else 0

            # If multiple qdiscs on same iface, accumulate drops or pick active
            if iface in qdiscs:
                existing = qdiscs[iface]
                dropped = max(existing.dropped_packets, dropped)
                overlimits = max(existing.overlimits, overlimits)
                loss_pct = max(existing.loss_percent, loss_pct)
                delay_ms = max(existing.delay_ms, delay_ms)

            qdiscs[iface] = QdiscState(
                interface=iface,
                qdisc_type=q_type,
                loss_percent=loss_pct,
                delay_ms=delay_ms,
                dropped_packets=dropped,
                overlimits=overlimits,
            )

        return qdiscs

    # =========================================================================
    # Reachability Probing
    # =========================================================================

    def _probe_reachability_matrix(
        self,
        nodes_to_query: List[str],
        node_ip_map: Dict[str, str],
    ) -> List[ReachabilityState]:
        """Runs reachability matrix probes across key nodes via adapter ping."""
        reachability_matrix: List[ReachabilityState] = []

        # Determine source endpoints and destinations
        hosts = [
            n for n in nodes_to_query
            if any(n.lower().startswith(p) for p in ("h", "pc", "host", "attacker"))
        ]
        if not hosts:
            hosts = [n for n in nodes_to_query if n in self.KEY_NODES]
        if not hosts and nodes_to_query:
            hosts = nodes_to_query[:4]

        destinations = [
            n for n in nodes_to_query
            if n in self.KEY_NODES or n in hosts or "egress" in n.lower()
        ]

        # Execute ping probes
        for src in hosts:
            for dst in destinations:
                if src == dst:
                    continue

                dst_ip = node_ip_map.get(dst) or self.DEFAULT_KNOWN_IPS.get(dst)
                if not dst_ip:
                    continue

                res = self.lab_adapter.exec_command(
                    node_name=src,
                    command=f"ping -c 2 -W 2 {dst_ip}",
                    timeout=5,
                )
                output = (res.stdout + ("\n" + res.stderr if res.stderr else "")).strip()

                is_reach, loss_pct, avg_rtt = self._parse_ping_output(output)

                reachability_matrix.append(
                    ReachabilityState(
                        source=src,
                        destination=dst,
                        reachable=is_reach,
                        latency_ms=avg_rtt,
                        packet_loss_pct=loss_pct,
                    )
                )

        return reachability_matrix

    def _parse_ping_output(self, raw_output: str) -> Tuple[bool, float, Optional[float]]:
        """Parse ping statistics output for reachability, loss, and latency."""
        loss_pct = 100.0
        rtt_avg = None

        m_stats = re.search(
            r"(?P<tx>\d+)\s+packets?\s+transmitted,\s+(?P<rx>\d+)\s+(?:packets?\s+)?received,.*?(?P<loss>\d+(?:\.\d+)?)%\s+packet\s+loss",
            raw_output,
            re.IGNORECASE,
        )
        if m_stats:
            rx = int(m_stats.group("rx"))
            loss_pct = float(m_stats.group("loss"))
            is_reach = (rx > 0 and loss_pct == 0.0)
        else:
            is_reach = ("0% packet loss" in raw_output or "bytes from" in raw_output) and "100% packet loss" not in raw_output
            if is_reach:
                loss_pct = 0.0

        m_rtt = re.search(
            r"(?:rtt|round-trip)\s+min/avg/max(?:/(?:mdev|stddev))?\s*=\s*[\d\.]+/(?P<avg>[\d\.]+)/[\d\.]+",
            raw_output,
            re.IGNORECASE,
        )
        if m_rtt:
            try:
                rtt_avg = float(m_rtt.group("avg"))
            except ValueError:
                pass

        return is_reach, loss_pct, rtt_avg
