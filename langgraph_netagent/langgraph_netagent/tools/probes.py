"""Multi-Vendor Network Telemetry Probes and Consolidated Collector."""

from __future__ import annotations
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from langgraph_netagent.models.telemetry import (
    InterfaceStatsTelemetry,
    InterfaceTelemetry,
    NetworkHealthReport,
    PingTelemetry,
    QdiscTelemetry,
    RouteEntry,
    RouteTableTelemetry,
)
from langgraph_netagent.tools.base import BaseNetworkLabAdapter


class PingProbe:
    """Probes IP connectivity between network containers using ICMP ping."""

    STATISTICS_REGEX = re.compile(
        r"(?P<tx>\d+)\s+packets?\s+transmitted,\s+(?P<rx>\d+)\s+(?:packets?\s+)?received,.*?(?P<loss>\d+(?:\.\d+)?)%\s+packet\s+loss",
        re.IGNORECASE,
    )
    RTT_REGEX = re.compile(
        r"(?:rtt|round-trip)\s+min/avg/max(?:/(?:mdev|stddev))?\s*=\s*(?P<min>[\d\.]+)/(?P<avg>[\d\.]+)/(?P<max>[\d\.]+)(?:/(?P<mdev>[\d\.]+))?\s*ms",
        re.IGNORECASE,
    )

    @classmethod
    def run(
        cls,
        adapter: BaseNetworkLabAdapter,
        src_node: str,
        dst_ip: str,
        count: int = 3,
        timeout: int = 2,
    ) -> PingTelemetry:
        """Execute ping inside src_node targeting dst_ip and parse structured telemetry."""
        cmd = f"ping -c {count} -W {timeout} {dst_ip}"
        result = adapter.exec_command(node_name=src_node, command=cmd, timeout=timeout + 5)
        raw = (result.stdout + ("\n" + result.stderr if result.stderr else "")).strip()
        return cls.parse_ping_output(raw_output=raw, src_node=src_node, dst_ip=dst_ip, fallback_count=count)

    @classmethod
    def parse_ping_output(
        cls,
        raw_output: str,
        src_node: str = "unknown",
        dst_ip: str = "unknown",
        fallback_count: int = 3,
    ) -> PingTelemetry:
        """Parse raw ping stdout/stderr into a structured PingTelemetry model."""
        tx = fallback_count
        rx = 0
        loss_pct = 100.0
        rtt_min = None
        rtt_avg = None
        rtt_max = None
        rtt_mdev = None
        error_message = None

        # Extract transmission statistics
        stats_match = cls.STATISTICS_REGEX.search(raw_output)
        if stats_match:
            tx = int(stats_match.group("tx"))
            rx = int(stats_match.group("rx"))
            loss_pct = float(stats_match.group("loss"))

        # Extract RTT metrics
        rtt_match = cls.RTT_REGEX.search(raw_output)
        if rtt_match:
            rtt_min = float(rtt_match.group("min"))
            rtt_avg = float(rtt_match.group("avg"))
            rtt_max = float(rtt_match.group("max"))
            mdev_val = rtt_match.group("mdev")
            rtt_mdev = float(mdev_val) if mdev_val is not None else None

        # Detect error messages
        lower_out = raw_output.lower()
        if "destination host unreachable" in lower_out:
            error_message = "Destination Host Unreachable (ARP or next-hop resolution failed)"
        elif "destination net unreachable" in lower_out:
            error_message = "Destination Net Unreachable (no route to destination subnet)"
        elif "network is unreachable" in lower_out:
            error_message = "Network is unreachable (missing default gateway or interface down)"
        elif "time to live exceeded" in lower_out or "ttl exceeded" in lower_out:
            error_message = "Time to Live (TTL) exceeded (routing loop detected)"
        elif loss_pct >= 100.0:
            error_message = "100% packet loss (packet dropped along forwarding path)"
        elif loss_pct > 0.0:
            error_message = f"Degraded path: {loss_pct:.1f}% packet loss observed"

        is_reachable = (rx > 0 and loss_pct == 0.0)

        return PingTelemetry(
            src_node=src_node,
            dst_ip=dst_ip,
            transmitted=tx,
            received=rx,
            loss_pct=loss_pct,
            rtt_min_ms=rtt_min,
            rtt_avg_ms=rtt_avg,
            rtt_max_ms=rtt_max,
            rtt_mdev_ms=rtt_mdev,
            is_reachable=is_reachable,
            error_message=error_message,
            raw_output=raw_output,
        )


class RouteTableProbe:
    """Probes and normalizes routing tables across Linux, FRRouting, and Nokia SR Linux."""

    @classmethod
    def run(
        cls,
        adapter: BaseNetworkLabAdapter,
        node: str,
        device_kind: str = "linux",
    ) -> RouteTableTelemetry:
        """Inspect routing table of a node and return RouteTableTelemetry."""
        clean_kind = device_kind.lower()

        if "frr" in clean_kind:
            # Try vtysh JSON first
            res = adapter.exec_command(node_name=node, command="vtysh -c 'show ip route json'", timeout=10)
            if res.success and res.stdout.strip().startswith("{"):
                return cls.parse_frr_routes_json(node=node, raw_output=res.stdout)
            # Fallback to text
            res_text = adapter.exec_command(node_name=node, command="vtysh -c 'show ip route'", timeout=10)
            return cls.parse_frr_routes_text(node=node, raw_output=res_text.stdout)

        elif "srl" in clean_kind or "srlinux" in clean_kind:
            res = adapter.exec_command(
                node_name=node,
                command="sr_cli 'show network-instance default route-table'",
                timeout=10,
            )
            return cls.parse_srl_routes(node=node, raw_output=res.stdout)

        else:
            # Standard Linux
            res = adapter.exec_command(node_name=node, command="ip route show", timeout=10)
            return cls.parse_linux_routes(node=node, raw_output=res.stdout)

    @classmethod
    def parse_linux_routes(cls, node: str, raw_output: str) -> RouteTableTelemetry:
        """Parse Linux 'ip route show' text output."""
        routes: List[RouteEntry] = []
        has_default = False

        for line in raw_output.splitlines():
            clean = line.strip()
            if not clean:
                continue

            # Match default route: default via 10.1.1.1 dev eth1 ...
            def_match = re.search(r"^default\s+via\s+([0-9\.]+)(?:\s+dev\s+(\S+))?", clean)
            if def_match:
                gw = def_match.group(1)
                dev = def_match.group(2)
                has_default = True
                routes.append(
                    RouteEntry(
                        destination="default",
                        next_hop=gw,
                        interface=dev,
                        protocol="static",
                    )
                )
                continue

            # Match subnet route: 10.1.1.0/24 dev eth1 proto kernel scope link ...
            # or: 10.2.2.0/24 via 10.1.12.2 dev eth2 proto static ...
            subnet_match = re.search(
                r"^([0-9\./]+)(?:\s+via\s+([0-9\.]+))?(?:\s+dev\s+(\S+))?(?:\s+proto\s+(\S+))?",
                clean,
            )
            if subnet_match:
                pfx = subnet_match.group(1)
                gw = subnet_match.group(2)
                dev = subnet_match.group(3)
                proto = subnet_match.group(4) or ("static" if gw else "connected")
                routes.append(
                    RouteEntry(
                        destination=pfx,
                        next_hop=gw,
                        interface=dev,
                        protocol=proto,
                    )
                )

        return RouteTableTelemetry(
            node=node,
            routes=routes,
            has_default_route=has_default,
            raw_output=raw_output,
        )

    @classmethod
    def parse_frr_routes_json(cls, node: str, raw_output: str) -> RouteTableTelemetry:
        """Parse FRR 'show ip route json' output."""
        routes: List[RouteEntry] = []
        has_default = False

        try:
            data = json.loads(raw_output)
            for pfx, entries in data.items():
                if pfx in ("default", "0.0.0.0/0"):
                    has_default = True
                if isinstance(entries, list):
                    for entry in entries:
                        proto = entry.get("protocol") or "static"
                        nexthops = entry.get("nexthops", [])
                        if nexthops:
                            for nh in nexthops:
                                routes.append(
                                    RouteEntry(
                                        destination=pfx,
                                        next_hop=nh.get("ip"),
                                        interface=nh.get("interfaceName"),
                                        protocol=proto,
                                    )
                                )
                        else:
                            routes.append(
                                RouteEntry(
                                    destination=pfx,
                                    next_hop=None,
                                    interface=None,
                                    protocol=proto,
                                )
                            )
        except Exception:
            # Fallback to text parsing
            return cls.parse_frr_routes_text(node=node, raw_output=raw_output)

        return RouteTableTelemetry(
            node=node,
            routes=routes,
            has_default_route=has_default,
            raw_output=raw_output,
        )

    @classmethod
    def parse_frr_routes_text(cls, node: str, raw_output: str) -> RouteTableTelemetry:
        """Parse FRR 'show ip route' text output."""
        routes: List[RouteEntry] = []
        has_default = False

        for line in raw_output.splitlines():
            clean = line.strip()
            # E.g. S>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2, weight 1, 00:01:23
            # or: C>* 10.1.1.0/24 is directly connected, eth1, 00:01:23
            match_via = re.search(r"^([A-Z>\*]+)\s+([0-9\./]+).*?via\s+([0-9\.]+)(?:,\s*(\S+))?", clean)
            if match_via:
                code = match_via.group(1)
                pfx = match_via.group(2)
                gw = match_via.group(3)
                dev = match_via.group(4)
                if pfx in ("0.0.0.0/0", "default"):
                    has_default = True
                proto = "static" if "S" in code else "dynamic"
                routes.append(RouteEntry(destination=pfx, next_hop=gw, interface=dev, protocol=proto))
                continue

            match_conn = re.search(r"^([A-Z>\*]+)\s+([0-9\./]+)\s+is directly connected(?:,\s*(\S+))?", clean)
            if match_conn:
                pfx = match_conn.group(2)
                dev = match_conn.group(3)
                routes.append(RouteEntry(destination=pfx, next_hop=None, interface=dev, protocol="connected"))

        return RouteTableTelemetry(
            node=node,
            routes=routes,
            has_default_route=has_default,
            raw_output=raw_output,
        )

    @classmethod
    def parse_srl_routes(cls, node: str, raw_output: str) -> RouteTableTelemetry:
        """Parse Nokia SR Linux route table output."""
        routes: List[RouteEntry] = []
        has_default = False

        for line in raw_output.splitlines():
            clean = line.strip()
            match = re.search(r"^([0-9\./]+)\s+(\S+)\s+(\S+)\s+(\S+)", clean)
            if match:
                pfx = match.group(1)
                rtype = match.group(2)
                nh = match.group(3)
                dev = match.group(4)
                if pfx in ("0.0.0.0/0", "default"):
                    has_default = True
                next_hop = None if nh.lower() == "direct" else nh
                routes.append(RouteEntry(destination=pfx, next_hop=next_hop, interface=dev, protocol=rtype))

        return RouteTableTelemetry(
            node=node,
            routes=routes,
            has_default_route=has_default,
            raw_output=raw_output,
        )


class InterfaceProbe:
    """Probes interface states, assigned IP addresses, and operational health."""

    @classmethod
    def run(
        cls,
        adapter: BaseNetworkLabAdapter,
        node: str,
        device_kind: str = "linux",
    ) -> List[InterfaceTelemetry]:
        """Inspect network interfaces on node."""
        res = adapter.exec_command(node_name=node, command="ip addr show", timeout=10)
        return cls.parse_linux_ip_addr(node=node, raw_output=res.stdout)

    @classmethod
    def parse_linux_ip_addr(cls, node: str, raw_output: str) -> List[InterfaceTelemetry]:
        """Parse standard Linux 'ip addr show' output."""
        interfaces: List[InterfaceTelemetry] = []
        current_iface: Optional[dict] = None

        for line in raw_output.splitlines():
            # Line format: 2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ... state UP ...
            header_match = re.search(r"^\d+:\s+([a-zA-Z0-9_\-\.@]+):\s+<([^>]+)>\s+mtu\s+(\d+).*?state\s+([a-zA-Z0-9_\-]+)", line)
            if header_match:
                if current_iface:
                    interfaces.append(cls._build_telemetry(node, current_iface))
                if_name = header_match.group(1).split("@")[0]  # strip @if...
                flags = header_match.group(2)
                mtu = int(header_match.group(3))
                state = header_match.group(4).upper()

                admin_state = "UP" if "UP" in flags else "DOWN"
                oper_state = state if state in ("UP", "DOWN", "UNKNOWN") else ("UP" if "LOWER_UP" in flags else "DOWN")

                current_iface = {
                    "name": if_name,
                    "admin": admin_state,
                    "oper": oper_state,
                    "mtu": mtu,
                    "mac": None,
                    "ips": [],
                }
                continue

            if not current_iface:
                continue

            # Extract MAC address
            mac_match = re.search(r"link/\S+\s+([0-9a-fA-F:]{17})", line)
            if mac_match:
                current_iface["mac"] = mac_match.group(1).lower()

            # Extract IPv4 address
            inet_match = re.search(r"inet\s+([0-9\./]+)", line)
            if inet_match:
                current_iface["ips"].append(inet_match.group(1))

        if current_iface:
            interfaces.append(cls._build_telemetry(node, current_iface))

        return interfaces

    @staticmethod
    def _build_telemetry(node: str, iface_data: dict) -> InterfaceTelemetry:
        admin = iface_data["admin"]
        oper = iface_data["oper"]
        is_healthy = (admin == "UP" and oper in ("UP", "LOWER_UP", "UNKNOWN"))

        return InterfaceTelemetry(
            node=node,
            interface_name=iface_data["name"],
            admin_state=admin,
            oper_state=oper,
            ip_addresses=iface_data["ips"],
            mtu=iface_data["mtu"],
            mac_address=iface_data["mac"],
            is_healthy=is_healthy,
        )


class QdiscProbe:
    """Probes Linux traffic control (tc) qdiscs for buffer overlimits and packet drops."""

    @classmethod
    def run(
        cls,
        adapter: BaseNetworkLabAdapter,
        node: str,
        interface: Optional[str] = None,
        timeout: int = 5,
    ) -> List[QdiscTelemetry]:
        """Execute 'tc -s qdisc show' inside node and parse structured telemetry."""
        cmd = f"tc -s qdisc show dev {interface}" if interface else "tc -s qdisc show"
        res = adapter.exec_command(node_name=node, command=cmd, timeout=timeout)
        if not res.success and not res.stdout:
            return []
        return cls.parse_tc_output(node=node, raw_output=res.stdout, fallback_interface=interface)

    @classmethod
    def parse_tc_output(
        cls,
        node: str,
        raw_output: str,
        fallback_interface: Optional[str] = None,
    ) -> List[QdiscTelemetry]:
        """Parse raw tc -s qdisc stdout into structured QdiscTelemetry models."""
        if not raw_output or not raw_output.strip():
            return []

        blocks = re.split(r"(?m)^(?=qdisc\s+)", raw_output.strip())
        results: List[QdiscTelemetry] = []

        for block in blocks:
            clean_block = block.strip()
            if not clean_block or not clean_block.startswith("qdisc"):
                continue

            lines = clean_block.splitlines()
            first_line = lines[0]

            m_th = re.match(r"^qdisc\s+([a-zA-Z0-9_\-]+)\s+([a-zA-Z0-9_:]+)", first_line)
            if not m_th:
                continue
            q_type = m_th.group(1)
            handle = m_th.group(2)

            m_dev = re.search(r"\bdev\s+([a-zA-Z0-9_\-\.]+)", first_line)
            iface = m_dev.group(1) if m_dev else (fallback_interface or "eth1")

            m_parent = re.search(r"\bparent\s+([a-zA-Z0-9_:]+)", first_line)
            parent = m_parent.group(1) if m_parent else None

            m_sent = re.search(r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt", clean_block, re.IGNORECASE)
            bytes_sent = int(m_sent.group(1)) if m_sent else 0
            packets_sent = int(m_sent.group(2)) if m_sent else 0

            m_dropped = re.search(r"dropped\s+(\d+)", clean_block, re.IGNORECASE)
            dropped = int(m_dropped.group(1)) if m_dropped else 0

            m_overlimits = re.search(r"overlimits\s+(\d+)", clean_block, re.IGNORECASE)
            overlimits = int(m_overlimits.group(1)) if m_overlimits else 0

            m_requeues = re.search(r"requeues\s+(\d+)", clean_block, re.IGNORECASE)
            requeues = int(m_requeues.group(1)) if m_requeues else 0

            m_backlog = re.search(r"backlog\s+(\d+)[bB]\s+(\d+)[pP]", clean_block, re.IGNORECASE)
            backlog_bytes = int(m_backlog.group(1)) if m_backlog else 0
            backlog_packets = int(m_backlog.group(2)) if m_backlog else 0

            results.append(
                QdiscTelemetry(
                    node=node,
                    interface=iface,
                    qdisc_type=q_type,
                    handle=handle,
                    parent=parent,
                    bytes_sent=bytes_sent,
                    packets_sent=packets_sent,
                    dropped=dropped,
                    overlimits=overlimits,
                    requeues=requeues,
                    backlog_bytes=backlog_bytes,
                    backlog_packets=backlog_packets,
                    raw_output=clean_block,
                )
            )

        return results


class InterfaceStatsProbe:
    """Probes Linux network interface packet loss and error counters using 'ip -s link show'."""

    @classmethod
    def run(
        cls,
        adapter: BaseNetworkLabAdapter,
        node: str,
        timeout: int = 5,
    ) -> List[InterfaceStatsTelemetry]:
        """Execute 'ip -s link show' inside node and parse structured interface statistics."""
        res = adapter.exec_command(node_name=node, command="ip -s link show", timeout=timeout)
        if not res.success and not res.stdout:
            return []
        return cls.parse_ip_link_stats(node=node, raw_output=res.stdout)

    @classmethod
    def parse_ip_link_stats(cls, node: str, raw_output: str) -> List[InterfaceStatsTelemetry]:
        """Parse raw 'ip -s link show' stdout into structured InterfaceStatsTelemetry models."""
        if not raw_output or not raw_output.strip():
            return []

        results: List[InterfaceStatsTelemetry] = []
        blocks = re.split(r"(?m)^(?=\d+:\s+)", raw_output.strip())

        for block in blocks:
            clean_block = block.strip()
            if not clean_block:
                continue

            lines = clean_block.splitlines()
            first_line = lines[0]

            m_iface = re.search(r"^\d+:\s+([a-zA-Z0-9_\-\.@]+):", first_line)
            if not m_iface:
                continue
            iface_name = m_iface.group(1).split("@")[0]

            rx_bytes = 0
            rx_packets = 0
            rx_errors = 0
            rx_dropped = 0

            tx_bytes = 0
            tx_packets = 0
            tx_errors = 0
            tx_dropped = 0

            for i, line in enumerate(lines):
                line_upper = line.strip().upper()
                if line_upper.startswith("RX:") and i + 1 < len(lines):
                    nums = [int(n) for n in re.findall(r"\d+", lines[i + 1])]
                    if len(nums) >= 4:
                        rx_bytes = nums[0]
                        rx_packets = nums[1]
                        rx_errors = nums[2]
                        rx_dropped = nums[3]

                elif line_upper.startswith("TX:") and i + 1 < len(lines):
                    nums = [int(n) for n in re.findall(r"\d+", lines[i + 1])]
                    if len(nums) >= 4:
                        tx_bytes = nums[0]
                        tx_packets = nums[1]
                        tx_errors = nums[2]
                        tx_dropped = nums[3]

            results.append(
                InterfaceStatsTelemetry(
                    node=node,
                    interface=iface_name,
                    rx_packets=rx_packets,
                    rx_bytes=rx_bytes,
                    rx_errors=rx_errors,
                    rx_dropped=rx_dropped,
                    tx_packets=tx_packets,
                    tx_bytes=tx_bytes,
                    tx_errors=tx_errors,
                    tx_dropped=tx_dropped,
                )
            )

        return results


class NetworkTelemetryCollector:
    """Consolidated telemetry collector running probes and building NetworkHealthReport."""

    @classmethod
    def collect(
        cls,
        adapter: BaseNetworkLabAdapter,
        ping_targets: List[Tuple[str, str]],  # (src_node, dst_ip)
        router_nodes: Optional[List[str]] = None,
        all_nodes: Optional[List[str]] = None,
        node_kinds: Optional[Dict[str, str]] = None,
        required_routes: Optional[Dict[str, List[str]]] = None,  # node -> [prefixes]
        last_qdisc_stats: Optional[Dict[str, Dict[str, int]]] = None,
    ) -> NetworkHealthReport:
        """Run connectivity, routing, interface, and qdisc probes and synthesize a health report.
        
        Args:
            adapter: Lab adapter (Live or Mock).
            ping_targets: List of (source_node_name, destination_ip) pairs.
            router_nodes: List of router node names to query routing tables and queue buffers.
            all_nodes: List of all nodes to query interface states.
            node_kinds: Optional map of node name to kind (e.g. {'frr1': 'frr'}).
            required_routes: Optional map of node name to expected route prefixes.
            last_qdisc_stats: Optional previous qdisc stats snapshot to detect active delta growth.
            
        Returns:
            NetworkHealthReport with consolidated health, failures, and diagnostic hints.
        """
        kinds = node_kinds or {}
        ping_results: List[PingTelemetry] = []
        route_tables: Dict[str, RouteTableTelemetry] = {}
        interfaces: Dict[str, List[InterfaceTelemetry]] = {}
        qdisc_stats: Dict[str, List[QdiscTelemetry]] = {}
        interface_stats: Dict[str, List[InterfaceStatsTelemetry]] = {}
        buffer_anomalies: List[Dict[str, Any]] = []
        failures: List[str] = []
        recommendations: List[str] = []

        # 1. Execute Ping Probes
        for src, dst in ping_targets:
            ping_res = PingProbe.run(adapter=adapter, src_node=src, dst_ip=dst)
            ping_results.append(ping_res)
            if not ping_res.is_reachable:
                err_text = ping_res.error_message or f"{ping_res.loss_pct}% loss"
                failures.append(f"Ping failure: {src} -> {dst}: {err_text}")

        # 2. Execute Route Table Probes
        if router_nodes:
            for r_node in router_nodes:
                kind = kinds.get(r_node, "linux")
                rt = RouteTableProbe.run(adapter=adapter, node=r_node, device_kind=kind)
                route_tables[r_node] = rt

                # Check required routes
                if required_routes and r_node in required_routes:
                    for req_pfx in required_routes[r_node]:
                        clean_pfx = req_pfx.strip()
                        if not rt.has_route_to(clean_pfx) and not (clean_pfx == "default" and rt.has_default_route):
                            failures.append(f"Missing route on router '{r_node}': prefix '{clean_pfx}' not in routing table")
                            recommendations.append(f"Configure static or dynamic route for '{clean_pfx}' on '{r_node}'")

        # 3. Execute Interface Probes
        nodes_to_check = all_nodes or (list(set([t[0] for t in ping_targets] + (router_nodes or []))))
        for node in nodes_to_check:
            kind = kinds.get(node, "linux")
            ifaces = InterfaceProbe.run(adapter=adapter, node=node, device_kind=kind)
            interfaces[node] = ifaces
            for ifc in ifaces:
                if not ifc.is_healthy:
                    failures.append(f"Interface anomaly: {node}:{ifc.interface_name} is {ifc.admin_state}/{ifc.oper_state}")
                    recommendations.append(f"Bring up interface '{ifc.interface_name}' on node '{node}'")

        # 4. Execute Qdisc & Interface Stats Probes on router nodes
        if router_nodes:
            for r_node in router_nodes:
                try:
                    qdiscs = QdiscProbe.run(adapter=adapter, node=r_node)
                    if qdiscs:
                        qdisc_stats[r_node] = qdiscs
                        for qd in qdiscs:
                            stat_key = f"{r_node}:{qd.interface}"
                            prev_stat = (last_qdisc_stats or {}).get(stat_key, {})
                            prev_dropped = prev_stat.get("dropped", 0)
                            prev_overlimits = prev_stat.get("overlimits", 0)

                            is_active = (
                                (qd.dropped > prev_dropped or qd.overlimits > prev_overlimits)
                                if last_qdisc_stats
                                else (qd.dropped > 0 or qd.overlimits > 0)
                            )
                            if is_active:
                                buffer_anomalies.append({
                                    "node": r_node,
                                    "interface": qd.interface,
                                    "qdisc_type": qd.qdisc_type,
                                    "dropped": qd.dropped,
                                    "overlimits": qd.overlimits,
                                })
                                failures.append(
                                    f"Buffer overlimit on {r_node}:{qd.interface}: "
                                    f"{qd.dropped} dropped, {qd.overlimits} overlimits"
                                )
                                recommendations.append(
                                    f"Deploy border iptables packet filtering or rate-limiting on {r_node}"
                                )
                except Exception:
                    pass

                try:
                    istats = InterfaceStatsProbe.run(adapter=adapter, node=r_node)
                    if istats:
                        interface_stats[r_node] = istats
                        for st in istats:
                            if st.rx_dropped > 0 or st.tx_dropped > 0:
                                buffer_anomalies.append({
                                    "node": r_node,
                                    "interface": st.interface,
                                    "rx_dropped": st.rx_dropped,
                                    "tx_dropped": st.tx_dropped,
                                })
                                failures.append(
                                    f"Interface packet drop on {r_node}:{st.interface}: "
                                    f"rx_dropped={st.rx_dropped}, tx_dropped={st.tx_dropped}"
                                )
                except Exception:
                    pass

        # 5. Overall status
        all_passed = (len(failures) == 0) and all(p.is_reachable for p in ping_results) and (len(buffer_anomalies) == 0)

        # De-duplicate recommendations while preserving order
        unique_recs: List[str] = []
        for r in recommendations:
            if r not in unique_recs:
                unique_recs.append(r)

        if all_passed and not unique_recs:
            unique_recs.append("All network verification checks passed successfully.")

        return NetworkHealthReport(
            all_passed=all_passed,
            ping_results=ping_results,
            route_tables=route_tables,
            interfaces=interfaces,
            qdisc_stats=qdisc_stats,
            interface_stats=interface_stats,
            buffer_anomalies=buffer_anomalies,
            failures=failures,
            recommendations=unique_recs,
        )
