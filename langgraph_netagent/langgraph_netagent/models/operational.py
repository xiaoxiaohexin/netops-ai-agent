"""Operational Models for NetOps Incident Troubleshooting and Self-Healing.

Defines Pydantic models for:
- 5-Tuple failure attributes parsed from telemetry and syslog.
- InventoryPool extracted from healthy network baselines.
- Single-exit and interface discrepancies.
- AAL (Agent Access Layer) tool call requests and responses.
- Shadow Sandbox replica execution results.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Literal, Optional, Tuple
from pydantic import BaseModel, Field


class FiveTuple(BaseModel):
    """5-tuple network failure attribute extracted from telemetry or syslog alerts."""
    source_ip: str
    destination_ip: str
    protocol: str = "ICMP"
    source_port: Optional[int] = 0
    destination_port: Optional[int] = 0
    alert_type: str = "PACKET_DROP"
    raw_log: Optional[str] = None
    overlimits_count: Optional[int] = 0
    dropped_packets: Optional[int] = 0
    is_external_overload: bool = False

    @classmethod
    def from_traffic_overload(
        cls,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        src_port: int = 0,
        dst_port: int = 80,
        overlimits: int = 0,
        dropped: int = 0,
        raw_log: Optional[str] = None,
    ) -> "FiveTuple":
        """Construct a 5-tuple attribute representing traffic overload / buffer overlimits."""
        return cls(
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=protocol.upper(),
            source_port=src_port,
            destination_port=dst_port,
            alert_type="TRAFFIC_OVERLOAD",
            overlimits_count=overlimits,
            dropped_packets=dropped,
            is_external_overload=True,
            raw_log=raw_log or f"Buffer overload: {dropped} dropped, {overlimits} overlimits on path {src_ip} -> {dst_ip}:{dst_port}",
        )

    @classmethod
    def from_qdisc_overlimits(
        cls,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        src_port: int = 0,
        dst_port: int = 80,
        overlimits: int = 0,
        dropped: int = 0,
        raw_log: Optional[str] = None,
    ) -> "FiveTuple":
        """Construct a 5-tuple attribute from tc qdisc overlimits."""
        return cls.from_traffic_overload(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            overlimits=overlimits,
            dropped=dropped,
            raw_log=raw_log,
        )

    @classmethod
    def from_ping_failure(
        cls,
        src_ip: str,
        dst_ip: str,
        failure_msg: str = "",
    ) -> "FiveTuple":
        """Construct a 5-tuple from a ping probe reachability failure."""
        return cls(
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol="ICMP",
            source_port=0,
            destination_port=0,
            alert_type="PACKET_DROP",
            raw_log=failure_msg or f"Ping drop {src_ip} -> {dst_ip}",
        )

    @classmethod
    def from_syslog(cls, log_line: str) -> Optional["FiveTuple"]:
        """Parse syslog or alert message into a 5-tuple failure if patterns match."""
        if not isinstance(log_line, str) or not log_line.strip():
            return None

        # 1. IPTables / Netfilter: SRC=... DST=... PROTO=... SPT=... DPT=...
        m_src = re.search(r"SRC=([0-9a-fA-F:\.]+)", log_line, re.IGNORECASE)
        m_dst = re.search(r"DST=([0-9a-fA-F:\.]+)", log_line, re.IGNORECASE)
        if m_src and m_dst:
            try:
                s_ip = str(ipaddress.ip_address(m_src.group(1)))
                d_ip = str(ipaddress.ip_address(m_dst.group(1)))
                m_proto = re.search(r"PROTO=(\w+)", log_line, re.IGNORECASE)
                m_spt = re.search(r"SPT=(\d+)", log_line, re.IGNORECASE)
                m_dpt = re.search(r"DPT=(\d+)", log_line, re.IGNORECASE)
                proto = (m_proto.group(1) if m_proto else "TCP").upper()
                s_port = int(m_spt.group(1)) if m_spt else 0
                d_port = int(m_dpt.group(1)) if m_dpt else 0
                return cls(
                    source_ip=s_ip,
                    destination_ip=d_ip,
                    protocol=proto,
                    source_port=s_port,
                    destination_port=d_port,
                    alert_type="PACKET_DROP",
                    raw_log=log_line,
                )
            except ValueError:
                pass

        # 2. Cisco IOS ACL: denied tcp 10.1.1.2(12345) -> 10.2.2.2(80) or IPv6
        m_cisco = re.search(
            r"denied\s+(\w+)\s+([0-9a-fA-F:\.]+)(?:\((\d+)\))?\s*(?:->|to)\s*([0-9a-fA-F:\.]+)(?:\((\d+)\))?",
            log_line,
            re.IGNORECASE,
        )
        if m_cisco:
            try:
                proto = m_cisco.group(1).upper()
                s_ip = str(ipaddress.ip_address(m_cisco.group(2)))
                s_port = int(m_cisco.group(3)) if m_cisco.group(3) else 0
                d_ip = str(ipaddress.ip_address(m_cisco.group(4)))
                d_port = int(m_cisco.group(5)) if m_cisco.group(5) else 0
                return cls(
                    source_ip=s_ip,
                    destination_ip=d_ip,
                    protocol=proto,
                    source_port=s_port,
                    destination_port=d_port,
                    alert_type="ACL_DENIED",
                    raw_log=log_line,
                )
            except ValueError:
                pass

        # Helper to parse IP and port from IPv4 or IPv6 tokens
        def _parse_ip_and_port(token: str) -> Tuple[Optional[str], int]:
            t = token.strip()
            if t.startswith("["):
                m_br = re.match(r"\[([0-9a-fA-F:]+)\](?::(\d+))?", t)
                if m_br:
                    try:
                        valid = str(ipaddress.ip_address(m_br.group(1)))
                        port = int(m_br.group(2)) if m_br.group(2) else 0
                        return valid, port
                    except ValueError:
                        return None, 0
            if "." in t:
                parts = re.split(r"[:/]", t)
                try:
                    valid = str(ipaddress.ip_address(parts[0]))
                    port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                    return valid, port
                except ValueError:
                    return None, 0
            if ":" in t:
                left, sep, right = t.rpartition(":")
                if sep and right.isdigit() and 1 <= int(right) <= 65535:
                    try:
                        valid = str(ipaddress.ip_address(left))
                        return valid, int(right)
                    except ValueError:
                        pass
                try:
                    valid = str(ipaddress.ip_address(t))
                    return valid, 0
                except ValueError:
                    pass
            return None, 0

        # 3. Standard / Juniper Junos: src -> dst
        m = re.search(
            r"([0-9a-fA-F:\.\[\]/]+)\s*(?:->|to)\s*([0-9a-fA-F:\.\[\]/]+).*?(?:proto=(\w+))?",
            log_line,
            re.IGNORECASE,
        )
        if m:
            s_ip, s_port = _parse_ip_and_port(m.group(1))
            d_ip, d_port = _parse_ip_and_port(m.group(2))
            if s_ip and d_ip:
                log_upper = log_line.upper()
                if "BGP" in log_upper:
                    proto = "TCP"
                    s_port = s_port or 179
                    d_port = d_port or 179
                    alert_type = "BGP_SESSION_DOWN"
                elif "OSPF" in log_upper:
                    proto = "OSPF"
                    alert_type = "OSPF_NEIGHBOR_DOWN"
                elif "ISIS" in log_upper or "IS-IS" in log_upper:
                    proto = "ISIS"
                    alert_type = "ISIS_ADJACENCY_DOWN"
                else:
                    proto = (m.group(3) or "TCP").upper()
                    alert_type = "PACKET_DROP" if "DROP" in log_upper else "SYSLOG_ALERT"

                return cls(
                    source_ip=s_ip,
                    destination_ip=d_ip,
                    protocol=proto,
                    source_port=s_port,
                    destination_port=d_port,
                    alert_type=alert_type,
                    raw_log=log_line,
                )

        # 4. Check BGP / OSPF / Routing Protocol / Adjacency logs
        log_upper = log_line.upper()
        if any(kw in log_upper for kw in ("BGP", "OSPF", "ISIS", "IS-IS", "ADJCHANGE", "PEER", "NEIGHBOR")):
            is_ospf = "OSPF" in log_upper
            is_isis = "ISIS" in log_upper or "IS-IS" in log_upper

            ip_matches: List[Tuple[str, int]] = []
            for cand in re.findall(r"[0-9a-fA-F:\.\[\]/]+", log_line):
                vip, port = _parse_ip_and_port(cand)
                if vip and vip not in [m[0] for m in ip_matches]:
                    ip_matches.append((vip, port))

            if ip_matches:
                if is_ospf:
                    proto = "OSPF"
                    s_port = 0
                    d_port = 0
                    alert_type = "OSPF_NEIGHBOR_DOWN"
                elif is_isis:
                    proto = "ISIS"
                    s_port = 0
                    d_port = 0
                    alert_type = "ISIS_ADJACENCY_DOWN"
                else:
                    proto = "TCP"
                    s_port = 179
                    d_port = ip_matches[0][1] or 179
                    alert_type = "BGP_SESSION_DOWN"

                if len(ip_matches) >= 2:
                    return cls(
                        source_ip=ip_matches[0][0],
                        destination_ip=ip_matches[1][0],
                        protocol=proto,
                        source_port=s_port,
                        destination_port=d_port,
                        alert_type=alert_type,
                        raw_log=log_line,
                    )
                else:
                    return cls(
                        source_ip="0.0.0.0",
                        destination_ip=ip_matches[0][0],
                        protocol=proto,
                        source_port=s_port,
                        destination_port=d_port,
                        alert_type=alert_type,
                        raw_log=log_line,
                    )
        return None


class InventoryPool(BaseModel):
    """Normalized inventory of network assets, interfaces, IP addresses, and baseline routes."""
    nodes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    ip_to_node: Dict[str, str] = Field(default_factory=dict)
    subnets: List[str] = Field(default_factory=list)
    assets: List[str] = Field(default_factory=list)
    interfaces: Dict[str, List[str]] = Field(default_factory=dict)
    baseline_routes: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)

    @classmethod
    def from_baseline(cls, baseline_data: Dict[str, Any]) -> "InventoryPool":
        """Extract an InventoryPool from raw baseline data."""
        nodes = baseline_data.get("nodes", {})
        assets = list(nodes.keys())
        ip_to_node: Dict[str, str] = {}
        subnets_set = set()
        interfaces: Dict[str, List[str]] = {}
        baseline_routes: Dict[str, List[Dict[str, Any]]] = {}

        for node_name, node_info in nodes.items():
            interfaces[node_name] = []
            ip_text = node_info.get("ip_addr", "")
            if not ip_text or ip_text.startswith("ERROR"):
                continue

            current_iface = None
            for line in ip_text.splitlines():
                m_hdr = re.match(r"(?:\d+:\s+)?([a-zA-Z0-9_\-\.@:]+):", line.strip())
                if m_hdr:
                    raw_name = m_hdr.group(1)
                    current_iface = raw_name.split("@")[0]
                    if current_iface not in interfaces[node_name]:
                        interfaces[node_name].append(current_iface)
                    continue

                if current_iface:
                    m_ip = re.search(r"inet\s+([0-9\.]+)/(\d+)", line)
                    if m_ip:
                        ip = m_ip.group(1)
                        prefix_len = int(m_ip.group(2))
                        # Ignore loopback and mgmt (eth0, 172.100.100.0/24)
                        if current_iface != "eth0" and not ip.startswith("127.") and not ip.startswith("172.100.100."):
                            ip_to_node[ip] = node_name
                            try:
                                net = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
                                subnets_set.add(str(net))
                            except Exception:
                                pass

            # Extract baseline routes
            route_text = node_info.get("route_table", "")
            node_routes: List[Dict[str, Any]] = []
            if route_text and not route_text.startswith("ERROR"):
                for line in route_text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # Match static/connected routes e.g. "S>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2"
                    # or "10.1.1.0/24 dev eth1 proto kernel"
                    m_stat = re.search(r"([0-9\.]+/\d+|default)\s+(?:\[.*?\]\s+)?via\s+([0-9\.]+)", line)
                    if m_stat:
                        node_routes.append({
                            "destination": m_stat.group(1),
                            "next_hop": m_stat.group(2),
                            "raw": line,
                            "type": "static",
                        })
                    else:
                        m_conn = re.search(r"([0-9\.]+/\d+)\s+is directly connected,\s*([a-zA-Z0-9_\-]+)", line)
                        if m_conn:
                            node_routes.append({
                                "destination": m_conn.group(1),
                                "next_hop": None,
                                "interface": m_conn.group(2),
                                "raw": line,
                                "type": "connected",
                            })
                        elif "dev" in line:
                            m_dev = re.search(r"([0-9\.]+/\d+|default)\s+dev\s+([a-zA-Z0-9_\-]+)", line)
                            if m_dev:
                                node_routes.append({
                                    "destination": m_dev.group(1),
                                    "next_hop": None,
                                    "interface": m_dev.group(2),
                                    "raw": line,
                                    "type": "connected",
                                })
            baseline_routes[node_name] = node_routes

        return cls(
            nodes=nodes,
            ip_to_node=ip_to_node,
            subnets=sorted(list(subnets_set)),
            assets=assets,
            interfaces=interfaces,
            baseline_routes=baseline_routes,
        )


class AnomalyClassification(BaseModel):
    """Categorization and root-cause classification of detected network anomalies."""
    category: Literal["single_exit_failure", "external_overload", "internal_link_failure", "healthy"]
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str
    bottleneck_node: Optional[str] = None
    bottleneck_interface: Optional[str] = None
    offending_source_ip: Optional[str] = None
    victim_destination_ip: Optional[str] = None
    recommended_action: str


class NetworkDiscrepancy(BaseModel):
    """Isolated difference between observed network state and healthy baseline."""
    node: str
    discrepancy_type: str  # "missing_route", "interface_down", "reachability_loss", "single_exit_failure", "buffer_overlimit"
    affected_interface: Optional[str] = None
    target_destination: Optional[str] = None
    description: str
    suspect_nodes: List[str] = Field(default_factory=list)


class AALToolCall(BaseModel):
    """Structured tool execution request managed by the Agent Access Layer."""
    tool_name: str  # "cli_exec", "read_config", "probe", "patch_exec", "sandbox_test"
    node_name: str
    command: str
    step_tag: Optional[str] = None
    read_only: bool = False
    timeout: int = 15


class AALResponse(BaseModel):
    """Normalized structured response returned by the Agent Access Layer."""
    success: bool
    exit_code: int = 0
    raw_stdout: str = ""
    raw_stderr: str = ""
    parsed_json: Dict[str, Any] = Field(default_factory=dict)
    step_tag: Optional[str] = None
    is_blocked: bool = False
    error_message: Optional[str] = None


class ShadowSandboxResult(BaseModel):
    """Validation report from running candidate patches inside a shadow sandbox replica."""
    sandbox_id: str
    cloned_node: str
    commands_tested: List[str] = Field(default_factory=list)
    all_passed: bool
    output_logs: List[Dict[str, Any]] = Field(default_factory=list)
    error_message: Optional[str] = None
