"""Network Telemetry and Health Verification Contracts."""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PingTelemetry(BaseModel):
    """Structured telemetry output from a container ping probe."""
    model_config = ConfigDict(populate_by_name=True)

    src_node: str = Field(..., description="Source container node name")
    dst_ip: str = Field(..., description="Target destination IP address")
    transmitted: int = Field(..., ge=0, description="Packets transmitted")
    received: int = Field(..., ge=0, description="Packets received")
    loss_pct: float = Field(..., ge=0.0, le=100.0, description="Packet loss percentage")
    rtt_min_ms: Optional[float] = Field(None, ge=0.0, description="Minimum RTT in milliseconds")
    rtt_avg_ms: Optional[float] = Field(None, ge=0.0, description="Average RTT in milliseconds")
    rtt_max_ms: Optional[float] = Field(None, ge=0.0, description="Maximum RTT in milliseconds")
    rtt_mdev_ms: Optional[float] = Field(None, ge=0.0, description="RTT standard deviation")
    is_reachable: bool = Field(..., description="True if received > 0 and loss_pct == 0.0")
    error_message: Optional[str] = Field(None, description="Diagnostic error text if ping failed")
    raw_output: str = Field(default="", description="Raw command stdout/stderr")


class RouteEntry(BaseModel):
    """Normalized route table entry across Linux, FRR, and SRL."""
    model_config = ConfigDict(populate_by_name=True)

    destination: str = Field(..., description="Destination CIDR prefix or 'default'")
    next_hop: Optional[str] = Field(None, description="Next hop IP address")
    interface: Optional[str] = Field(None, description="Outgoing interface name")
    protocol: Optional[str] = Field(None, description="Routing protocol (e.g. kernel, static, bgp)")
    metric: Optional[int] = Field(None, description="Route administrative metric")


class RouteTableTelemetry(BaseModel):
    """Structured telemetry output from route table inspection."""
    model_config = ConfigDict(populate_by_name=True)

    node: str = Field(..., description="Node name where route table was queried")
    routes: List[RouteEntry] = Field(default_factory=list, description="Parsed route entries")
    has_default_route: bool = Field(False, description="True if default gateway exists")
    raw_output: str = Field(default="", description="Raw route command output")

    def has_route_to(self, destination: str) -> bool:
        """Check if routing table has entry for specified prefix."""
        return any(r.destination == destination for r in self.routes)

    def get_nexthop(self, destination: str) -> Optional[str]:
        """Find next-hop address for given destination prefix."""
        for r in self.routes:
            if r.destination == destination:
                return r.next_hop
        return None


class InterfaceTelemetry(BaseModel):
    """Structured telemetry output for a network interface."""
    model_config = ConfigDict(populate_by_name=True)

    node: str = Field(..., description="Node name")
    interface_name: str = Field(..., description="Interface name (e.g. eth1, e1-1)")
    admin_state: str = Field(..., description="Admin state: UP, DOWN")
    oper_state: str = Field(..., description="Operational state: UP, DOWN, LOWER_UP, NO-CARRIER")
    ip_addresses: List[str] = Field(default_factory=list, description="Assigned CIDR IPv4/IPv6 addresses")
    mtu: Optional[int] = Field(None, description="Maximum Transmission Unit")
    mac_address: Optional[str] = Field(None, description="Hardware MAC address")
    is_healthy: bool = Field(..., description="True if admin_state == UP and oper_state in ['UP', 'LOWER_UP']")


class QdiscTelemetry(BaseModel):
    """Structured telemetry output from Linux traffic control (tc) queue inspection."""
    model_config = ConfigDict(populate_by_name=True)

    node: str = Field(..., description="Node name where qdisc was queried")
    interface: str = Field(default="eth1", description="Network interface name")
    qdisc_type: str = Field(..., description="Qdisc algorithm: tbf, netem, fq_codel, pfifo_fast, etc.")
    handle: str = Field(default="", description="Qdisc handle ID (e.g. 1:, 10:)")
    parent: Optional[str] = Field(None, description="Parent handle if nested")
    bytes_sent: int = Field(default=0, ge=0, description="Bytes transmitted through qdisc")
    packets_sent: int = Field(default=0, ge=0, description="Packets transmitted through qdisc")
    dropped: int = Field(default=0, ge=0, description="Packets dropped by queue or buffer overflow")
    overlimits: int = Field(default=0, ge=0, description="Buffer overlimits / rate throttle occurrences")
    requeues: int = Field(default=0, ge=0, description="Number of requeued packets")
    backlog_bytes: int = Field(default=0, ge=0, description="Current queue backlog in bytes")
    backlog_packets: int = Field(default=0, ge=0, description="Current queue backlog in packets")
    raw_output: str = Field(default="", description="Raw command stdout")


class InterfaceStatsTelemetry(BaseModel):
    """Hardware/kernel interface packet counters from 'ip -s link show'."""
    model_config = ConfigDict(populate_by_name=True)

    node: str = Field(..., description="Node name")
    interface: str = Field(..., description="Interface name")
    rx_packets: int = Field(default=0, ge=0, description="Received packets count")
    rx_bytes: int = Field(default=0, ge=0, description="Received bytes count")
    rx_errors: int = Field(default=0, ge=0, description="Received errors count")
    rx_dropped: int = Field(default=0, ge=0, description="Received dropped packets count")
    tx_packets: int = Field(default=0, ge=0, description="Transmitted packets count")
    tx_bytes: int = Field(default=0, ge=0, description="Transmitted bytes count")
    tx_errors: int = Field(default=0, ge=0, description="Transmitted errors count")
    tx_dropped: int = Field(default=0, ge=0, description="Transmitted dropped packets count")


class NetworkHealthReport(BaseModel):
    """Consolidated verification report injected into LangGraph Agent State."""
    model_config = ConfigDict(populate_by_name=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Report creation time")
    all_passed: bool = Field(..., description="True if all connectivity and route checks pass")
    ping_results: List[PingTelemetry] = Field(default_factory=list)
    route_tables: Dict[str, RouteTableTelemetry] = Field(default_factory=dict)
    interfaces: Dict[str, List[InterfaceTelemetry]] = Field(default_factory=dict)
    qdisc_stats: Dict[str, List[QdiscTelemetry]] = Field(default_factory=dict)
    interface_stats: Dict[str, List[InterfaceStatsTelemetry]] = Field(default_factory=dict)
    buffer_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    failures: List[str] = Field(default_factory=list, description="Human/LLM-readable failure descriptions")
    recommendations: List[str] = Field(default_factory=list, description="Suggested diagnostic focus areas")

    def to_summary_markdown(self) -> str:
        """Render a concise markdown summary suitable for LLM self-healing prompts."""
        lines = [
            "### Network Verification Summary",
            f"- Status: {'✅ PASSED' if self.all_passed else '❌ FAILED'}",
            f"- Pings Checked: {len(self.ping_results)} (Failed: {len([p for p in self.ping_results if not p.is_reachable])})",
        ]
        if self.buffer_anomalies:
            lines.append(f"- Buffer Anomalies Detected: {len(self.buffer_anomalies)}")
        if self.failures:
            lines.append("- Failures:")
            for f in self.failures:
                lines.append(f"  * {f}")
        if self.recommendations:
            lines.append("- Recommendations:")
            for r in self.recommendations:
                lines.append(f"  * {r}")
        return "\n".join(lines)
