"""Standard Operating Procedure (SOP) Knowledge Retriever for NetOps Agent.

Provides pre-loaded operational playbooks and search retrieval based on
inferred RAG keywords and 5-tuple failure attributes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class SOPDocument(BaseModel):
    """Standard Operating Procedure (SOP) playbook document."""
    sop_id: str
    title: str
    category: str
    keywords: List[str]
    symptoms: List[str]
    diagnosis_steps: List[str]
    remediation_template: List[str]
    rollback_template: List[str]


# Pre-loaded production operational playbooks
DEFAULT_SOPS: List[SOPDocument] = [
    SOPDocument(
        sop_id="SOP-ROUTING-001",
        title="FRRouting (FRR) Missing Static Route Remediation",
        category="ROUTING_MISCONFIG",
        keywords=["frr", "static", "route", "missing_route", "next-hop", "icmp drop", "routing_misconfig"],
        symptoms=[
            "Ping packets dropped across router",
            "Route table missing destination subnet",
            "Single-exit interface failure",
        ],
        diagnosis_steps=[
            "Run 'vtysh -c \"show ip route\"' to inspect active RIB",
            "Verify next-hop reachable via local interface subnet",
            "Check egress interface state",
        ],
        remediation_template=[
            "vtysh -c 'configure terminal' -c 'ip route {destination_subnet} {next_hop_ip}'",
        ],
        rollback_template=[
            "vtysh -c 'configure terminal' -c 'no ip route {destination_subnet} {next_hop_ip}'",
        ],
    ),
    SOPDocument(
        sop_id="SOP-INTERFACE-002",
        title="Network Interface State Recovery",
        category="INTERFACE_DOWN",
        keywords=["interface", "link", "down", "operstate", "admin_down", "eth1", "eth2"],
        symptoms=[
            "Interface operstate is DOWN",
            "Directly connected link unreachable",
            "Packet loss on local segment",
        ],
        diagnosis_steps=[
            "Execute 'ip link show dev {interface}'",
            "Check carrier signal and MTU negotiation",
        ],
        remediation_template=[
            "ip link set dev {interface} up",
        ],
        rollback_template=[
            "ip link set dev {interface} down",
        ],
    ),
    SOPDocument(
        sop_id="SOP-GATEWAY-003",
        title="Linux Host Default Gateway Remediation",
        category="ROUTING_MISCONFIG",
        keywords=["linux", "host", "gateway", "default", "pc1", "pc2", "default_gateway"],
        symptoms=[
            "End-host cannot reach external subnets",
            "Missing 'default via' in 'ip route show'",
        ],
        diagnosis_steps=[
            "Run 'ip route show' on end host",
            "Verify local subnet interface IP and netmask",
        ],
        remediation_template=[
            "ip route replace default via {gateway_ip} dev {interface}",
        ],
        rollback_template=[
            "ip route del default via {gateway_ip} dev {interface}",
        ],
    ),
    SOPDocument(
        sop_id="SOP-BGP-004",
        title="BGP Peering Adjacency Discrepancy",
        category="BGP_SESSION_DOWN",
        keywords=["bgp", "neighbor", "adjchange", "session", "as", "peering", "tcp 179"],
        symptoms=[
            "BGP neighbor state is Active or Idle instead of Established",
            "Missing dynamic route updates across peers",
        ],
        diagnosis_steps=[
            "Run 'vtysh -c \"show ip bgp summary\"'",
            "Verify local AS and remote AS configuration match",
        ],
        remediation_template=[
            "vtysh -c 'configure terminal' -c 'router bgp {local_as}' -c 'neighbor {peer_ip} remote-as {remote_as}'",
        ],
        rollback_template=[
            "vtysh -c 'configure terminal' -c 'router bgp {local_as}' -c 'no neighbor {peer_ip}'",
        ],
    ),
    SOPDocument(
        sop_id="SOP-OVERLOAD-005",
        title="Border Gateway Buffer Overlimit and External Traffic Overload Mitigation",
        category="TRAFFIC_OVERLOAD",
        keywords=[
            "overlimits",
            "buffer",
            "qdisc",
            "tc",
            "traffic_overload",
            "packet_drop",
            "external_overload",
            "syn_flood",
            "udp_blast",
            "ddos",
        ],
        symptoms=[
            "Queue buffer overlimits or tail-drops surging on border gateway interface",
            "High volume external traffic flood saturating ingress/egress queue",
            "Packet drops observed in tc qdisc while routes remain intact",
        ],
        diagnosis_steps=[
            "Run 'tc -s qdisc show' to inspect queue drops and overlimits",
            "Run 'ip -s link show' to inspect interface hardware drop counters",
            "Analyze offending source IP, destination VIP, and ports",
        ],
        remediation_template=[
            "iptables -I FORWARD -s {source_ip} -d {destination_ip} -p {protocol} --dport {destination_port} -j DROP",
            "iptables -I FORWARD -s {source_ip} -j DROP",
        ],
        rollback_template=[
            "iptables -D FORWARD -s {source_ip} -d {destination_ip} -p {protocol} --dport {destination_port} -j DROP",
            "iptables -D FORWARD -s {source_ip} -j DROP",
        ],
    ),
]


class SOPRetriever:
    """Retrieves relevant operational SOPs matching search keywords and failure attributes."""

    def __init__(self, sops: Optional[List[SOPDocument]] = None):
        self.sops = sops or DEFAULT_SOPS

    def retrieve(self, keywords: List[str], limit: int = 3) -> List[Dict[str, Any]]:
        """Find most relevant SOPs based on keyword overlap scoring.

        Args:
            keywords: Inferred RAG search keywords from Stage 1.
            limit: Maximum SOPs to return.

        Returns:
            List of matching SOP dictionaries ordered by relevance.
        """
        kw_lower = {k.lower().strip() for k in keywords if k}
        scored_sops: List[Tuple[int, SOPDocument]] = []

        for sop in self.sops:
            sop_kws = {k.lower().strip() for k in sop.keywords}
            # Overlap score
            overlap = len(kw_lower.intersection(sop_kws))
            # Also check substring match in title/symptoms
            title_lower = sop.title.lower()
            for kw in kw_lower:
                if kw in title_lower:
                    overlap += 2

            if overlap > 0:
                scored_sops.append((overlap, sop))

        # Sort descending by score
        scored_sops.sort(key=lambda x: x[0], reverse=True)
        results = [sop.model_dump() for _, sop in scored_sops[:limit]]

        # Fallback to default routing SOP if no matches
        if not results and self.sops:
            results = [self.sops[0].model_dump()]

        return results

    @staticmethod
    def format_sop_markdown(sops: List[Dict[str, Any]]) -> str:
        """Format SOP list into markdown for LLM prompt context."""
        parts = []
        for sop in sops:
            parts.append(
                f"### {sop.get('sop_id')}: {sop.get('title')}\n"
                f"- Category: {sop.get('category')}\n"
                f"- Symptoms: {', '.join(sop.get('symptoms', []))}\n"
                f"- Recommended Remediation: {'; '.join(sop.get('remediation_template', []))}\n"
                f"- Recommended Rollback: {'; '.join(sop.get('rollback_template', []))}"
            )
        return "\n\n".join(parts)
