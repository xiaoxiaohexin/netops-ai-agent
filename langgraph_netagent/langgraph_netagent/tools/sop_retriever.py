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
    SOPDocument(
        sop_id="SOP-SEC-ARP-001",
        title="Linux Host & Gateway L2 ARP Spoofing and Cache Poisoning Mitigation",
        category="L2_SECURITY_ARP",
        keywords=[
            "arp",
            "arp_spoofing",
            "arp_poisoning",
            "mitm",
            "ip_neigh",
            "arptables",
            "ebtables",
            "arp_ignore",
            "arp_announce",
            "rp_filter",
            "gratuitous_arp",
        ],
        symptoms=[
            "Intermittent gateway packet loss or erratic round-trip time (RTT) spikes across the local broadcast domain",
            "Gateway MAC address unexpectedly changes or flaps to an unauthorized MAC in ip neigh show",
            "Inbound or egress traffic intercepted/blackholed while the physical interface link state remains UP",
            "Kernel log messages indicating unsolicited or conflicting ARP announcements",
        ],
        diagnosis_steps=[
            "ip -s neigh show dev {interface} nud reachable stale",
            "arping -I {interface} -c 3 {gateway_ip}",
            "tcpdump -nei {interface} arp -c 30",
            "sysctl net.ipv4.conf.all.arp_ignore net.ipv4.conf.all.arp_announce net.ipv4.conf.all.rp_filter",
        ],
        remediation_template=[
            "ip neigh replace {gateway_ip} lladdr {gateway_mac} nud permanent dev {interface}",
            "sysctl -w net.ipv4.conf.all.arp_ignore=1",
            "sysctl -w net.ipv4.conf.{interface}.arp_ignore=1",
            "sysctl -w net.ipv4.conf.all.arp_announce=2",
            "sysctl -w net.ipv4.conf.{interface}.arp_announce=2",
            "sysctl -w net.ipv4.conf.all.rp_filter=1",
            "sysctl -w net.ipv4.conf.{interface}.rp_filter=1",
            "sysctl -w net.ipv4.conf.{interface}.drop_gratuitous_arp=1",
            "arptables -I INPUT -i {interface} --source-ip {gateway_ip} --source-mac ! {gateway_mac} -j DROP",
            "ebtables -I FORWARD -p ARP -i {interface} --arp-ip-src {gateway_ip} --arp-mac-src ! {gateway_mac} -j DROP",
        ],
        rollback_template=[
            "ip neigh del {gateway_ip} dev {interface}",
            "arptables -D INPUT -i {interface} --source-ip {gateway_ip} --source-mac ! {gateway_mac} -j DROP 2>/dev/null || true",
            "ebtables -D FORWARD -p ARP -i {interface} --arp-ip-src {gateway_ip} --arp-mac-src ! {gateway_mac} -j DROP 2>/dev/null || true",
            "sysctl -w net.ipv4.conf.{interface}.drop_gratuitous_arp=0",
            "sysctl -w net.ipv4.conf.{interface}.arp_ignore=0",
            "sysctl -w net.ipv4.conf.all.arp_ignore=0",
            "sysctl -w net.ipv4.conf.{interface}.arp_announce=0",
            "sysctl -w net.ipv4.conf.all.arp_announce=0",
            "sysctl -w net.ipv4.conf.{interface}.rp_filter=0",
            "sysctl -w net.ipv4.conf.all.rp_filter=0",
        ],
    ),
    SOPDocument(
        sop_id="SOP-SEC-SWITCH-002",
        title="Switch-Level Dynamic ARP Inspection (DAI), DHCP Snooping & Port Security",
        category="L2_SECURITY_SWITCH",
        keywords=[
            "switch",
            "dai",
            "dynamic_arp_inspection",
            "dhcp_snooping",
            "port_security",
            "802.1x",
            "dot1x",
            "cam_table_exhaustion",
            "arp_rate_limit",
            "mac_sticky",
        ],
        symptoms=[
            "Switch CAM/MAC address table flooding causing unicast flooding across all VLAN ports",
            "Switch CPU spikes caused by ARP processing queue exhaustion (SW_DAI syslog warnings)",
            "Rogue host answering ARP requests for IP addresses assigned to other switch ports",
        ],
        diagnosis_steps=[
            "show ip arp inspection vlan {vlan_id}",
            "show ip dhcp snooping binding",
            "show mac address-table dynamic address {target_mac}",
            "show port-security interface {access_interface}",
            "show dot1x all summary",
        ],
        remediation_template=[
            "configure terminal",
            "ip dhcp snooping",
            "ip dhcp snooping vlan {vlan_id}",
            "no ip dhcp snooping information option allow-untrusted",
            "interface {uplink_interface}",
            "ip dhcp snooping trust",
            "ip arp inspection trust",
            "exit",
            "ip arp inspection vlan {vlan_id}",
            "ip arp inspection validate src-mac dst-mac ip",
            "interface {access_interface}",
            "ip arp inspection limit rate 15 burst interval 1",
            "switchport mode access",
            "switchport port-security",
            "switchport port-security maximum 2",
            "switchport port-security violation restrict",
            "switchport port-security mac-address sticky",
            "dot1x pae authenticator",
            "authentication port-control auto",
        ],
        rollback_template=[
            "configure terminal",
            "interface {access_interface}",
            "no dot1x pae authenticator",
            "no switchport port-security",
            "no ip arp inspection limit rate",
            "exit",
            "no ip arp inspection vlan {vlan_id}",
            "interface {uplink_interface}",
            "no ip arp inspection trust",
            "no ip dhcp snooping trust",
            "exit",
            "no ip dhcp snooping vlan {vlan_id}",
            "no ip dhcp snooping",
        ],
    ),
    SOPDocument(
        sop_id="SOP-SEC-DDOS-003",
        title="Fine-Grained Netfilter L3/L4 TCP SYN Flood and Connection Starvation Mitigation",
        category="TRAFFIC_OVERLOAD",
        keywords=[
            "ddos",
            "syn_flood",
            "hashlimit",
            "connlimit",
            "syncookies",
            "rate_limiting",
            "token_bucket",
            "netfilter",
            "iptables",
            "legitimate_traffic_protection",
            "zero_collateral",
        ],
        symptoms=[
            "TCP half-open connection table saturated (SYN_RECV socket surge in ss -s)",
            "Legitimate clients experiencing connection timeouts while ping to VIP remains partially responsive",
            "Conntrack table approaching nf_conntrack_max",
            "Volumetric attack targeting port 80/443 without attacking hosts sharing legitimate client subnets",
        ],
        diagnosis_steps=[
            "ss -ant state syn-recv | wc -l",
            "sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.netfilter.nf_conntrack_count",
            "iptables -vnL FORWARD --line-numbers",
            "tcpdump -n -c 50 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'",
        ],
        remediation_template=[
            "sysctl -w net.ipv4.tcp_syncookies=1",
            "sysctl -w net.ipv4.tcp_max_syn_backlog=8192",
            "sysctl -w net.core.somaxconn=4096",
            "sysctl -w net.ipv4.tcp_synack_retries=2",
            "iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "iptables -I FORWARD 2 -s {trusted_internal_subnet} -j ACCEPT",
            "iptables -I FORWARD 3 -m conntrack --ctstate INVALID -j DROP",
            "iptables -I FORWARD 4 -p tcp --syn --dport {target_port} -m hashlimit --hashlimit-name syn_flood_lim --hashlimit-mode srcip --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-htable-expire 30000 -j DROP",
            "iptables -I FORWARD 5 -p tcp --syn --dport {target_port} -m connlimit --connlimit-above {max_conn_per_ip} --connlimit-mask 32 -j REJECT --reject-with tcp-reset",
        ],
        rollback_template=[
            "iptables -D FORWARD -p tcp --syn --dport {target_port} -m connlimit --connlimit-above {max_conn_per_ip} --connlimit-mask 32 -j REJECT --reject-with tcp-reset 2>/dev/null || true",
            "iptables -D FORWARD -p tcp --syn --dport {target_port} -m hashlimit --hashlimit-name syn_flood_lim --hashlimit-mode srcip --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-htable-expire 30000 -j DROP 2>/dev/null || true",
            "iptables -D FORWARD -m conntrack --ctstate INVALID -j DROP 2>/dev/null || true",
            "iptables -D FORWARD -s {trusted_internal_subnet} -j ACCEPT 2>/dev/null || true",
            "iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true",
            "sysctl -w net.ipv4.tcp_synack_retries=5",
            "sysctl -w net.ipv4.tcp_max_syn_backlog=1024",
        ],
    ),
    SOPDocument(
        sop_id="SOP-SEC-DDOS-004",
        title="Ingress Traffic Control (TC) Policer & Non-Destructive Bandwidth Shaping",
        category="TRAFFIC_OVERLOAD",
        keywords=[
            "tc",
            "traffic_control",
            "policer",
            "tbf",
            "token_bucket",
            "volumetric_ddos",
            "udp_flood",
            "rate_limiting",
            "bandwidth_saturation",
            "lossless_shaping",
            "frr_flowspec",
        ],
        symptoms=[
            "Tail-drops surging on WAN edge router (tc -s qdisc show reports dropped/overlimits increasing rapidly)",
            "High-volume UDP blast saturating edge link bandwidth",
            "Crucial internal protocols (BGP session, SSH, management traffic) suffering collateral drops and latency degradation",
        ],
        diagnosis_steps=[
            "tc -s qdisc show dev {interface}",
            "ip -s link show dev {interface}",
            "iftop -i {interface} -nNP -t -s 2",
            "vtysh -c 'show ip bgp summary'",
        ],
        remediation_template=[
            "tc qdisc add dev {interface} handle ffff: ingress",
            "tc filter add dev {interface} parent ffff: protocol ip prio 1 u32 match ip protocol 1 0xff action pass",
            "tc filter add dev {interface} parent ffff: protocol ip prio 2 u32 match ip protocol 6 0xff match ip dport 179 0xffff action pass",
            "tc filter add dev {interface} parent ffff: protocol ip prio 3 u32 match ip protocol 6 0xff match ip dport 22 0xffff action pass",
            "tc filter add dev {interface} parent ffff: protocol ip prio 10 u32 match ip protocol 17 0xff match ip dport {target_port} 0xffff police rate {rate_cap} burst {burst_size} drop flowid :1",
            "vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' -c 'match-action RATE_LIMIT' -c 'rate {flowspec_rate_bps}'",
        ],
        rollback_template=[
            "tc qdisc del dev {interface} handle ffff: ingress 2>/dev/null || true",
            "vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' -c 'no match-action RATE_LIMIT' 2>/dev/null || true",
        ],
    ),
    SOPDocument(
        sop_id="SOP-SEC-DHCP-005",
        title="Rogue DHCP Server Containment and DHCP Snooping Port Isolation",
        category="DHCP_SECURITY",
        keywords=[
            "dhcp",
            "rogue_dhcp",
            "dhcp_snooping",
            "untrusted_port",
            "dhcpoffer",
            "udp_67_68",
            "man_in_the_middle",
            "port_isolation",
        ],
        symptoms=[
            "Client workstations intermittently receive rogue default gateways, invalid subnets, or malicious DNS servers",
            "Sudden loss of intranet/internet reachability or internal IP address conflicts across the subnet",
            "Packet captures reveal multiple DHCPOFFER or DHCPACK packets sent by unauthorized MAC/IP addresses",
        ],
        diagnosis_steps=[
            "tcpdump -nei {interface} 'udp and (port 67 or port 68)' -v -c 15",
            "dhcping -c {test_client_ip} -s {suspected_rogue_server_ip} -h {client_mac}",
            "show ip dhcp snooping statistics",
        ],
        remediation_template=[
            "configure terminal",
            "ip dhcp snooping",
            "ip dhcp snooping vlan {vlan_id}",
            "interface {legitimate_dhcp_uplink}",
            "ip dhcp snooping trust",
            "interface range {all_access_interfaces}",
            "no ip dhcp snooping trust",
            "iptables -I FORWARD -i {untrusted_interface} -p udp --sport 67 --dport 68 -j DROP",
            "iptables -I INPUT -i {untrusted_interface} -p udp --sport 67 --dport 68 -j DROP",
            "ebtables -I FORWARD -i {untrusted_interface} -p IPv4 --ip-proto udp --ip-sport 67 --ip-dport 68 -j DROP",
        ],
        rollback_template=[
            "iptables -D FORWARD -i {untrusted_interface} -p udp --sport 67 --dport 68 -j DROP 2>/dev/null || true",
            "iptables -D INPUT -i {untrusted_interface} -p udp --sport 67 --dport 68 -j DROP 2>/dev/null || true",
            "ebtables -D FORWARD -i {untrusted_interface} -p IPv4 --ip-proto udp --ip-sport 67 --ip-dport 68 -j DROP 2>/dev/null || true",
            "configure terminal",
            "no ip dhcp snooping vlan {vlan_id}",
            "no ip dhcp snooping",
        ],
    ),
    SOPDocument(
        sop_id="SOP-SEC-DHCP-006",
        title="DHCP Starvation and Pool Exhaustion Defense",
        category="DHCP_SECURITY",
        keywords=[
            "dhcp",
            "dhcp_starvation",
            "pool_exhaustion",
            "dhcp_snooping_rate_limit",
            "port_security",
            "chaddr_spoofing",
            "hashlimit",
            "udp_67",
        ],
        symptoms=[
            "DHCP server pool completely drained (zero available IP leases remaining in lease database)",
            "Legitimate new hosts cannot acquire leases (DHCPDISCOVER packets time out without DHCPOFFER)",
            "Influx of hundreds of DHCPDISCOVER frames per second with randomized client MACs (CHADDR spoofing)",
        ],
        diagnosis_steps=[
            "dhcpd-pools -c /etc/dhcp/dhcpd.conf -l /var/lib/dhcp/dhcpd.leases",
            "tcpdump -nei {interface} 'udp port 67' -c 30",
            "show ip dhcp snooping binding",
            "show errdisable detect",
        ],
        remediation_template=[
            "configure terminal",
            "interface range {access_ports}",
            "ip dhcp snooping limit rate 15",
            "switchport port-security",
            "switchport port-security maximum 2",
            "switchport port-security violation restrict",
            "exit",
            "errdisable recovery cause dhcpsnoop-rate-limit",
            "errdisable recovery interval 30",
            "iptables -I INPUT -p udp --dport 67 -m hashlimit --hashlimit-name dhcp_rate_lim --hashlimit-mode srcmac --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-htable-expire 15000 -j DROP",
        ],
        rollback_template=[
            "iptables -D INPUT -p udp --dport 67 -m hashlimit --hashlimit-name dhcp_rate_lim --hashlimit-mode srcmac --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-htable-expire 15000 -j DROP 2>/dev/null || true",
            "configure terminal",
            "interface range {access_ports}",
            "no ip dhcp snooping limit rate",
            "no switchport port-security",
            "no errdisable recovery cause dhcpsnoop-rate-limit",
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
