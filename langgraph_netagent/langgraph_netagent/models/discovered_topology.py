"""Discovered Topology and Graph Models for Dynamic Network Discovery.

Provides data structures holding dynamically discovered Containerlab network topology,
runtime interface states, IP-to-node indexes, subnet-to-nodes LPM indexes, and graph query methods.
"""

from __future__ import annotations
import collections
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field


class DiscoveredInterface(BaseModel):
    """Represents a network interface on a discovered node."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str = Field(..., description="Interface name, e.g. 'eth1'")
    ipv4_addresses: List[str] = Field(default_factory=list, description="Assigned IPv4 addresses with CIDR, e.g. ['172.16.1.1/24']")
    ipv6_addresses: List[str] = Field(default_factory=list, description="Assigned IPv6 addresses with CIDR")
    peer_node: Optional[str] = Field(default=None, description="Connected peer node name")
    peer_interface: Optional[str] = Field(default=None, description="Connected peer interface name")
    is_mgmt: bool = Field(default=False, description="True if interface is in management network")
    is_unnumbered: bool = Field(default=False, description="True if interface is unnumbered (e.g. BGP unnumbered)")
    mtu: int = Field(default=1500, description="Interface MTU")
    admin_state: str = Field(default="UP", description="Administrative state (UP/DOWN)")
    oper_state: str = Field(default="UP", description="Operational state (UP/DOWN)")


class DiscoveredNode(BaseModel):
    """Represents a discovered node in the network topology."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str = Field(..., description="Node hostname or name")
    kind: str = Field(default="linux", description="Containerlab kind ('linux', 'nokia_srlinux', etc.)")
    image: str = Field(default="", description="Container image")
    mgmt_ip: Optional[str] = Field(default=None, description="Management IP address")
    ips: List[str] = Field(default_factory=list, description="Data plane IP addresses with CIDR prefix")
    subnets: List[str] = Field(default_factory=list, description="Subnets attached to this node")
    interfaces: Dict[str, DiscoveredInterface] = Field(default_factory=dict, description="Interfaces keyed by name")
    env: Dict[str, Any] = Field(default_factory=dict, description="Environment variables declared or discovered")
    exec_cmds: List[str] = Field(default_factory=list, description="Startup or exec commands")
    role: str = Field(default="router", description="Node role (router, leaf, spine, superspine, egress, host, server, attacker, collector)")
    group: Optional[str] = Field(default=None, description="Node group or tier")
    vips: List[str] = Field(default_factory=list, description="NAT Virtual IPs mapped or hosted on this node")
    bgp_as: Optional[int] = Field(default=None, description="BGP Autonomous System number")
    static_routes: List[Dict[str, Any]] = Field(default_factory=list, description="Static routes configured on this node")
    ports: List[Union[str, int]] = Field(default_factory=list, description="Exposed port mappings")


class DiscoveredLink(BaseModel):
    """Represents a link between two node interfaces in the network."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    endpoints: List[Tuple[str, str]] = Field(..., description="List of (node, interface) tuples")
    local_node: str = Field(..., description="Local node name")
    local_iface: str = Field(..., description="Local interface name")
    remote_node: str = Field(..., description="Remote peer node name")
    remote_iface: str = Field(..., description="Remote peer interface name")
    mtu: Optional[int] = Field(default=1500, description="Link MTU")
    subnet: Optional[str] = Field(default=None, description="Subnet CIDR for link, if numbered")
    is_unnumbered: bool = Field(default=False, description="True if link operates without IPv4")


class DiscoveredTopology(BaseModel):
    """Top-level discovered network topology graph model with query helpers."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str = Field(..., description="Topology or lab name")
    mgmt_network: str = Field(default="clab", description="Management network name")
    mgmt_ipv4_subnet: Optional[str] = Field(default="172.100.100.0/24", description="Management IPv4 subnet CIDR")
    mgmt_ipv6_subnet: Optional[str] = Field(default=None, description="Management IPv6 subnet CIDR")
    nodes: Dict[str, DiscoveredNode] = Field(default_factory=dict, description="Nodes keyed by name")
    links: List[DiscoveredLink] = Field(default_factory=list, description="List of bidirectional links")

    # Dynamic Indexes
    ip_to_node: Dict[str, str] = Field(default_factory=dict, description="IP address (without CIDR) -> node name")
    subnet_to_nodes: Dict[str, List[str]] = Field(default_factory=dict, description="Subnet CIDR -> list of node names")
    subnets: List[str] = Field(default_factory=list, description="All data-plane subnets")
    node_roles: Dict[str, str] = Field(default_factory=dict, description="Node name -> role mapping")
    vips: List[str] = Field(default_factory=list, description="All virtual IPs in the topology")
    routers: List[str] = Field(default_factory=list, description="List of router/switch node names")
    hosts: List[str] = Field(default_factory=list, description="List of host/server/attacker node names")

    def find_node_by_ip(self, ip: str) -> Optional[str]:
        """Find the node that owns or hosts the given IP address.
        
        Supports exact IP matching, IP with CIDR prefix stripping,
        VIP lookup, and Longest Prefix Match (LPM) fallback.
        """
        if not ip:
            return None
        clean_ip = ip.strip()
        if "/" in clean_ip:
            clean_ip = clean_ip.split("/")[0]

        # 1. Direct index match
        if clean_ip in self.ip_to_node:
            return self.ip_to_node[clean_ip]

        # 2. Check VIPs
        for node_name, node in self.nodes.items():
            if clean_ip in node.vips:
                return node_name

        # 3. Check individual node IPs with ip_interface
        try:
            target_obj = ipaddress.ip_address(clean_ip)
            for node_name, node in self.nodes.items():
                for node_ip in node.ips:
                    try:
                        iface_obj = ipaddress.ip_interface(node_ip)
                        if iface_obj.ip == target_obj:
                            return node_name
                    except ValueError:
                        continue
        except ValueError:
            pass

        # 4. Longest Prefix Match against known subnets
        best_match_node: Optional[str] = None
        best_prefix_len = -1
        try:
            target_obj = ipaddress.ip_address(clean_ip)
            for subnet_str, nodes_list in self.subnet_to_nodes.items():
                try:
                    net_obj = ipaddress.ip_network(subnet_str, strict=False)
                    if target_obj in net_obj and net_obj.prefixlen > best_prefix_len:
                        best_prefix_len = net_obj.prefixlen
                        # Pick matching node if any
                        if nodes_list:
                            best_match_node = nodes_list[0]
                except ValueError:
                    continue
        except ValueError:
            pass

        return best_match_node

    def find_gateway_for_subnet(self, subnet: str) -> Optional[str]:
        """Find the gateway or router node that services the given subnet or IP.
        
        Prefers nodes with router/leaf/egress roles that hold an IP on the subnet.
        """
        if not subnet:
            return None
        clean_sub = subnet.strip()

        try:
            if "/" in clean_sub:
                target_net = ipaddress.ip_network(clean_sub, strict=False)
            else:
                target_ip = ipaddress.ip_address(clean_sub)
                target_net = None
        except ValueError:
            return None

        router_roles = {"router", "leaf", "egress", "spine", "superspine", "gateway"}
        candidates: List[Tuple[str, int]] = []  # (node_name, priority)

        for node_name, node in self.nodes.items():
            is_router_role = node.role.lower() in router_roles or (node.group and node.group.lower() in router_roles)
            for node_ip in node.ips:
                try:
                    iface_obj = ipaddress.ip_interface(node_ip)
                    matched = False
                    if target_net:
                        matched = iface_obj.network == target_net or iface_obj.ip in target_net
                    else:
                        matched = target_ip in iface_obj.network

                    if matched:
                        priority = 0
                        if is_router_role:
                            priority += 10
                        if iface_obj.ip == (iface_obj.network.network_address + 1):
                            # Default gateway typically ends in .1
                            priority += 5
                        candidates.append((node_name, priority))
                except ValueError:
                    continue

        if candidates:
            candidates.sort(key=lambda x: x[1], reverse=True)
            return candidates[0][0]

        # Fallback: check subnet_to_nodes
        if target_net:
            for sub_str, node_names in self.subnet_to_nodes.items():
                try:
                    if ipaddress.ip_network(sub_str, strict=False) == target_net:
                        for n in node_names:
                            if self.nodes.get(n) and self.nodes[n].role.lower() in router_roles:
                                return n
                        if node_names:
                            return node_names[0]
                except ValueError:
                    continue

        return None

    def find_router_nodes(self) -> List[str]:
        """Return a list of all router, switch, leaf, spine, and egress nodes."""
        router_roles = {"router", "leaf", "spine", "superspine", "egress", "gateway"}
        found = set(self.routers)
        for name, node in self.nodes.items():
            if node.role.lower() in router_roles or (node.group and node.group.lower() in router_roles):
                found.add(name)
        return sorted(found)

    def find_peer_interfaces(self, node: str) -> Dict[str, Tuple[str, str]]:
        """Return a mapping of local interface -> (remote_node, remote_interface) for a node."""
        result: Dict[str, Tuple[str, str]] = {}
        for link in self.links:
            if link.local_node == node:
                result[link.local_iface] = (link.remote_node, link.remote_iface)
            elif link.remote_node == node:
                result[link.remote_iface] = (link.local_node, link.local_iface)
        # Also check node.interfaces
        if node in self.nodes:
            for iface_name, iface in self.nodes[node].interfaces.items():
                if iface.peer_node and iface.peer_interface and iface_name not in result:
                    result[iface_name] = (iface.peer_node, iface.peer_interface)
        return result

    def get_node_subnets(self, node: str) -> List[str]:
        """Return all subnets associated with or configured on the specified node."""
        if node not in self.nodes:
            return []
        subnets_set = set(self.nodes[node].subnets)
        for ip in self.nodes[node].ips:
            try:
                net = str(ipaddress.ip_interface(ip).network)
                subnets_set.add(net)
            except ValueError:
                continue
        return sorted(subnets_set)

    def resolve_next_hop(self, source_node: str, dest_ip: str) -> Optional[str]:
        """Compute the next-hop IP or interface address from source_node towards dest_ip.
        
        Performs graph shortest path (BFS) from source_node to the destination node
        and extracts the IP of the adjacent node along the path.
        """
        if source_node not in self.nodes or not dest_ip:
            return None

        clean_dst = dest_ip.strip()
        if "/" in clean_dst:
            clean_dst = clean_dst.split("/")[0]

        dest_node = self.find_node_by_ip(clean_dst)
        if not dest_node:
            dest_node = self.find_gateway_for_subnet(clean_dst)

        if not dest_node or dest_node == source_node:
            return None

        # Build adjacency graph
        adj: Dict[str, List[Tuple[str, str, str]]] = collections.defaultdict(list)
        # adj[u] = [(v, u_iface, v_iface)]
        for link in self.links:
            adj[link.local_node].append((link.remote_node, link.local_iface, link.remote_iface))
            adj[link.remote_node].append((link.local_node, link.remote_iface, link.local_iface))

        # BFS from source_node to dest_node
        queue = collections.deque([(source_node, [source_node])])
        visited = {source_node}
        found_path: Optional[List[str]] = None

        while queue:
            curr, path = queue.popleft()
            if curr == dest_node:
                found_path = path
                break
            for neighbor, _, _ in adj[curr]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        if not found_path or len(found_path) < 2:
            return None

        next_hop_node = found_path[1]

        # Find the connecting link to get the interface IP on next_hop_node
        target_iface: Optional[str] = None
        for neighbor, local_iface, remote_iface in adj[source_node]:
            if neighbor == next_hop_node:
                target_iface = remote_iface
                break

        if target_iface and next_hop_node in self.nodes:
            nh_node = self.nodes[next_hop_node]
            if target_iface in nh_node.interfaces:
                intf = nh_node.interfaces[target_iface]
                if intf.ipv4_addresses:
                    return intf.ipv4_addresses[0].split("/")[0]

            # Check if any IP of next_hop_node is in the same subnet as source_node
            src_node = self.nodes[source_node]
            for src_ip in src_node.ips:
                try:
                    src_net = ipaddress.ip_interface(src_ip).network
                    for nh_ip in nh_node.ips:
                        try:
                            nh_iface = ipaddress.ip_interface(nh_ip)
                            if nh_iface.ip in src_net:
                                return str(nh_iface.ip)
                        except ValueError:
                            continue
                except ValueError:
                    continue

            # Fallback to the first data IP on next_hop_node
            if nh_node.ips:
                return nh_node.ips[0].split("/")[0]

        return next_hop_node
