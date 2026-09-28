"""In-Memory Virtual Network Graph and Mock Containerlab Adapter."""

from __future__ import annotations
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import yaml

from langgraph_netagent.models.telemetry import RouteEntry
from langgraph_netagent.models.topology import ContainerlabTopologyFile, DeviceConfigFile, FullTopologyPackage
from langgraph_netagent.tools.base import (
    BaseNetworkLabAdapter,
    CommandResult,
    DeploymentResult,
    DestructionResult,
    LabInspectionResult,
    LabNodeState,
)
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType


class VirtualInterface:
    """Virtual network interface on a mock node."""

    def __init__(
        self,
        name: str,
        ip_cidr: Optional[str] = None,
        admin_state: str = "UP",
        oper_state: str = "UP",
        peer_node: Optional[str] = None,
        peer_interface: Optional[str] = None,
        mtu: int = 1500,
        mac_address: Optional[str] = None,
    ):
        self.name = name
        self.ip_cidr = ip_cidr
        self.admin_state = admin_state
        self.oper_state = oper_state
        self.peer_node = peer_node
        self.peer_interface = peer_interface
        self.mtu = mtu
        self.mac_address = mac_address or f"00:16:3e:{hash(name) % 256:02x}:01:02"

    @property
    def ip_address(self) -> Optional[str]:
        if self.ip_cidr:
            return self.ip_cidr.split("/")[0]
        return None

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        if self.ip_cidr:
            try:
                return ipaddress.IPv4Interface(self.ip_cidr).network
            except Exception:
                return None
        return None


class VirtualNode:
    """Virtual network device node in the mock engine."""

    def __init__(
        self,
        name: str,
        kind: str = "linux",
        image: str = "alpine:latest",
    ):
        self.name = name
        self.kind = kind
        self.image = image
        self.interfaces: Dict[str, VirtualInterface] = {}
        self.routes: List[RouteEntry] = []
        self.default_gateway: Optional[str] = None
        self.state: str = "running"

    def add_interface(self, iface: VirtualInterface) -> None:
        self.interfaces[iface.name] = iface

    def get_interface(self, iface_name: str) -> Optional[VirtualInterface]:
        return self.interfaces.get(iface_name)

    def add_route(self, route: RouteEntry) -> None:
        # Avoid duplicate destination
        self.routes = [r for r in self.routes if r.destination != route.destination]
        self.routes.append(route)
        if route.destination == "default" or route.destination == "0.0.0.0/0":
            self.default_gateway = route.next_hop


class VirtualNetworkGraph:
    """In-memory representation of nodes, interfaces, links, and IP allocation."""

    def __init__(self):
        self.lab_name: str = "mock-lab"
        self.nodes: Dict[str, VirtualNode] = {}
        self.links: List[Tuple[str, str, str, str]] = []  # (n1, if1, n2, if2)
        self.ip_to_node: Dict[str, Tuple[str, str]] = {}  # ip -> (node_name, iface_name)

    def clear(self) -> None:
        self.nodes.clear()
        self.links.clear()
        self.ip_to_node.clear()

    def add_node(self, node: VirtualNode) -> None:
        self.nodes[node.name] = node

    def add_link(self, node1: str, iface1: str, node2: str, iface2: str) -> None:
        self.links.append((node1, iface1, node2, iface2))
        if node1 in self.nodes and iface1 in self.nodes[node1].interfaces:
            self.nodes[node1].interfaces[iface1].peer_node = node2
            self.nodes[node1].interfaces[iface1].peer_interface = iface2
        if node2 in self.nodes and iface2 in self.nodes[node2].interfaces:
            self.nodes[node2].interfaces[iface2].peer_node = node1
            self.nodes[node2].interfaces[iface2].peer_interface = iface1

    def register_ip(self, ip_cidr: str, node_name: str, iface_name: str) -> None:
        ip_only = ip_cidr.split("/")[0].strip()
        self.ip_to_node[ip_only] = (node_name, iface_name)
        if node_name in self.nodes:
            node = self.nodes[node_name]
            if iface_name in node.interfaces:
                node.interfaces[iface_name].ip_cidr = ip_cidr
            else:
                iface = VirtualInterface(name=iface_name, ip_cidr=ip_cidr)
                node.add_interface(iface)


class MockEngine:
    """Simulates network operations, routing lookups, and ping reachability."""

    def __init__(self, fault_injector: Optional[FaultInjector] = None):
        self.graph = VirtualNetworkGraph()
        self.fault_injector = fault_injector or FaultInjector()
        self.deployed_configs: Dict[str, str] = {}

    def load_topology_package(self, package: FullTopologyPackage) -> None:
        """Load from a FullTopologyPackage."""
        self.load_topology(
            topo_data=package.topology,
            configs=package.configs,
            ip_allocations=package.ip_allocations,
        )

    def load_topology(
        self,
        topo_data: Union[str, Path, dict, ContainerlabTopologyFile],
        config_dir: Optional[Path] = None,
        configs: Optional[List[DeviceConfigFile]] = None,
        ip_allocations: Optional[List[Any]] = None,
    ) -> None:
        """Parse topology and node configuration files into the virtual graph."""
        self.graph.clear()

        # Parse root topology object
        if isinstance(topo_data, ContainerlabTopologyFile):
            topo_dict = topo_data.model_dump(by_alias=True)
        elif isinstance(topo_data, dict):
            topo_dict = topo_data
        else:
            p = Path(topo_data)
            if p.exists() and p.is_file():
                if config_dir is None:
                    config_dir = p.parent
                with open(p, "r", encoding="utf-8") as f:
                    topo_dict = yaml.safe_load(f)
            else:
                topo_dict = yaml.safe_load(str(topo_data))

        self.graph.lab_name = topo_dict.get("name", "lab")
        inner_topo = topo_dict.get("topology", {})
        nodes_dict = inner_topo.get("nodes", {})
        links_list = inner_topo.get("links", [])

        # 1. Initialize Virtual Nodes and track declared config files
        node_file_map: Dict[str, List[str]] = {}
        for name, n_conf in nodes_dict.items():
            kind = n_conf.get("kind", "linux")
            img = n_conf.get("image", "alpine:latest")
            v_node = VirtualNode(name=name, kind=kind, image=img)
            self.graph.add_node(v_node)

            node_files: List[str] = []
            binds = n_conf.get("binds", [])
            for b in binds:
                host_path = b.split(":")[0].strip().replace("\\", "/")
                node_files.append(host_path)
            startup_cfg = n_conf.get("startup_config") or n_conf.get("startup-config")
            if startup_cfg:
                node_files.append(str(startup_cfg).strip().replace("\\", "/"))
            node_file_map[name] = node_files

        # 2. Add Links and initialize interfaces
        for l in links_list:
            eps = l.get("endpoints", []) if isinstance(l, dict) else getattr(l, "endpoints", [])
            if len(eps) == 2:
                n1, if1 = eps[0].split(":", 1)
                n2, if2 = eps[1].split(":", 1)
                if n1 in self.graph.nodes and if1 not in self.graph.nodes[n1].interfaces:
                    self.graph.nodes[n1].add_interface(VirtualInterface(name=if1))
                if n2 in self.graph.nodes and if2 not in self.graph.nodes[n2].interfaces:
                    self.graph.nodes[n2].add_interface(VirtualInterface(name=if2))
                self.graph.add_link(n1, if1, n2, if2)

        # 3. Incorporate explicit IP allocations if provided
        if ip_allocations:
            for alloc in ip_allocations:
                if isinstance(alloc, dict):
                    n_name = alloc.get("node_name")
                    if_name = alloc.get("interface_name")
                    ip_addr = alloc.get("ipv4_address")
                    gw = alloc.get("gateway_ipv4")
                else:
                    n_name = getattr(alloc, "node_name", None)
                    if_name = getattr(alloc, "interface_name", None)
                    ip_addr = getattr(alloc, "ipv4_address", None)
                    gw = getattr(alloc, "gateway_ipv4", None)
                if n_name and if_name and ip_addr:
                    self.graph.register_ip(ip_addr, n_name, if_name)
                    if gw and n_name in self.graph.nodes:
                        self.graph.nodes[n_name].default_gateway = gw
                        self.graph.nodes[n_name].add_route(
                            RouteEntry(destination="default", next_hop=gw, interface=if_name, protocol="static")
                        )

        # 4. Parse config files from DeviceConfigFile list or directory
        parsed_configs: Dict[str, str] = {}
        if configs:
            for c in configs:
                parsed_configs[c.file_path] = c.content
                self._parse_node_config_content(c.node_name, c.file_path, c.content)
        elif config_dir and Path(config_dir).exists():
            cfg_base = Path(config_dir)
            for f in cfg_base.glob("**/*"):
                if f.is_file() and not f.name.endswith(".clab.yml"):
                    rel_path = str(f.relative_to(cfg_base)).replace("\\", "/")
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")
                        parsed_configs[rel_path] = content
                        
                        # Match node using explicit declared file map or path naming
                        matched_node = None
                        for node_name, expected_files in node_file_map.items():
                            for exp in expected_files:
                                if rel_path.endswith(exp) or exp.endswith(rel_path):
                                    matched_node = node_name
                                    break
                            if matched_node:
                                break

                        if not matched_node:
                            for node_name in self.graph.nodes:
                                base_name = node_name.rstrip("0123456789")
                                if (
                                    f"/{node_name}/" in f"/{rel_path}/"
                                    or rel_path.startswith(f"{node_name}/")
                                    or f"/{base_name}/" in f"/{rel_path}/"
                                    or rel_path.startswith(f"{base_name}/")
                                ):
                                    matched_node = node_name
                                    break

                        if matched_node:
                            self._parse_node_config_content(matched_node, rel_path, content)
                    except Exception:
                        pass

        self.deployed_configs = parsed_configs

        # 5. Populate connected subnet routes for all interfaces with IPs
        for node in self.graph.nodes.values():
            for iface in node.interfaces.values():
                if iface.ip_cidr:
                    try:
                        net = ipaddress.IPv4Interface(iface.ip_cidr).network
                        net_str = str(net)
                        # Add connected route
                        node.add_route(
                            RouteEntry(destination=net_str, next_hop=None, interface=iface.name, protocol="connected")
                        )
                    except Exception:
                        pass

    def _parse_node_config_content(self, node_name: str, file_path: str, content: str) -> None:
        """Extract IP addresses and static routes from setup.sh, frr.conf, or srl.cfg."""
        if node_name not in self.graph.nodes:
            return
        node = self.graph.nodes[node_name]

        # Alpine Linux setup.sh
        if file_path.endswith(".sh") or "setup.sh" in file_path:
            # Match ip addr add <ip/mask> dev <iface>
            for match in re.finditer(r"ip\s+addr\s+add\s+([0-9\./]+)\s+dev\s+([a-zA-Z0-9_\-]+)", content):
                ip_cidr = match.group(1)
                iface_name = match.group(2)
                self.graph.register_ip(ip_cidr, node_name, iface_name)

            # Match ip route replace/add default via <gw> [dev <iface>]
            gw_match = re.search(r"ip\s+route\s+(?:replace|add)\s+default\s+via\s+([0-9\.]+)(?:\s+dev\s+([a-zA-Z0-9_\-]+))?", content)
            if gw_match:
                gw = gw_match.group(1)
                dev = gw_match.group(2) or "eth1"
                node.default_gateway = gw
                node.add_route(RouteEntry(destination="default", next_hop=gw, interface=dev, protocol="static"))

            # Match generic ip route add <pfx> via <gw>
            for r_match in re.finditer(r"ip\s+route\s+(?:replace|add)\s+([0-9\./]+)\s+via\s+([0-9\.]+)(?:\s+dev\s+([a-zA-Z0-9_\-]+))?", content):
                pfx = r_match.group(1)
                gw = r_match.group(2)
                dev = r_match.group(3)
                if pfx != "default":
                    node.add_route(RouteEntry(destination=pfx, next_hop=gw, interface=dev, protocol="static"))

        # FRRouting frr.conf
        elif "frr.conf" in file_path:
            current_iface = None
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("interface "):
                    current_iface = line.split()[1]
                elif line.startswith("ip address ") and current_iface:
                    ip_cidr = line.split()[2]
                    self.graph.register_ip(ip_cidr, node_name, current_iface)
                elif line.startswith("ip route "):
                    parts = line.split()
                    if len(parts) >= 4:
                        pfx = parts[2]
                        gw = parts[3]
                        node.add_route(RouteEntry(destination=pfx, next_hop=gw, protocol="static"))

        # Nokia SR Linux srl.cfg
        elif "srl.cfg" in file_path or file_path.endswith(".cfg"):
            for match in re.finditer(r"interface\s+([a-zA-Z0-9_\-]+).*?ipv4\s+address\s+([0-9\./]+)", content, re.DOTALL):
                iface_name = match.group(1)
                ip_cidr = match.group(2)
                self.graph.register_ip(ip_cidr, node_name, iface_name)

            for r_match in re.finditer(r"static-route\s+([0-9\./]+).*?next-hop\s+([0-9\.]+)", content, re.DOTALL):
                pfx = r_match.group(1)
                gw = r_match.group(2)
                node.add_route(RouteEntry(destination=pfx, next_hop=gw, protocol="static"))

    def _get_egress_interface(self, node_name: str, dst_ip: str) -> Optional[str]:
        """Find the local egress interface on node_name towards dst_ip using LPM."""
        node = self.graph.nodes.get(node_name)
        if not node:
            return None
        try:
            target_addr = ipaddress.IPv4Address(dst_ip)
        except Exception:
            return None

        best_pfx_len = -1
        best_iface_name: Optional[str] = None
        best_is_connected = False

        # 1. Connected interfaces
        for iface in node.interfaces.values():
            if iface.network and target_addr in iface.network:
                net_str = str(iface.network)
                if not self.fault_injector.should_suppress_route(node_name, net_str):
                    pfx_len = iface.network.prefixlen
                    if pfx_len > best_pfx_len or (pfx_len == best_pfx_len and not best_is_connected):
                        best_pfx_len = pfx_len
                        best_iface_name = iface.name
                        best_is_connected = True

        # 2. Configured routes
        for route in node.routes:
            dest_str = route.destination
            if self.fault_injector.should_suppress_route(node_name, dest_str):
                continue
            if route.protocol == "connected" or not route.next_hop:
                continue

            matched = False
            pfx = -1
            if dest_str in ("default", "0.0.0.0/0"):
                matched = True
                pfx = 0
            else:
                try:
                    net = ipaddress.IPv4Network(dest_str)
                    if target_addr in net:
                        matched = True
                        pfx = net.prefixlen
                except Exception:
                    pass

            if matched and pfx > best_pfx_len:
                egr = route.interface
                if not egr and route.next_hop:
                    try:
                        nh_addr = ipaddress.IPv4Address(route.next_hop)
                        for ifc in node.interfaces.values():
                            if ifc.network and nh_addr in ifc.network:
                                egr = ifc.name
                                break
                    except Exception:
                        pass
                if egr:
                    best_pfx_len = pfx
                    best_iface_name = egr
                    best_is_connected = False

        return best_iface_name

    def simulate_ping(
        self,
        src_node: str,
        dst_ip: str,
        count: int = 3,
        timeout: int = 2,
    ) -> CommandResult:
        """Simulate ping forwarding hop-by-hop through the virtual network graph."""
        cmd = f"ping -c {count} -W {timeout} {dst_ip}"

        # 1. Check direct fault injection rule for ping
        rule = self.fault_injector.should_drop_ping(src_node=src_node, dst_ip=dst_ip)
        if rule:
            if rule.loss_pct >= 100.0:
                err_msg = rule.error_message or "Destination Net Unreachable"
                stdout = self._render_failed_ping(dst_ip=dst_ip, count=count, err_msg=err_msg)
                return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)
            else:
                stdout = self._render_partial_loss_ping(dst_ip=dst_ip, count=count, loss_pct=rule.loss_pct)
                return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=src_node)

        # 2. Validate source node existence
        if src_node not in self.graph.nodes:
            stderr = f"Error: source node '{src_node}' not found in virtual lab"
            return CommandResult(command=cmd, exit_code=1, stdout="", stderr=stderr, node=src_node)

        # 3. Check if target IP exists in the network
        dst_clean = dst_ip.split("/")[0].strip()
        if dst_clean not in self.graph.ip_to_node:
            stdout = self._render_failed_ping(dst_ip=dst_clean, count=count, err_msg="Destination Host Unreachable")
            return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)

        dst_node_name, dst_iface_name = self.graph.ip_to_node[dst_clean]

        # 4. Check interface down on source or destination
        src_node_obj = self.graph.nodes[src_node]
        src_egress_iface = self._get_egress_interface(src_node, dst_clean)
        if src_egress_iface:
            if self.fault_injector.is_interface_down(src_node, src_egress_iface):
                stdout = self._render_failed_ping(dst_ip=dst_clean, count=count, err_msg="Network is unreachable")
                return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)
        elif src_node_obj.interfaces and all(self.fault_injector.is_interface_down(src_node, ifc.name) for ifc in src_node_obj.interfaces.values()):
            stdout = self._render_failed_ping(dst_ip=dst_clean, count=count, err_msg="Network is unreachable")
            return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)

        dst_node_obj = self.graph.nodes.get(dst_node_name)
        if not dst_node_obj:
            stdout = self._render_failed_ping(dst_ip=dst_clean, count=count, err_msg="Destination Host Unreachable")
            return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)

        if self.fault_injector.is_interface_down(dst_node_name, dst_iface_name):
            stdout = self._render_failed_ping(dst_ip=dst_clean, count=count, err_msg="Destination Host Unreachable")
            return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)

        # 5. Hop-by-hop forward path evaluation
        fwd_ok, fwd_err, transit_nodes = self._trace_path(src_node=src_node, dst_ip=dst_clean)
        if not fwd_ok:
            err_text = "Destination Net Unreachable"
            if fwd_err and "down" in fwd_err.lower():
                err_text = f"Destination Net Unreachable ({fwd_err})"
            elif fwd_err and "loop" in fwd_err.lower():
                err_text = "Time to live exceeded"
            stdout = self._render_failed_ping(dst_ip=dst_clean, count=count, err_msg=err_text)
            return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)

        # 6. Hop-by-hop return path evaluation from dst_node back to src_node IP
        src_ip = None
        if src_egress_iface and src_egress_iface in src_node_obj.interfaces:
            src_ip = src_node_obj.interfaces[src_egress_iface].ip_address

        if not src_ip:
            for iface in src_node_obj.interfaces.values():
                if iface.ip_address:
                    src_ip = iface.ip_address
                    break

        if src_ip:
            ret_ok, ret_err, _ = self._trace_path(src_node=dst_node_name, dst_ip=src_ip)
            if not ret_ok:
                stdout = self._render_failed_ping(dst_ip=dst_clean, count=count, err_msg="100% packet loss (return path missing)")
                return CommandResult(command=cmd, exit_code=1, stdout=stdout, stderr="", node=src_node)

        # 7. Success: All paths healthy
        hops = len(transit_nodes)
        ttl = max(64 - hops, 1)
        stdout = self._render_successful_ping(dst_ip=dst_clean, count=count, ttl=ttl)
        return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=src_node)

    def _trace_path(self, src_node: str, dst_ip: str) -> Tuple[bool, Optional[str], List[str]]:
        """Trace hop-by-hop routing from src_node to destination IP."""
        current_node_name = src_node
        visited = []
        try:
            target_addr = ipaddress.IPv4Address(dst_ip)
        except Exception:
            return False, f"Invalid destination IP {dst_ip}", visited

        for _ in range(15):  # Max 15 hops
            visited.append(current_node_name)
            current_node = self.graph.nodes.get(current_node_name)
            if not current_node:
                return False, f"Node {current_node_name} missing", visited

            # 1. Check if this node directly owns the destination IP
            for iface in current_node.interfaces.values():
                if iface.ip_address == dst_ip:
                    return True, None, visited

            # 2. LPM Candidate Selection across connected subnets and configured routes
            best_pfx_len = -1
            best_is_connected = False
            best_iface: Optional[VirtualInterface] = None
            best_match: Optional[RouteEntry] = None

            # 2a. Connected subnets
            for iface in current_node.interfaces.values():
                if iface.network and target_addr in iface.network:
                    net_str = str(iface.network)
                    if self.fault_injector.should_suppress_route(current_node_name, net_str):
                        continue
                    pfx_len = iface.network.prefixlen
                    # Connected routes win over static routes on tie (lower administrative distance)
                    if pfx_len > best_pfx_len or (pfx_len == best_pfx_len and not best_is_connected):
                        best_pfx_len = pfx_len
                        best_is_connected = True
                        best_iface = iface
                        best_match = None

            # 2b. Configured routes in current_node.routes
            for route in current_node.routes:
                dest_str = route.destination
                if self.fault_injector.should_suppress_route(current_node_name, dest_str):
                    continue

                if route.protocol == "connected" or not route.next_hop:
                    continue

                if dest_str in ("default", "0.0.0.0/0"):
                    if best_pfx_len < 0:
                        best_pfx_len = 0
                        best_is_connected = False
                        best_iface = None
                        best_match = route
                else:
                    try:
                        net = ipaddress.IPv4Network(dest_str)
                        if target_addr in net and net.prefixlen > best_pfx_len:
                            best_pfx_len = net.prefixlen
                            best_is_connected = False
                            best_iface = None
                            best_match = route
                    except Exception:
                        pass

            # 3. Process best LPM match
            if best_is_connected and best_iface is not None:
                if self.fault_injector.is_interface_down(current_node_name, best_iface.name):
                    return False, f"Interface {best_iface.name} down on {current_node_name}", visited
                target_owner, target_iface = self.graph.ip_to_node.get(dst_ip, (None, None))
                if target_owner:
                    if target_iface and self.fault_injector.is_interface_down(target_owner, target_iface):
                        return False, f"Interface {target_iface} down on {target_owner}", visited
                    visited.append(target_owner)
                    return True, None, visited
                else:
                    return False, f"Destination host {dst_ip} unreachable from {current_node_name}", visited

            if not best_match or not best_match.next_hop:
                return False, f"Missing route to {dst_ip} on {current_node_name}", visited

            nh_ip = best_match.next_hop
            nh_owner, nh_iface = self.graph.ip_to_node.get(nh_ip, (None, None))
            if not nh_owner:
                return False, f"Next-hop {nh_ip} unreachable from {current_node_name}", visited

            # Determine local egress interface towards next-hop
            egress_iface = best_match.interface
            if not egress_iface:
                try:
                    nh_addr = ipaddress.IPv4Address(nh_ip)
                    for ifc in current_node.interfaces.values():
                        if ifc.network and nh_addr in ifc.network:
                            egress_iface = ifc.name
                            break
                except Exception:
                    pass

            # Check transit interfaces down
            if (egress_iface and self.fault_injector.is_interface_down(current_node_name, egress_iface)) or (
                nh_owner and nh_iface and self.fault_injector.is_interface_down(nh_owner, nh_iface)
            ):
                return False, f"Transit interface down between {current_node_name}:{egress_iface} and {nh_owner}:{nh_iface}", visited

            # Check for forwarding loops
            if nh_owner in visited:
                return False, f"Routing loop detected between {current_node_name} and {nh_owner}", visited

            current_node_name = nh_owner

        return False, "TTL exceeded / hop limit reached", visited

    def simulate_ip_route(self, node_name: str, cmd: str) -> CommandResult:
        """Generate realistic route table output for Linux or FRR."""
        if node_name not in self.graph.nodes:
            return CommandResult(command=cmd, exit_code=1, stderr=f"Node {node_name} not found", node=node_name)

        node = self.graph.nodes[node_name]
        lines = []

        # Default route first if present
        for r in node.routes:
            if self.fault_injector.should_suppress_route(node_name, r.destination):
                continue
            if r.destination in ("default", "0.0.0.0/0") and r.next_hop:
                dev = r.interface or "eth1"
                lines.append(f"default via {r.next_hop} dev {dev}")

        # Subnet routes
        for r in node.routes:
            if self.fault_injector.should_suppress_route(node_name, r.destination):
                continue
            if r.destination not in ("default", "0.0.0.0/0"):
                dev = r.interface or "eth1"
                if r.next_hop:
                    lines.append(f"{r.destination} via {r.next_hop} dev {dev} proto static")
                else:
                    src_ip = ""
                    for ifc in node.interfaces.values():
                        if ifc.ip_address and ifc.network and ipaddress.IPv4Address(ifc.ip_address) in ipaddress.IPv4Network(r.destination):
                            src_ip = f" src {ifc.ip_address}"
                            break
                    lines.append(f"{r.destination} dev {dev} proto kernel scope link{src_ip}")

        stdout = "\n".join(lines) + "\n"
        return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=node_name)

    def simulate_vtysh_command(self, node_name: str, cmd: str) -> CommandResult:
        """Simulate FRR vtysh commands (e.g. 'show ip route json', 'show ip route')."""
        if node_name not in self.graph.nodes:
            return CommandResult(command=cmd, exit_code=1, stderr=f"Node {node_name} not found", node=node_name)

        node = self.graph.nodes[node_name]

        if "json" in cmd:
            # Build JSON route structure
            routes_data: Dict[str, Any] = {}
            for r in node.routes:
                if self.fault_injector.should_suppress_route(node_name, r.destination):
                    continue
                routes_data[r.destination] = [
                    {
                        "prefix": r.destination,
                        "protocol": r.protocol or "static",
                        "nexthops": [
                            {
                                "ip": r.next_hop or "0.0.0.0",
                                "interfaceName": r.interface or "eth1",
                                "active": True,
                            }
                        ],
                    }
                ]
            stdout = json.dumps(routes_data, indent=2) + "\n"
            return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=node_name)
        else:
            # Text output
            lines = [
                "Codes: K - kernel route, C - connected, S - static, O - OSPF, B - BGP",
                "",
            ]
            for r in node.routes:
                if self.fault_injector.should_suppress_route(node_name, r.destination):
                    continue
                if r.next_hop:
                    lines.append(f"S>* {r.destination} [1/0] via {r.next_hop}, {r.interface or 'eth1'}")
                else:
                    lines.append(f"C>* {r.destination} is directly connected, {r.interface or 'eth1'}")
            stdout = "\n".join(lines) + "\n"
            return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=node_name)

    def simulate_srl_command(self, node_name: str, cmd: str) -> CommandResult:
        """Simulate Nokia SR Linux sr_cli route table output."""
        if node_name not in self.graph.nodes:
            return CommandResult(command=cmd, exit_code=1, stderr=f"Node {node_name} not found", node=node_name)

        node = self.graph.nodes[node_name]
        lines = [
            "-------------------------------------------------------------------",
            "Network-instance : default",
            "-------------------------------------------------------------------",
            f"{'IPv4 Prefix':<20} {'Type':<12} {'Next-hop':<18} {'Interface':<12}",
            "-------------------------------------------------------------------",
        ]
        for r in node.routes:
            if self.fault_injector.should_suppress_route(node_name, r.destination):
                continue
            pfx = r.destination
            rtype = r.protocol or "static"
            nh = r.next_hop or "direct"
            ifc = r.interface or "e1-1"
            lines.append(f"{pfx:<20} {rtype:<12} {nh:<18} {ifc:<12}")
        stdout = "\n".join(lines) + "\n"
        return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=node_name)

    def simulate_ip_addr(self, node_name: str, cmd: str) -> CommandResult:
        """Generate realistic `ip addr show` output."""
        if node_name not in self.graph.nodes:
            return CommandResult(command=cmd, exit_code=1, stderr=f"Node {node_name} not found", node=node_name)

        node = self.graph.nodes[node_name]
        lines = [
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN",
            "    inet 127.0.0.1/8 scope host lo",
        ]
        idx = 2
        for iface in node.interfaces.values():
            is_down = bool(self.fault_injector.is_interface_down(node_name, iface.name))
            state = "DOWN" if is_down else iface.oper_state
            flags = "<BROADCAST,MULTICAST>" if is_down else "<BROADCAST,MULTICAST,UP,LOWER_UP>"
            lines.append(f"{idx}: {iface.name}: {flags} mtu {iface.mtu} qdisc fq_codel state {state}")
            lines.append(f"    link/ether {iface.mac_address} brd ff:ff:ff:ff:ff:ff")
            if iface.ip_cidr:
                ip_only = iface.ip_cidr.split("/")[0]
                lines.append(f"    inet {iface.ip_cidr} scope global {iface.name}")
            idx += 1

        stdout = "\n".join(lines) + "\n"
        return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=node_name)

    def simulate_tc_command(self, node_name: str, cmd: str) -> CommandResult:
        """Simulate Linux traffic control (tc) command output."""
        if node_name not in self.graph.nodes:
            return CommandResult(
                command=cmd,
                exit_code=1,
                stderr=f"Error: node '{node_name}' not found",
                node=node_name,
            )

        node = self.graph.nodes[node_name]
        m_dev = re.search(r"\bdev\s+([a-zA-Z0-9_\-\.]+)", cmd)
        req_dev = m_dev.group(1) if m_dev else None

        rule = self.fault_injector.get_buffer_overlimit(node=node_name, interface=req_dev)

        lines: List[str] = []
        if req_dev:
            target_ifaces = [req_dev]
        elif node.interfaces:
            target_ifaces = [ifc for ifc in node.interfaces.keys() if not ifc.startswith("lo")] or ["eth1"]
        else:
            target_ifaces = ["eth1"]

        for iface_name in target_ifaces:
            if rule and (not rule.target_interface or rule.target_interface == iface_name):
                dropped = rule.dropped
                overlimits = rule.overlimits
                lines.append(f"qdisc netem 1: dev {iface_name} root refcnt 17 limit 1000 delay 8.0ms 1.0ms")
                lines.append(f" Sent 426714991 bytes 4281816 pkt (dropped 0, overlimits 0 requeues 0)")
                lines.append(f" backlog 0b 0p requeues 0")
                lines.append(f"qdisc tbf 10: dev {iface_name} parent 1: rate 50Mbit burst 2Kb lat 4.9ms")
                lines.append(f" Sent 426714991 bytes 4281816 pkt (dropped {dropped}, overlimits {overlimits} requeues 0)")
                lines.append(f" backlog 0b 0p requeues 0")
            else:
                lines.append(f"qdisc fq_codel 0: dev {iface_name} root refcnt 2 limit 10240p flows 1024 quantum 1514")
                lines.append(f" Sent 1024 bytes 12 pkt (dropped 0, overlimits 0 requeues 0)")
                lines.append(f" backlog 0b 0p requeues 0")

        stdout = "\n".join(lines) + "\n"
        return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=node_name)

    def simulate_ip_link_stats(self, node_name: str, cmd: str) -> CommandResult:
        """Simulate `ip -s link show` output with packet and drop counters."""
        if node_name not in self.graph.nodes:
            return CommandResult(command=cmd, exit_code=1, stderr=f"Node {node_name} not found", node=node_name)

        node = self.graph.nodes[node_name]
        lines = [
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000",
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
            "    RX:  bytes packets errors dropped missed mcast",
            "          1234      10      0       0      0     0",
            "    TX:  bytes packets errors dropped carrier collsns",
            "          1234      10      0       0       0       0",
        ]
        idx = 2
        for iface in node.interfaces.values():
            is_down = bool(self.fault_injector.is_interface_down(node_name, iface.name))
            state = "DOWN" if is_down else iface.oper_state
            flags = "<BROADCAST,MULTICAST>" if is_down else "<BROADCAST,MULTICAST,UP,LOWER_UP>"
            rule = self.fault_injector.get_buffer_overlimit(node=node_name, interface=iface.name)
            rx_drop = 0
            tx_drop = rule.dropped if rule else 0

            lines.append(f"{idx}: {iface.name}: {flags} mtu {iface.mtu} qdisc fq_codel state {state} mode DEFAULT group default qlen 1000")
            lines.append(f"    link/ether {iface.mac_address} brd ff:ff:ff:ff:ff:ff")
            lines.append("    RX:  bytes packets errors dropped missed mcast")
            lines.append(f"        {50000}     {500}      0       {rx_drop}      0     0")
            lines.append("    TX:  bytes packets errors dropped carrier collsns")
            lines.append(f"        {60000}     {600}      0       {tx_drop}       0       0")
            idx += 1

        stdout = "\n".join(lines) + "\n"
        return CommandResult(command=cmd, exit_code=0, stdout=stdout, stderr="", node=node_name)

    def simulate_iptables_command(self, node_name: str, cmd: str) -> CommandResult:
        """Simulate iptables command execution and auto-clear resolved buffer overlimits."""
        if node_name not in self.graph.nodes and not node_name.startswith("sandbox_"):
            return CommandResult(command=cmd, exit_code=1, stderr=f"Node {node_name} not found", node=node_name)

        # Live execution on the real node clears the fault rule
        if not node_name.startswith("sandbox_"):
            self.fault_injector.on_remediation(command=cmd, node=node_name)

        return CommandResult(
            command=cmd,
            exit_code=0,
            stdout="",
            stderr="",
            node=node_name,
        )

    def exec_command(self, node_name: str, command: str, timeout: int = 15) -> CommandResult:
        """Route container command to appropriate simulator."""
        clean_cmd = command.strip()

        # Ping
        if clean_cmd.startswith("ping ") or " ping " in clean_cmd:
            parts = clean_cmd.split()
            dst_ip = parts[-1]
            count = 3
            if "-c" in parts:
                c_idx = parts.index("-c")
                if c_idx + 1 < len(parts):
                    try:
                        count = int(parts[c_idx + 1])
                    except ValueError:
                        pass
            return self.simulate_ping(src_node=node_name, dst_ip=dst_ip, count=count, timeout=timeout)

        # FRR vtysh
        if "vtysh" in clean_cmd:
            return self.simulate_vtysh_command(node_name=node_name, cmd=clean_cmd)

        # SRL sr_cli
        if "sr_cli" in clean_cmd:
            return self.simulate_srl_command(node_name=node_name, cmd=clean_cmd)

        # IP Route
        if "route" in clean_cmd and ("ip " in clean_cmd or clean_cmd.startswith("route")):
            return self.simulate_ip_route(node_name=node_name, cmd=clean_cmd)

        # IP Link Stats
        if "-s" in clean_cmd and "link" in clean_cmd:
            return self.simulate_ip_link_stats(node_name=node_name, cmd=clean_cmd)

        # Traffic Control (tc)
        if clean_cmd.startswith("tc ") or " tc " in clean_cmd:
            return self.simulate_tc_command(node_name=node_name, cmd=clean_cmd)

        # iptables
        if clean_cmd.startswith("iptables ") or " iptables " in clean_cmd:
            return self.simulate_iptables_command(node_name=node_name, cmd=clean_cmd)

        # IP Link / Addr
        if "addr" in clean_cmd or "link" in clean_cmd or "ifconfig" in clean_cmd:
            return self.simulate_ip_addr(node_name=node_name, cmd=clean_cmd)

        # Default fallback
        return CommandResult(
            command=clean_cmd,
            exit_code=0,
            stdout=f"mock: executed '{clean_cmd}' successfully\n",
            stderr="",
            node=node_name,
        )

    def _render_successful_ping(self, dst_ip: str, count: int, ttl: int) -> str:
        lines = [
            f"PING {dst_ip} ({dst_ip}) 56(84) bytes of data.",
        ]
        for seq in range(1, count + 1):
            lines.append(f"64 bytes from {dst_ip}: icmp_seq={seq} ttl={ttl} time=0.082 ms")
        lines.append("")
        lines.append(f"--- {dst_ip} ping statistics ---")
        lines.append(f"{count} packets transmitted, {count} received, 0% packet loss, time {count * 1000}ms")
        lines.append("rtt min/avg/max/mdev = 0.075/0.082/0.090/0.005 ms")
        return "\n".join(lines)

    def _render_failed_ping(self, dst_ip: str, count: int, err_msg: str) -> str:
        lines = [
            f"PING {dst_ip} ({dst_ip}) 56(84) bytes of data.",
        ]
        for seq in range(1, count + 1):
            lines.append(f"From 127.0.0.1 icmp_seq={seq} {err_msg}")
        lines.append("")
        lines.append(f"--- {dst_ip} ping statistics ---")
        lines.append(f"{count} packets transmitted, 0 received, +{count} errors, 100% packet loss, time {count * 1000}ms")
        return "\n".join(lines)

    def _render_partial_loss_ping(self, dst_ip: str, count: int, loss_pct: float) -> str:
        rx = max(int(count * (1.0 - (loss_pct / 100.0))), 0)
        lines = [
            f"PING {dst_ip} ({dst_ip}) 56(84) bytes of data.",
        ]
        for seq in range(1, rx + 1):
            lines.append(f"64 bytes from {dst_ip}: icmp_seq={seq} ttl=62 time=0.080 ms")
        lines.append("")
        lines.append(f"--- {dst_ip} ping statistics ---")
        lines.append(f"{count} packets transmitted, {rx} received, {loss_pct:.1f}% packet loss, time {count * 1000}ms")
        lines.append("rtt min/avg/max/mdev = 0.070/0.080/0.090/0.006 ms")
        return "\n".join(lines)


class MockContainerlabAdapter(BaseNetworkLabAdapter):
    """Hermetic, in-memory mock implementation of BaseNetworkLabAdapter."""

    def __init__(
        self,
        mock_engine: Optional[MockEngine] = None,
        fault_injector: Optional[FaultInjector] = None,
    ):
        self.fault_injector = fault_injector or FaultInjector()
        self.mock_engine = mock_engine or MockEngine(fault_injector=self.fault_injector)
        self._deployed = False
        self._current_topo_file: Optional[str] = None

    def deploy(
        self,
        topo_file: Union[str, Path],
        reconfigure: bool = True,
    ) -> DeploymentResult:
        """Simulate Containerlab topology deployment."""
        lab_name = self.mock_engine.graph.lab_name
        rule = self.fault_injector.should_fail_deploy(lab_name=lab_name)
        if rule:
            err = rule.error_message or "Failed to deploy topology: mock deploy failure injected"
            return DeploymentResult(
                success=False,
                lab_name=lab_name,
                topo_file=str(topo_file),
                nodes_deployed=[],
                raw_output=err,
                error_message=err,
            )

        # Parse and load into virtual graph
        p = Path(topo_file)
        if p.exists():
            config_dir = p.parent
            self.mock_engine.load_topology(topo_data=p, config_dir=config_dir)
            # Auto-clear faults on remediation/redeploy
            self.fault_injector.on_redeploy(self.mock_engine.deployed_configs)

        self._deployed = True
        self._current_topo_file = str(topo_file)
        nodes = list(self.mock_engine.graph.nodes.keys())
        return DeploymentResult(
            success=True,
            lab_name=self.mock_engine.graph.lab_name,
            topo_file=str(topo_file),
            nodes_deployed=nodes,
            raw_output="** Containerlab deployment successful (Mock) **",
        )

    def destroy(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
        cleanup: bool = True,
    ) -> DestructionResult:
        """Simulate Containerlab destruction."""
        name = lab_name or self.mock_engine.graph.lab_name
        self.mock_engine.graph.clear()
        self._deployed = False
        return DestructionResult(
            success=True,
            lab_name=name,
            raw_output="** Containerlab lab destroyed (Mock) **",
        )

    def inspect(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
    ) -> LabInspectionResult:
        """Simulate Containerlab inspect."""
        name = lab_name or self.mock_engine.graph.lab_name
        node_states = []
        for n in self.mock_engine.graph.nodes.values():
            first_ip = None
            for iface in n.interfaces.values():
                if iface.ip_address:
                    first_ip = iface.ip_address
                    break
            node_states.append(
                LabNodeState(
                    name=n.name,
                    container_id=f"clab-{name}-{n.name}",
                    image=n.image,
                    kind=n.kind,
                    state="running" if self._deployed else "stopped",
                    ipv4_address=first_ip,
                )
            )

        return LabInspectionResult(
            success=True,
            lab_name=name,
            nodes=node_states,
            raw_output=json.dumps([ns.model_dump() for ns in node_states], indent=2),
        )

    def exec_command(
        self,
        node_name: str,
        command: str,
        timeout: int = 15,
    ) -> CommandResult:
        """Execute command inside mock node."""
        return self.mock_engine.exec_command(node_name=node_name, command=command, timeout=timeout)

    def is_live_ready(self) -> bool:
        """Mock adapter is always ready for in-memory execution."""
        return True

    def get_topology_summary(self) -> str:
        """Extract and format topology details from mock virtual graph."""
        nodes = self.mock_engine.graph.nodes
        if not nodes:
            return ""
        lines = [
            f"当前运行中 Mock 实验拓扑: {self.mock_engine.graph.lab_name or 'mock-lab'}",
            f"节点规模: 共 {len(nodes)} 个节点\n",
            "【节点与接口配置】:",
        ]
        for name, node in nodes.items():
            ifaces_info = []
            for iface_name, iface in node.interfaces.items():
                desc = iface_name
                if iface.ip_cidr:
                    desc += f"={iface.ip_cidr}"
                if iface.peer_node:
                    desc += f" (对端: {iface.peer_node}:{iface.peer_interface})"
                ifaces_info.append(desc)
            route_info = [f"{r.destination} via {r.next_hop or r.interface}" for r in node.routes]
            desc = f"- {name} ({node.kind}): 接口=[{', '.join(ifaces_info)}]"
            if route_info:
                desc += f", 路由=[{', '.join(route_info)}]"
            lines.append(desc)
        return "\n".join(lines)
